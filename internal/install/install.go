//go:build linux

// Package install turns the running machine into a Kairos node: it installs
// the image onto a file the size of the disk, then replaces the disk with it.
package install

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/efiboot"
	"github.com/lexfrei/boot-to-kairos/internal/flash"
	"github.com/lexfrei/boot-to-kairos/internal/image"
	"github.com/lexfrei/boot-to-kairos/internal/kairos"
	"github.com/lexfrei/boot-to-kairos/internal/loop"
	"github.com/lexfrei/boot-to-kairos/internal/mountns"
	"github.com/lexfrei/boot-to-kairos/internal/netcfg"
	"github.com/lexfrei/boot-to-kairos/internal/quiesce"
	"github.com/lexfrei/boot-to-kairos/internal/sandbox"
)

// Options are the user's choices.
type Options struct {
	Image      string
	Disk       string
	ConfigPath string
	Yes        bool
	// KeepNetwork carries the host's network configuration over.
	KeepNetwork bool
	// DryRun stops before the point of no return and prints the plan.
	DryRun bool
	// Output is OutputText or OutputJSON; empty means text.
	Output string
}

const (
	OutputText = "text"
	OutputJSON = "json"
)

var (
	ErrMissingImage    = errors.New("--image is required")
	ErrMissingDisk     = errors.New("--disk is required")
	ErrMissingConfig   = errors.New("--cloud-config is required")
	ErrNotWholeDisk    = errors.New("--disk must be a whole disk")
	ErrBadConfig       = kairos.ErrBadConfig
	ErrBIOSUnsupported = errors.New("legacy BIOS boot is not supported")
	ErrAborted         = errors.New("aborted by user")
	ErrBadOutput       = errors.New("--output must be text or json")
	ErrLabelClash      = errors.New("host partitions carry names kairos-agent uses")

	errNotBlockDevice = errors.New("not a block device")
)

const (
	workDir  = "/run/boot-to-kairos"
	lockFile = "/run/boot-to-kairos.lock"
	// repairRounds bounds how often a page that differs on read-back is
	// rewritten before giving up.
	repairRounds = 3
)

// Validate checks everything that can be checked before any work starts and
// returns the cloud-config content. It rewrites o.Disk to the kernel name of
// the disk, /dev/vda for /dev/disk/by-id/..., since mounts and swap on it are
// found by that name. devOf returns major:minor of a block device.
func Validate(o *Options, sysfs string, devOf func(string) (string, error)) ([]byte, error) {
	switch {
	case o.Image == "":
		return nil, ErrMissingImage
	case o.Disk == "":
		return nil, ErrMissingDisk
	case o.ConfigPath == "":
		return nil, ErrMissingConfig
	case o.Output != "" && o.Output != OutputText && o.Output != OutputJSON:
		return nil, errors.Wrapf(ErrBadOutput, "not %q", o.Output)
	}
	majmin, err := devOf(o.Disk)
	if err != nil {
		return nil, errors.Wrapf(ErrNotWholeDisk, "%s: %v", o.Disk, err)
	}
	dev, err := filepath.EvalSymlinks(filepath.Join(sysfs, "dev/block", majmin))
	if err != nil {
		return nil, errors.Wrapf(ErrNotWholeDisk, "%s is not a known block device", o.Disk)
	}
	if _, err := os.Stat(filepath.Join(dev, "partition")); err == nil {
		return nil, errors.Wrapf(ErrNotWholeDisk, "%s is a partition", o.Disk)
	}
	// LVM, md, loop: the firmware cannot boot from a disk image inside one.
	if strings.Contains(dev, "/devices/virtual/") {
		return nil, errors.Wrapf(ErrNotWholeDisk, "%s is a virtual block device", o.Disk)
	}
	o.Disk = "/dev/" + filepath.Base(dev)
	cfg, err := os.ReadFile(o.ConfigPath)
	if err != nil {
		return nil, errors.Wrap(err, "read --cloud-config")
	}
	if err := kairos.CheckConfig(cfg); err != nil {
		return nil, errors.Wrap(ErrBadConfig, err.Error())
	}
	return cfg, nil
}

// Firmware returns the mode the running system booted in, which is the one
// kairos-agent installs for: it looks for /sys/firmware/efi too.
func Firmware(sysfs string) (string, error) {
	_, err := os.Stat(filepath.Join(sysfs, "firmware/efi"))
	switch {
	case err == nil:
		return kairos.EFI, nil
	case errors.Is(err, fs.ErrNotExist):
		return kairos.BIOS, nil
	}
	return "", errors.Wrap(err, "tell UEFI from legacy BIOS")
}

// checkFirmware returns the mode the machine booted in and refuses an
// install that would not boot in it.
func checkFirmware(cfg []byte, sysfs, arch, disk string, sectorSize func(string) (int, error)) (string, error) {
	firmware, err := Firmware(sysfs)
	if err != nil {
		return "", err
	}
	if firmware == kairos.BIOS && arch != "amd64" {
		return "", errors.Mark(errors.Newf("this machine did not boot through UEFI, and a legacy BIOS install is supported only on x86-64, not on %s", arch), ErrBIOSUnsupported)
	}
	if err := kairos.CheckFirmware(cfg, firmware); err != nil {
		return "", errors.Mark(err, ErrBadConfig)
	}
	sector, err := sectorSize(disk)
	if err != nil {
		return "", err
	}
	if err := checkBootable(firmware, sector); err != nil {
		return "", err
	}
	return firmware, nil
}

// checkBootable refuses a legacy BIOS install onto a disk whose logical
// sectors are not 512 bytes: legacy firmware commonly cannot read one, and
// the machine would come back with nothing to boot.
func checkBootable(firmware string, sector int) error {
	if firmware == kairos.BIOS && sector != 512 {
		return errors.Mark(errors.Newf("legacy BIOS firmware commonly cannot boot a disk with %d-byte sectors; refusing to leave the machine unbootable", sector), ErrBIOSUnsupported)
	}
	return nil
}

// Run installs the image and reboots into it. Every step before the disk is
// quiesced leaves the running system as it was when it fails.
func Run(ctx context.Context, o Options) error {
	plan := &Plan{}
	return lockedAndReported(os.Stdout, o, plan, lockFile, workDir, dropWork, func(frozen *bool) error {
		return run(ctx, o, plan, frozen)
	})
}

// lockedAndReported runs run under the lock and reports the outcome, a
// refusal to take the lock included.
func lockedAndReported(out io.Writer, o Options, plan *Plan, lock, dir string, drop func(string, bool), run func(frozen *bool) error) error {
	frozen, err := withWorkLock(lock, dir, drop, run)
	report(out, o, plan, err, frozen)
	return err
}

// dropWork drops the work tmpfs and, unless the disk may be frozen, the
// directory under it: /run may be a directory on a filesystem of the
// target disk, and an rmdir on a frozen filesystem waits for a thaw that
// never comes.
func dropWork(dir string, frozen bool) {
	_ = unix.Unmount(dir, unix.MNT_DETACH)
	if !frozen {
		_ = os.Remove(dir)
	}
}

func run(ctx context.Context, o Options, plan *Plan, frozen *bool) error {
	cfg, err := Validate(&o, "/sys", blockDevOf)
	if err != nil {
		return err
	}
	if err := quiesce.Preflight(o.Disk); err != nil {
		return err
	}
	names, labels, err := kairos.Targets(cfg)
	if err != nil {
		return err
	}
	if _, err := checkFirmware(cfg, "/sys", runtime.GOARCH, o.Disk, flash.SectorSize); err != nil {
		return err
	}
	clashes := append(kairos.LabelClashes("/dev/disk/by-partlabel", names), kairos.LabelClashes("/dev/disk/by-label", labels)...)
	if len(clashes) > 0 {
		return errors.Wrapf(ErrLabelClash, "host partitions already carry %s, which kairos-agent finds its own partitions by; "+
			"it would format or mount those instead. Rename them first", strings.Join(clashes, ", "))
	}
	plan.Add("image", o.Image)
	return proceed(ctx, o, cfg, plan, os.Stdin, os.Stdout, frozen)
}

// proceed asks, builds the image and replaces the disk with it. A dry run
// does not ask, as it leaves the disk alone, and stops before the point of
// no return. frozen is set once the disk may be quiesced.
func proceed(ctx context.Context, o Options, cfg []byte, plan *Plan, in io.Reader, out io.Writer, frozen *bool) error {
	if !o.KeepNetwork {
		plan.Add("network", "not carried (--keep-network=false)")
	} else {
		var carried netcfg.Carried
		var err error
		if cfg, carried, err = netcfg.Carry(cfg, captureNetwork, log.Printf); err != nil {
			return err
		}
		plan.addNetwork(&carried)
	}
	if !o.Yes && !o.DryRun {
		prompt := out
		if o.Output == OutputJSON {
			// stdout carries only the JSON report.
			prompt = log.Writer()
		}
		if err := confirm(ctx, in, prompt, o); err != nil {
			return err
		}
	}
	warnSecureBoot()

	raw, err := buildInterruptible(ctx, o, cfg, plan)
	if err != nil {
		return err
	}
	entry, err := prepareBootEntry(raw, o.Disk, plan)
	if err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if o.DryRun {
		stop, err := planStop(o.Disk)
		if err != nil {
			return errors.Wrap(err, "quiesce target disk")
		}
		plan.AddList("swap to turn off", stop.Swaps)
		plan.AddList("filesystems to stop", stop.Filesystems)
		if err := lockCheck(); err != nil {
			return err
		}
		if o.Output == OutputJSON {
			return nil
		}
		fmt.Fprintf(out, "\nDry run: every check before the point of no return passed, and the disk, its swap, its filesystems and the firmware's NVRAM were left alone, apart from what the cloud-config's own stages did. The real run would go on with this plan:\n")
		plan.Print(out)
		return nil
	}
	if o.Output == OutputJSON {
		report(out, o, plan, nil, false)
	}
	*frozen = true
	log.Printf("point of no return: stopping writes to %s", o.Disk)
	if err := enterPointOfNoReturn(); err != nil {
		return err
	}
	thaw, err := quiesceDisk(o.Disk)
	if err != nil {
		if errors.Is(err, quiesce.ErrUndoIncomplete) {
			return errors.Wrap(err, "quiesce target disk; nothing was written, but a filesystem may still be frozen: reboot")
		}
		return errors.Wrap(err, "quiesce target disk; nothing was written, the changes made so far were undone")
	}
	st, err := write(raw, o.Disk)
	if errors.Is(err, flash.ErrNothingWritten) {
		if uerr := thaw(); uerr != nil {
			return errors.Wrap(err, "nothing was written, but a filesystem may still be frozen: reboot")
		}
		return errors.Wrap(err, "nothing was written; the system was restored")
	}
	if err != nil {
		return err
	}
	log.Printf("copied %d MiB, zeroed %d MiB, read-back verified after %d repair rounds; flushing the other disks",
		st.Copied>>20, st.Zeroed>>20, st.Repairs)
	syncOthers(o.Disk, syncTimeout)
	if entry != nil {
		applyBootEntry(entry)
	}
	log.Print("rebooting")
	return errors.Wrap(reboot(), "reboot")
}

const efivars = "/sys/firmware/efi/efivars"

// bootEntry prepares the boot entry while the old disk can still be read.
// Without efivarfs there is nothing to write it to, and the firmware's
// fallback is all the new system has. Legacy BIOS has no entries: it boots
// the boot sector the image put on the disk.
func bootEntry(sysfs, raw, disk string, summary *Plan) (*efiboot.Plan, error) {
	firmware, err := Firmware(sysfs)
	if err != nil {
		return nil, err
	}
	if firmware == kairos.BIOS {
		summary.Add("firmware", "legacy BIOS")
		summary.Add("boot entry", "none; legacy BIOS boots the boot sector the image put on the disk")
		return nil, nil //nolint:nilnil // nothing to write is not an error
	}
	summary.Add("firmware", "UEFI")
	if err := efiboot.Available(efivars); err != nil {
		log.Printf("warning: %v; no boot entry will be written, the firmware has to fall back to \\EFI\\BOOT on the disk", err)
		summary.addBootEntry(disk, err, nil)
		return nil, nil //nolint:nilnil // nothing to write is not an error
	}
	sector, err := flash.SectorSize(disk)
	if err != nil {
		return nil, err
	}
	plan, err := efiboot.NewPlan(raw, sector, runtime.GOARCH)
	if err != nil {
		return nil, errors.Wrap(err, "boot entry; nothing was written")
	}
	err = plan.Replacing(disk, sector)
	if err != nil {
		log.Printf("warning: %v; the old system's boot entries will stay", err)
	}
	summary.addBootEntry(disk, nil, err)
	return plan, nil
}

// writeBootEntry only logs a failure: the disk is written by now, and the
// reboot still has the firmware's fallback to \EFI\BOOT.
func writeBootEntry(plan *efiboot.Plan) {
	res, err := plan.Apply(efivars)
	switch {
	case err == nil:
		log.Printf("boot entry: %s", res)
	case !res.Ordered:
		log.Printf("boot entry: %s; %v. The firmware has to fall back to \\EFI\\BOOT on the disk", res, err)
	default:
		log.Printf("boot entry: %s; %v", res, err)
	}
}

// buildInterruptible builds the image and marks a failure after a
// cancellation as one: a cancelled agent fails with its own exit status,
// not with ctx.Err().
func buildInterruptible(ctx context.Context, o Options, cfg []byte, plan *Plan) (string, error) {
	raw, err := buildImage(ctx, o, cfg, plan)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return "", errors.Mark(err, cerr)
		}
		return "", err
	}
	return raw, nil
}

// Test seams for every step from the network capture on.
//
//nolint:gochecknoglobals // test seams
var (
	buildImage           = build
	enterPointOfNoReturn = pointOfNoReturn
	quiesceDisk          = quiesce.Disk
	planStop             = quiesce.Plan
	captureNetwork       = netcfg.Capture
	lockCheck            = checkLock
	writeImage           = flash.WriteVerified
	syncOthers           = quiesce.SyncOthers
	reboot               = func() error { return unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART) }
	prepareBootEntry     = func(raw, disk string, summary *Plan) (*efiboot.Plan, error) {
		return bootEntry("/sys", raw, disk, summary)
	}
	applyBootEntry = writeBootEntry
)

const writeAttempts = 3

// syncTimeout bounds the flush of the other filesystems before the reboot.
const syncTimeout = 30 * time.Second

func blockDevOf(path string) (string, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return "", errNotBlockDevice
	}
	return fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev)), nil
}

// write repeats the whole verified write: a later attempt can succeed where
// the repair rounds of an earlier one ran out.
func write(raw, disk string) (flash.Stats, error) {
	var err error
	for attempt := 1; attempt <= writeAttempts; attempt++ {
		var st flash.Stats
		if st, err = writeImage(raw, disk, repairRounds); err == nil {
			return st, nil
		}
		// Only before the first attempt wrote anything is the disk intact.
		if attempt == 1 && errors.Is(err, flash.ErrNothingWritten) {
			return flash.Stats{}, err
		}
		log.Printf("write attempt %d of %d: %v", attempt, writeAttempts, err)
	}
	if errors.Is(err, flash.ErrNothingWritten) {
		// A later attempt that wrote nothing says nothing about the earlier
		// ones: drop the mark, keep the text.
		err = errors.New(err.Error())
	}
	return flash.Stats{}, errors.Wrapf(err,
		"%s is in an unknown state and will not boot; reinstall it from rescue media", disk)
}

// safeLog is where logging goes once the disk is quiesced. A regular file
// may live on the frozen disk, where a write blocks forever, so stderr is
// kept only when it is a terminal or a pipe, and never waited for.
func safeLog(stderr *os.File, kmsg io.Writer) io.Writer {
	k := kmsgWriter{kmsg}
	if st, err := stderr.Stat(); err != nil || st.Mode().IsRegular() {
		return k
	}
	w, err := nonblocking(stderr)
	if err != nil {
		return k
	}
	return bestEffort{k, w}
}

// nonblocking opens f again with O_NONBLOCK, as a descriptor of its own so
// that whoever else shares the pipe or terminal is not affected. A write to
// it fails instead of waiting for a reader that may itself be stuck on the
// frozen disk. It is written with write(2) directly: through an os.File the
// runtime poller would park the write instead.
func nonblocking(f *os.File) (io.Writer, error) {
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return rawWriter(fd), nil
}

type rawWriter int

func (w rawWriter) Write(p []byte) (int, error) {
	return unix.Write(int(w), p)
}

// kmsgWriter tags each log line with level 2, which consoles print at any
// usual loglevel.
type kmsgWriter struct{ w io.Writer }

func (k kmsgWriter) Write(p []byte) (int, error) {
	_, err := k.w.Write(append([]byte("<2>boot-to-kairos: "), p...))
	return len(p), err
}

// bestEffort writes to every writer, unlike io.MultiWriter, which stops at
// the first one that fails.
type bestEffort []io.Writer

func (b bestEffort) Write(p []byte) (int, error) {
	for _, w := range b {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

// pointOfNoReturn prepares the process to outlive its own disk: nothing may
// stop it half way, and nothing may page in from the disk being replaced.
func pointOfNoReturn() error {
	mountns.Absorb(unix.SIGHUP, unix.SIGPIPE, unix.SIGINT, unix.SIGTERM)
	// Opened for each line: /dev/kmsg rate-limits every open file on its
	// own, and a descriptor kept open could have spent its budget by the
	// time the last error comes.
	kmsg := reopenWriter(func() (io.WriteCloser, error) { return os.OpenFile("/dev/kmsg", os.O_WRONLY, 0) })
	log.SetOutput(safeLog(os.Stderr, kmsg))
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0); err != nil {
		log.Printf("oom_score_adj: %v", err)
	}
	return errors.Wrap(unix.Mlockall(unix.MCL_CURRENT|unix.MCL_FUTURE), "mlockall; nothing was changed")
}

// checkLock locks the process in memory as the point of no return does,
// then lets go.
func checkLock() error {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return errors.Wrap(err, "mlockall")
	}
	return errors.Wrap(unix.Munlockall(), "munlockall")
}

// dropWorkDir unmounts the work tmpfs lazily, which drops the whole tree,
// binds included, without deleting anything through them.
func dropWorkDir() {
	_ = unix.Unmount(workDir, unix.MNT_DETACH)
}

// build installs the image onto a sparse file the size of the disk, in RAM,
// and returns its path. The work tmpfs stays mounted on success because the
// file is read from it next.
func build(ctx context.Context, o Options, cfg []byte, plan *Plan) (string, error) {
	size, err := flash.DeviceSize(o.Disk)
	if err != nil {
		return "", err
	}
	sector, err := flash.SectorSize(o.Disk)
	if err != nil {
		return "", err
	}
	plan.addDisk(o.Disk, size, sector)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return "", errors.Wrap(err, "create work dir")
	}
	mi, err := os.Open("/proc/meminfo")
	if err != nil {
		return "", errors.Wrap(err, "open meminfo")
	}
	budget, err := memBudget(mi)
	mi.Close()
	if err != nil {
		return "", err
	}
	if err := unix.Mount("tmpfs", workDir, "tmpfs", 0, fmt.Sprintf("mode=0700,size=%d", budget)); err != nil {
		return "", errors.Wrap(err, "mount work tmpfs")
	}
	ok := false
	defer func() {
		if !ok {
			dropWorkDir()
		}
	}()

	// The rootfs gets its own tmpfs so that it can be dropped by unmounting
	// it once the install is done, without deleting through any bind.
	root := filepath.Join(workDir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		return "", errors.Wrap(err, "create rootfs dir")
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", 0, fmt.Sprintf("mode=0755,size=%d", budget)); err != nil {
		return "", errors.Wrap(err, "mount rootfs tmpfs")
	}
	log.Printf("pulling %s", o.Image)
	img, err := image.Pull(ctx, o.Image, "linux/"+runtime.GOARCH)
	if err != nil {
		return "", err
	}
	if err := img.Extract(root); err != nil {
		return "", err
	}
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return "", errors.Wrap(err, "statfs rootfs")
	}
	rootfsSize, workSize, err := splitBudget(budget, (st.Blocks-st.Bfree)*uint64(st.Bsize))
	if err != nil {
		return "", err
	}
	if err := unix.Mount("", root, "", unix.MS_REMOUNT, fmt.Sprintf("size=%d", rootfsSize)); err != nil {
		return "", errors.Wrap(err, "shrink rootfs tmpfs")
	}
	if err := unix.Mount("", workDir, "", unix.MS_REMOUNT, fmt.Sprintf("mode=0700,size=%d", workSize)); err != nil {
		return "", errors.Wrap(err, "size work tmpfs")
	}

	raw := filepath.Join(workDir, "image.raw")
	f, err := os.Create(raw)
	if err != nil {
		return "", errors.Wrap(err, "create image file")
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return "", errors.Wrap(err, "size image file")
	}
	f.Close()

	dev, err := loop.Attach(raw, sector)
	if err != nil {
		return "", err
	}
	defer func() { _ = dev.Detach() }()

	if err := sandbox.Setup(root, sandbox.HostBinds()); err != nil {
		_ = sandbox.Teardown(root)
		return "", err
	}
	runErr := install(ctx, root, dev.Path, cfg)
	if err := sandbox.Teardown(root); err != nil {
		return "", err
	}
	if runErr != nil {
		return "", runErr
	}
	if err := dev.Detach(); err != nil {
		return "", err
	}
	if err := unix.Unmount(root, unix.MNT_DETACH); err != nil {
		return "", errors.Wrap(err, "drop rootfs")
	}
	var rst unix.Stat_t
	if err := unix.Stat(raw, &rst); err != nil {
		return "", errors.Wrap(err, "stat image file")
	}
	// st_blocks counts 512-byte units whatever the block size.
	plan.addRaw(rst.Blocks*512, size)
	ok = true
	return raw, nil
}

func install(ctx context.Context, root, device string, cfg []byte) error {
	if err := kairos.WriteConfig(root, cfg); err != nil {
		return err
	}
	log.Printf("installing with the image's kairos-agent onto %s", device)
	return errors.Wrap(kairos.Install(ctx, root, device), "kairos-agent manual-install")
}

func confirm(ctx context.Context, in io.Reader, out io.Writer, o Options) error {
	fmt.Fprintf(out, "\nImage:        %s\nTarget disk:  %s (ALL DATA WILL BE ERASED)\nCloud-config: %s\n\nType the disk path to continue: ",
		o.Image, o.Disk, o.ConfigPath)
	// The read cannot be interrupted, so Ctrl-C is waited for beside it.
	answer := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(in).ReadString('\n')
		answer <- line
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case line := <-answer:
		if strings.TrimSpace(line) != o.Disk {
			return ErrAborted
		}
		return nil
	}
}

func warnSecureBoot() {
	// SecureBoot-<EFI global variable GUID>: 4 attribute bytes, then the value.
	b, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err == nil && len(b) == 5 && b[4] == 1 {
		log.Print("warning: Secure Boot is on; the image's boot chain must be trusted by this firmware or it will not boot")
	}
}

const (
	// memReserve is left to everything else running while the image is
	// built in RAM.
	memReserve = 512 << 20
	// rootfsHeadroom is what the installer may still write into the
	// unpacked image while it runs from it.
	rootfsHeadroom = 256 << 20
)

// ErrNotEnoughMemory stops the build cleanly, before the OOM killer would.
var ErrNotEnoughMemory = errors.New("not enough memory to build the image")

// memBudget is how much the two tmpfs may hold together.
func memBudget(meminfo io.Reader) (uint64, error) {
	sc := bufio.NewScanner(meminfo)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "MemAvailable:" {
			continue
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return 0, errors.Wrap(err, "parse MemAvailable")
		}
		if kb<<10 <= memReserve {
			return 0, errors.Wrapf(ErrNotEnoughMemory, "%d MiB available", kb>>10)
		}
		return kb<<10 - memReserve, nil
	}
	return 0, errors.New("no MemAvailable in meminfo")
}

// splitBudget shrinks the unpacked image's tmpfs to what it holds and gives
// the rest to the disk image.
func splitBudget(budget, rootfsUsed uint64) (rootfs, work uint64, err error) {
	rootfs = rootfsUsed + rootfsHeadroom
	if rootfs >= budget {
		return 0, 0, errors.Wrapf(ErrNotEnoughMemory, "the unpacked image alone takes %d MiB of %d MiB", rootfsUsed>>20, budget>>20)
	}
	return rootfs, budget - rootfs, nil
}

// reopenWriter writes through a writer it opens for each write.
type reopenWriter func() (io.WriteCloser, error)

func (r reopenWriter) Write(p []byte) (int, error) {
	w, err := r()
	if err != nil {
		return 0, err
	}
	defer w.Close()
	return w.Write(p)
}

// Plan is what the install has worked out it will do, in the order it
// worked it out. A dry run prints it, and the JSON report carries it.
type Plan struct {
	items []planItem
}

type planItem struct {
	name, value string
	// values is set, possibly empty, for an item that is a list.
	values []string
}

func (it planItem) MarshalJSON() ([]byte, error) {
	if it.values != nil {
		return json.Marshal(struct {
			Name   string   `json:"name"`
			Values []string `json:"values"`
		}{it.name, it.values})
	}
	return json.Marshal(struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}{it.name, it.value})
}

// Add adds one item.
func (p *Plan) Add(name, value string) {
	p.items = append(p.items, planItem{name: name, value: value})
}

// AddList adds a list of values, or none.
func (p *Plan) AddList(name string, values []string) {
	v := strings.Join(values, ", ")
	if v == "" {
		v = "none"
	}
	p.items = append(p.items, planItem{name: name, value: v, values: append([]string{}, values...)})
}

func (p *Plan) addDisk(disk string, size int64, sector int) {
	p.Add("target disk", fmt.Sprintf("%s, %d bytes (%d GiB)", disk, size, size>>30))
	p.Add("sector size", fmt.Sprintf("%d bytes", sector))
}

func (p *Plan) addRaw(used, size int64) {
	p.Add("image.raw", fmt.Sprintf("%d MiB used of %d MiB", used>>20, size>>20))
}

func (p *Plan) addNetwork(c *netcfg.Carried) {
	if c.Reason != "" {
		p.Add("network", "not carried: "+c.Reason)
		return
	}
	p.AddList("network files", c.Files)
	p.AddList("network addresses", c.Addresses)
	p.AddList("network routes", c.Routes)
}

// Print writes one indented line per item, the values aligned.
func (p *Plan) Print(w io.Writer) {
	width := 0
	for _, it := range p.items {
		width = max(width, len(it.name))
	}
	for _, it := range p.items {
		fmt.Fprintf(w, "  %-*s %s\n", width+1, it.name+":", it.value)
	}
}

// ErrAlreadyRunning is returned while another instance holds the lock.
var ErrAlreadyRunning = errors.New("another boot-to-kairos is running")

// withWorkLock runs run while holding lock, then drops the work dir before
// letting go, telling drop whether run passed the point of no return: the
// work dir is shared through the host's /run, and an rmdir of it detaches
// whatever another instance has mounted on it. A run that reboots never
// returns, and the lock goes with the process.
func withWorkLock(lock, dir string, drop func(dir string, frozen bool), run func(frozen *bool) error) (frozen bool, err error) {
	f, err := os.OpenFile(lock, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return false, errors.Wrap(err, "open lock file")
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, errors.Wrapf(ErrAlreadyRunning, "%s is held", lock)
		}
		return false, errors.Wrap(err, "lock")
	}
	defer func() { drop(dir, frozen) }()
	err = run(&frozen)
	return frozen, err
}

// addBootEntry says what Apply will be asked to do, given why efivarfs is
// unusable and why the old disk's entries cannot be told, nil if neither.
func (p *Plan) addBootEntry(disk string, avail, replace error) {
	if avail != nil {
		p.Add("boot entry", fmt.Sprintf("none (%v); the firmware has to fall back to \\EFI\\BOOT on the disk", avail))
		return
	}
	v := fmt.Sprintf("%q for the image's EFI system partition; ", efiboot.Description)
	if replace != nil {
		v += fmt.Sprintf("the old system's entries stay: %v", replace)
	} else {
		v += fmt.Sprintf("the entries for %s's partitions, if any, are removed", disk)
	}
	p.Add("boot entry", v)
}

// report prints the plan as one JSON object, with the refusal if err is
// set, unless the output is text or the disk may be frozen: stdout can be
// a file on it, and a write there would block for good.
func report(out io.Writer, o Options, plan *Plan, err error, frozen bool) {
	if o.Output != OutputJSON || frozen {
		return
	}
	type refusal struct {
		Class   string `json:"class"`
		Message string `json:"message"`
	}
	r := struct {
		DryRun  bool       `json:"dryRun"`
		Passed  bool       `json:"passed"`
		Plan    []planItem `json:"plan"`
		Refusal *refusal   `json:"refusal"`
	}{DryRun: o.DryRun, Passed: err == nil, Plan: append([]planItem{}, plan.items...)}
	if err != nil {
		r.Refusal = &refusal{Class: errorClass(err), Message: err.Error()}
	}
	b, merr := json.Marshal(r)
	if merr != nil {
		log.Printf("json report: %v", merr)
		return
	}
	fmt.Fprintf(out, "%s\n", b)
}

// errorClasses name refusals for automation; the first match wins.
//
//nolint:gochecknoglobals // fixed table
var errorClasses = []struct {
	err   error
	class string
}{
	{ErrMissingImage, "usage"},
	{ErrMissingDisk, "usage"},
	{ErrMissingConfig, "usage"},
	{ErrBadOutput, "usage"},
	{ErrNotWholeDisk, "not-whole-disk"},
	{ErrBadConfig, "bad-config"},
	{kairos.ErrUncheckable, "bad-config"},
	{ErrBIOSUnsupported, "bios-unsupported"},
	{ErrLabelClash, "label-clash"},
	{ErrAborted, "aborted"},
	{ErrNotEnoughMemory, "not-enough-memory"},
	{ErrAlreadyRunning, "already-running"},
	{quiesce.ErrUnplaceable, "disk-in-use"},
	{netcfg.ErrUnsupported, "network-unsupported"},
	{context.Canceled, "interrupted"},
}

func errorClass(err error) string {
	for _, c := range errorClasses {
		if errors.Is(err, c.err) {
			return c.class
		}
	}
	return "error"
}
