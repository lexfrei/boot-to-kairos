//go:build linux

// Package install turns the running machine into a Kairos node: it installs
// the image onto a file the size of the disk, then replaces the disk with it.
package install

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"

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
}

var (
	ErrMissingImage    = errors.New("--image is required")
	ErrMissingDisk     = errors.New("--disk is required")
	ErrMissingConfig   = errors.New("--cloud-config is required")
	ErrNotWholeDisk    = errors.New("--disk must be a whole disk")
	ErrBadConfig       = errors.New("--cloud-config is not a cloud-config")
	ErrBIOSUnsupported = errors.New("legacy BIOS boot is not supported")
	ErrAborted         = errors.New("aborted by user")

	errNotBlockDevice = errors.New("not a block device")
)

const (
	workDir = "/run/boot-to-kairos"
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
	if _, err := os.Stat(filepath.Join(sysfs, "firmware/efi")); err != nil {
		return nil, ErrBIOSUnsupported
	}
	return cfg, nil
}

// Run installs the image and reboots into it. Every step before the disk is
// quiesced leaves the running system as it was when it fails.
func Run(ctx context.Context, o Options) error {
	cfg, err := Validate(&o, "/sys", blockDevOf)
	if err != nil {
		return err
	}
	if err := quiesce.Preflight(o.Disk); err != nil {
		return err
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return errors.Wrap(err, "read /proc/cmdline")
	}
	names, labels, err := kairos.Targets(cfg, cmdline)
	if err != nil {
		return err
	}
	clashes := append(kairos.LabelClashes("/dev/disk/by-partlabel", names), kairos.LabelClashes("/dev/disk/by-label", labels)...)
	if len(clashes) > 0 {
		return errors.Newf("host partitions already carry %s, which kairos-agent finds its own partitions by; "+
			"it would format or mount those instead. Rename them first", strings.Join(clashes, ", "))
	}
	if o.KeepNetwork {
		if cfg, err = netcfg.Carry(cfg, netcfg.Capture, log.Printf); err != nil {
			return err
		}
	}
	if !o.Yes {
		if err := confirm(ctx, os.Stdin, os.Stdout, o); err != nil {
			return err
		}
	}
	warnSecureBoot()

	raw, err := build(ctx, o, cfg)
	if err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	log.Printf("point of no return: stopping writes to %s", o.Disk)
	if err := pointOfNoReturn(); err != nil {
		return err
	}
	thaw, err := quiesce.Disk(o.Disk)
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
	quiesce.SyncOthers(o.Disk, syncTimeout)
	log.Print("rebooting")
	return errors.Wrap(unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART), "reboot")
}

var writeImage = flash.WriteVerified //nolint:gochecknoglobals // test seam

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

// dropWorkDir unmounts the work tmpfs lazily, which drops the whole tree,
// binds included, without deleting anything through them.
func dropWorkDir() {
	_ = unix.Unmount(workDir, unix.MNT_DETACH)
}

// build installs the image onto a sparse file the size of the disk, in RAM,
// and returns its path. The work tmpfs stays mounted on success because the
// file is read from it next.
func build(ctx context.Context, o Options, cfg []byte) (string, error) {
	size, err := flash.DeviceSize(o.Disk)
	if err != nil {
		return "", err
	}
	sector, err := flash.SectorSize(o.Disk)
	if err != nil {
		return "", err
	}
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
