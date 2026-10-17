//go:build linux

// Package quiesce stops everything that can still write to a disk that is
// about to be overwritten: filesystems mounted from it and swap backed by it.
package quiesce

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

// FIFREEZE and FITHAW, _IOWR('X', 119/120, int) from linux/fs.h; x/sys does
// not export them.
const (
	fiFreeze = 0xC0045877
	fiThaw   = 0xC0045878
)

// ErrUnplaceable is returned for a mounted filesystem whose devices cannot be
// determined, so it may or may not live on the disk.
var ErrUnplaceable = errors.New("cannot tell which disk a filesystem lives on")

// ErrUndoIncomplete marks a Run failure after which some change could not
// be undone.
var ErrUndoIncomplete = errors.New("not every change could be undone")

// DiskName turns /dev/vda or vda into vda.
func DiskName(disk string) string {
	return filepath.Base(disk)
}

// MountsOnDisk returns one mount point per filesystem whose device is the
// disk, one of its partitions, or a device stacked on them (LVM, dm-crypt),
// deepest mount point first so freezing never blocks a later open. devOf
// maps a device path to major:minor, for filesystems that report an
// anonymous device (btrfs). A filesystem that may be on the disk but cannot
// be placed is an ErrUnplaceable error.
func MountsOnDisk(mountinfo io.Reader, sysfs, disk string, devOf func(string) (string, error)) ([]string, error) {
	mounts, err := readMounts(mountinfo, sysfs, disk, devOf)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, fs := range filesystems(mounts) {
		i := slices.IndexFunc(fs, func(m mount) bool { return !mountedOver(mounts, m) })
		if i < 0 {
			return nil, errors.Wrapf(ErrUnplaceable, "every mount point of %s is mounted over", fs[0].dev)
		}
		out = append(out, fs[i].point)
	}
	return out, nil
}

// filesystems groups the writable mounts on the disk by filesystem, the one
// with the deepest first mount point first.
func filesystems(mounts []mount) [][]mount {
	var out [][]mount
	at := map[string]int{}
	for _, m := range mounts {
		if !m.onDisk || m.superRO {
			continue
		}
		i, ok := at[m.dev]
		if !ok {
			i = len(out)
			at[m.dev] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], m)
	}
	sort.SliceStable(out, func(i, j int) bool { return depth(out[i][0].point) > depth(out[j][0].point) })
	return out
}

func mountedOver(mounts []mount, m mount) bool {
	i := slices.IndexFunc(mounts, func(o mount) bool { return o.id == m.id })
	return slices.ContainsFunc(mounts[i+1:], func(o mount) bool { return o.point == m.point })
}

type mount struct {
	id, point, dev, fstype, source string
	onDisk, superRO                bool
}

// readMounts returns every mount in mountinfo order.
func readMounts(mountinfo io.Reader, sysfs, disk string, devOf func(string) (string, error)) ([]mount, error) {
	disk = DiskName(disk)
	placed := map[string]bool{}
	var out []mount
	sc := bufio.NewScanner(mountinfo)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := slices.Index(f, "-")
		if len(f) < 5 || sep < 0 || sep+2 >= len(f) {
			continue
		}
		majmin, mnt, fstype, source := f[2], unescape(f[4]), f[sep+1], unescape(f[sep+2])
		on, ok := placed[majmin]
		if !ok {
			var err error
			if on, err = mountOnDisk(sysfs, disk, majmin, fstype, source, devOf); err != nil {
				return nil, errors.Wrapf(err, "%s at %s", fstype, mnt)
			}
			placed[majmin] = on
		}
		superRO := sep+3 < len(f) && slices.Contains(strings.Split(f[sep+3], ","), "ro")
		out = append(out, mount{id: f[0], point: mnt, dev: majmin, fstype: fstype, source: source, onDisk: on, superRO: superRO})
	}
	return out, errors.Wrap(sc.Err(), "read mountinfo")
}

func mountOnDisk(sysfs, disk, majmin, fstype, source string, devOf func(string) (string, error)) (bool, error) {
	if fstype == "zfs" {
		// Pool members are invisible in sysfs.
		return false, ErrUnplaceable
	}
	if !strings.HasPrefix(majmin, "0:") {
		return onDisk(sysfs, filepath.Join(sysfs, "dev/block", majmin), disk, 0), nil
	}
	if !strings.HasPrefix(source, "/dev/") {
		return false, nil
	}
	dev, err := devOf(source)
	if err != nil {
		return false, errors.Wrapf(ErrUnplaceable, "%s: %v", source, err)
	}
	for _, d := range fsDevices(sysfs, filepath.Join(sysfs, "dev/block", dev)) {
		if onDisk(sysfs, d, disk, 0) {
			return true, nil
		}
	}
	return false, nil
}

// fsDevices returns every device of the multi-device btrfs filesystem that
// link belongs to, or just link: mountinfo names only one of them.
func fsDevices(sysfs, link string) []string {
	dev, err := filepath.EvalSymlinks(link)
	if err != nil {
		return []string{link}
	}
	m, _ := filepath.Glob(filepath.Join(sysfs, "fs/btrfs/*/devices", filepath.Base(dev)))
	if len(m) == 0 {
		return []string{link}
	}
	entries, err := os.ReadDir(filepath.Dir(m[0]))
	if err != nil {
		return []string{link}
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.Join(filepath.Dir(m[0]), e.Name()))
	}
	return out
}

// DevOf returns major:minor of the block device that path is, or that holds
// the file at path.
func DevOf(path string) (string, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", errors.Wrapf(err, "stat %s", path)
	}
	dev := st.Dev
	if st.Mode&unix.S_IFMT == unix.S_IFBLK {
		dev = st.Rdev
	}
	return strconv.FormatUint(uint64(unix.Major(dev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(dev)), 10), nil
}

// Disk turns off swap on the disk and freezes every filesystem on it. A
// filesystem that cannot be frozen is remounted read-only instead; remount is
// synchronous, unlike sysrq u. Everything is resolved before the first
// change, and a failure part way undoes what was done.
func Disk(disk string) (undo func() error, err error) {
	targets, swaps, err := resolve(disk)
	if err != nil {
		return nil, err
	}
	var steps []Step
	for _, s := range offOrder(swaps) {
		steps = append(steps, Step{Name: "swapoff " + s.Path, Do: func() (func() error, error) {
			log.Printf("swapoff %s", s.Path)
			return func() error { return swapon(s.Path, swapFlags(s.Prio)) }, swapoff(s.Path)
		}})
	}
	for _, t := range targets {
		f, m, flags, bindRO := t.f, t.m, t.flags, t.bindRO
		// Through the descriptor, the path can no longer lead elsewhere.
		self := "/proc/self/fd/" + strconv.Itoa(int(f.Fd()))
		steps = append(steps, Step{Name: "quiesce " + m.Point, Do: func() (func() error, error) {
			if err := ioctlFd(f, fiFreeze); err == nil {
				log.Printf("froze %s", m.Point)
				return func() error { return ioctlFd(f, fiThaw) }, nil
			} else {
				log.Printf("freeze %s: %v, remounting read-only", m.Point, err)
			}
			undo := func() error {
				if err := unix.Mount("", self, "", unix.MS_REMOUNT|flags, ""); err != nil || !bindRO {
					return err
				}
				return unix.Mount("", self, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|flags, "")
			}
			return undo, unix.Mount("", self, "", unix.MS_REMOUNT|unix.MS_RDONLY|flags, "")
		}})
	}
	// The descriptors stay open: the frozen filesystems are thawed through
	// them on failure, and the process ends in a reboot otherwise.
	return Run(steps)
}

// Stop is what Disk would stop: the swap areas, in the order it turns them
// off, and one mount point per filesystem it freezes or remounts read-only.
type Stop struct {
	Swaps, Filesystems []string
}

// Plan resolves what Disk would stop, with the same checks, and changes
// nothing.
func Plan(disk string) (Stop, error) {
	targets, swaps, err := resolve(disk)
	if err != nil {
		return Stop{}, err
	}
	mounts := make([]Mount, 0, len(targets))
	for _, t := range targets {
		t.f.Close()
		mounts = append(mounts, t.m)
	}
	return stopOf(mounts, swaps), nil
}

func stopOf(mounts []Mount, swaps []Swap) Stop {
	var st Stop
	for _, s := range offOrder(swaps) {
		st.Swaps = append(st.Swaps, s.Path)
	}
	for _, m := range mounts {
		st.Filesystems = append(st.Filesystems, m.Point)
	}
	return st
}

// target is a filesystem on the disk, held open, with the flags a remount
// back to read-write restores.
type target struct {
	f      *os.File
	m      Mount
	flags  uintptr
	bindRO bool
}

// resolve finds everything Disk stops. Nothing it returns with an error
// needs closing.
func resolve(disk string) (targets []target, swaps []Swap, err error) {
	if err := Preflight(disk); err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			for _, t := range targets {
				t.f.Close()
			}
			targets = nil
		}
	}()
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, nil, errors.Wrap(err, "read mountinfo")
	}
	mounts, err := readMounts(bytes.NewReader(mi), "/sys", disk, DevOf)
	if err != nil {
		return nil, nil, err
	}
	for _, fs := range filesystems(mounts) {
		cands := make([]Mount, 0, len(fs))
		for _, m := range fs {
			cands = append(cands, Mount{ID: m.id, Point: m.point})
		}
		f, m, err := OpenMount(cands)
		if err != nil {
			return targets, nil, err
		}
		targets = append(targets, target{f: f, m: m})
		var st unix.Statfs_t
		if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
			return targets, nil, errors.Wrapf(err, "statfs %s", m.Point)
		}
		t := &targets[len(targets)-1]
		t.flags, t.bindRO = remountUndo(st.Flags)
	}
	sw, err := os.Open("/proc/swaps")
	if err != nil {
		return targets, nil, errors.Wrap(err, "open /proc/swaps")
	}
	swaps, err = SwapsToStop(sw, "/sys", disk, DevOf, fileOnDiskBy(mounts))
	sw.Close()
	if err != nil {
		return targets, nil, err
	}
	return targets, swaps, nil
}

// mountFlags are the statfs flags that mean the same as the MS_ flags of
// the same value, so a remount keeps them.
const mountFlags = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC | unix.ST_SYNCHRONOUS |
	unix.ST_MANDLOCK | unix.ST_NOATIME | unix.ST_NODIRATIME | unix.ST_RELATIME

func ioctlFd(f *os.File, req uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), req, 0); errno != 0 {
		return errno
	}
	return nil
}

func swapon(path string, flags int) error {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	if _, _, errno := unix.Syscall(unix.SYS_SWAPON, uintptr(unsafe.Pointer(p)), uintptr(flags), 0); errno != 0 {
		return errno
	}
	return nil
}

func swapoff(path string) error {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	if _, _, errno := unix.Syscall(unix.SYS_SWAPOFF, uintptr(unsafe.Pointer(p)), 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// onDisk reports whether the sysfs block device at link is the disk, a
// partition of it, or stacked on one of those.
func onDisk(sysfs, link, disk string, level int) bool {
	if level > 8 {
		return false
	}
	dev, err := filepath.EvalSymlinks(link)
	if err != nil {
		return false
	}
	if filepath.Base(dev) == disk || filepath.Base(filepath.Dir(dev)) == disk {
		return true
	}
	// A loop device over a block device keeps the link only here, not in
	// slaves. Over a file it writes through the filesystem holding the file.
	if b, err := os.ReadFile(filepath.Join(dev, "loop/backing_file")); err == nil {
		backing := strings.TrimSpace(string(b))
		if !strings.HasPrefix(backing, "/dev/") {
			return false
		}
		if resolved, err := filepath.EvalSymlinks(backing); err == nil {
			backing = resolved
		}
		return onDisk(sysfs, filepath.Join(sysfs, "class/block", filepath.Base(backing)), disk, level+1)
	}
	slaves, err := os.ReadDir(filepath.Join(dev, "slaves"))
	if err != nil {
		// A partition of a stacked device (md0p1) has no slaves of its own;
		// they belong to the device it is a partition of.
		if _, perr := os.Stat(filepath.Join(dev, "partition")); perr == nil {
			return onDisk(sysfs, filepath.Dir(dev), disk, level+1)
		}
		return false
	}
	for _, s := range slaves {
		if onDisk(sysfs, filepath.Join(sysfs, "class/block", s.Name()), disk, level+1) {
			return true
		}
	}
	return false
}

func depth(mnt string) int {
	if mnt == "/" {
		return 0
	}
	return strings.Count(mnt, "/")
}

// unescape decodes the \ooo octal escapes the kernel uses for spaces and
// other special characters in mountinfo and /proc/swaps.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Step is one change to the running system and the way back.
type Step struct {
	Name string
	Do   func() (undo func() error, err error)
}

// Run applies steps in order. When one fails it undoes the completed ones,
// last first, and returns the failure.
func Run(steps []Step) (func() error, error) {
	var undos []func() error
	for _, s := range steps {
		undo, err := watched(s)
		if err != nil {
			err = errors.Wrap(err, s.Name)
			if uerr := undoAll(undos); uerr != nil {
				return nil, errors.Join(err, uerr)
			}
			return nil, err
		}
		undos = append(undos, undo)
	}
	return func() error { return undoAll(undos) }, nil
}

// undoAll undoes in reverse order, going on past a failure.
func undoAll(undos []func() error) error {
	undone := true
	for _, undo := range slices.Backward(undos) {
		if uerr := undo(); uerr != nil {
			log.Printf("undo: %v", uerr)
			undone = false
		}
	}
	if !undone {
		return ErrUndoIncomplete
	}
	return nil
}

// StackedWriter says why a device stacked on the disk or one of its
// partitions would keep writing to it after every filesystem is frozen, or
// returns "". md writes its own metadata, bcache and dm caches write back on
// their own; linear, striped, crypt and multipath mappings only pass
// writes through.
// dmTargets returns the target types of a dm device by its kernel name.
func StackedWriter(sysfs, disk string, dmTargets func(string) ([]string, error)) string {
	dev, err := filepath.EvalSymlinks(filepath.Join(sysfs, "class/block", DiskName(disk)))
	if err != nil {
		return ""
	}
	devs := []string{dev}
	entries, _ := os.ReadDir(dev)
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dev, e.Name(), "partition")); err == nil {
			devs = append(devs, filepath.Join(dev, e.Name()))
		}
	}
	for _, d := range devs {
		if why := writerAbove(d, dmTargets, 0); why != "" {
			return why
		}
	}
	return ""
}

func writerAbove(dev string, dmTargets func(string) ([]string, error), level int) string {
	if level > 8 {
		return "devices are stacked too deep to check"
	}
	holders, _ := os.ReadDir(filepath.Join(dev, "holders"))
	for _, h := range holders {
		name := h.Name()
		switch {
		case strings.HasPrefix(name, "md"), strings.HasPrefix(name, "bcache"):
			return "it is under " + name + ", which writes to it on its own"
		case strings.HasPrefix(name, "dm-"):
			targets, err := dmTargets(name)
			if err != nil {
				return fmt.Sprintf("cannot tell what %s does with it: %v", name, err)
			}
			for _, t := range targets {
				if t != "linear" && t != "striped" && t != "crypt" && t != "multipath" {
					return fmt.Sprintf("it is under %s, a %s mapping, which may write to it on its own", name, t)
				}
			}
		}
		if next, err := filepath.EvalSymlinks(filepath.Join(dev, "holders", name)); err == nil {
			if why := writerAbove(next, dmTargets, level+1); why != "" {
				return why
			}
		}
	}
	return ""
}

// dmTargets reads the target types of a dm device, by its kernel name, from
// the kernel's own table through /dev/mapper/control.
func dmTargets(name string) ([]string, error) {
	dev, err := os.ReadFile(filepath.Join("/sys/block", name, "dev"))
	if err != nil {
		return nil, err
	}
	var major, minor uint32
	if _, err := fmt.Sscanf(strings.TrimSpace(string(dev)), "%d:%d", &major, &minor); err != nil {
		return nil, errors.Wrapf(err, "parse %s", dev)
	}
	ctl, err := os.OpenFile("/dev/mapper/control", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer ctl.Close()
	words := make([]uint64, 2048)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	hdr := dmTableRequest(words, major, minor)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, ctl.Fd(), unix.DM_TABLE_STATUS, uintptr(unsafe.Pointer(&words[0]))); errno != 0 {
		clear(buf)
		return nil, errors.Wrap(errno, "DM_TABLE_STATUS")
	}
	if hdr.Flags&unix.DM_BUFFER_FULL_FLAG != 0 {
		clear(buf)
		return nil, errors.Newf("the table of %s does not fit in %d bytes", name, len(buf))
	}
	return dmTargetsFrom(buf)
}

// HiddenMounts fails when a filesystem on the disk is mounted in one of the
// other mount namespaces but not in own: nothing here could freeze it.
func HiddenMounts(own io.Reader, others []Namespace, sysfs, disk string, devOf func(string) (string, error)) error {
	mine, err := readMounts(own, sysfs, disk, devOf)
	if err != nil {
		return err
	}
	visible := map[string]bool{}
	for _, m := range mine {
		visible[m.dev] = true
	}
	for _, n := range others {
		theirs, err := readMounts(n.Mountinfo, sysfs, disk, devOf)
		if err != nil {
			return err
		}
		for _, m := range theirs {
			if m.onDisk && !m.superRO && !visible[m.dev] {
				return errors.Wrapf(ErrUnplaceable, "%s is mounted at %s only in the mount namespace of process %s", m.dev, m.point, n.PID)
			}
		}
	}
	return nil
}

// Preflight checks, without changing anything, that everything writing to
// the disk can be found and stopped.
func Preflight(disk string) error {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return errors.Wrap(err, "read mountinfo")
	}
	if _, err := MountsOnDisk(bytes.NewReader(mi), "/sys", disk, DevOf); err != nil {
		return err
	}
	sw, err := os.Open("/proc/swaps")
	if err != nil {
		return errors.Wrap(err, "open /proc/swaps")
	}
	mounts, err := readMounts(bytes.NewReader(mi), "/sys", disk, DevOf)
	if err != nil {
		sw.Close()
		return err
	}
	_, err = SwapsToStop(sw, "/sys", disk, DevOf, fileOnDiskBy(mounts))
	sw.Close()
	if err != nil {
		return err
	}
	if why := StackedWriter("/sys", disk, dmTargets); why != "" {
		return errors.Wrapf(ErrUnplaceable, "%s: %s", disk, why)
	}
	// A virtual machine or anything else writing to the device itself is
	// stopped by no freeze.
	self := []string{strconv.Itoa(os.Getpid()), strconv.Itoa(os.Getppid())}
	if w := RawWriters("/proc", "/sys", disk, BlockOf, self); len(w) > 0 {
		return errors.Wrapf(ErrUnplaceable, "%s is open for writing by %s; stop them first", disk, strings.Join(w, ", "))
	}
	return HiddenMounts(bytes.NewReader(mi), otherNamespaces(), "/sys", disk, DevOf)
}

// otherNamespaces returns the mountinfo of one process per mount namespace
// other than this one.
func otherNamespaces() []Namespace {
	self, _ := os.Readlink("/proc/self/ns/mnt")
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for i := range pids {
		pids[i] = filepath.Base(pids[i])
	}
	nsOf := func(pid string) (string, error) { return os.Readlink(filepath.Join("/proc", pid, "ns/mnt")) }
	mountinfoOf := func(pid string) ([]byte, error) { return os.ReadFile(filepath.Join("/proc", pid, "mountinfo")) }
	return pickNamespaces(pids, self, nsOf, mountinfoOf)
}

// pickNamespaces returns the mountinfo of one process per mount namespace
// other than self.
func pickNamespaces(pids []string, self string, nsOf func(string) (string, error), mountinfoOf func(string) ([]byte, error)) []Namespace {
	seen := map[string]bool{self: true}
	var out []Namespace
	for _, pid := range pids {
		ns, err := nsOf(pid)
		if err != nil || seen[ns] {
			continue
		}
		b, err := mountinfoOf(pid)
		// The process may exit, and its pid be reused, between the reads.
		if again, nerr := nsOf(pid); err != nil || nerr != nil || again != ns {
			continue
		}
		seen[ns] = true
		out = append(out, Namespace{PID: pid, Mountinfo: bytes.NewReader(b)})
	}
	return out
}

// Mount is one entry of mountinfo.
type Mount struct {
	ID, Point string
}

// OpenMount opens the first candidate whose path really leads to that
// mount.
func OpenMount(candidates []Mount) (*os.File, Mount, error) {
	for _, c := range candidates {
		f, err := os.Open(c.Point)
		if err != nil {
			continue
		}
		if id, err := mountID(f); err == nil && id == c.ID {
			return f, c, nil
		}
		f.Close()
	}
	return nil, Mount{}, errors.Wrapf(ErrUnplaceable, "no path leads to mount %v", candidates)
}

// mountID reads the id of the mount f is on; fdinfo has it since Linux 3.15,
// statx only since 5.8.
func mountID(f *os.File) (string, error) {
	b, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(int(f.Fd())))
	if err != nil {
		return "", err
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "mnt_id:"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", errors.New("no mnt_id in fdinfo")
}

// SwapsToStop returns the swap areas to turn off: swap writes bypass a
// frozen filesystem. Those are the swap partitions on the disk and the swap
// files on a filesystem on it. fileOnDisk places a swap file by the mount
// its open descriptor is on: a path can be mounted over. Swap elsewhere,
// zram included, stays on: turning it off would pull its pages back into
// memory the build has filled.
func SwapsToStop(swaps io.Reader, sysfs, disk string, devOf func(string) (string, error), fileOnDisk func(string, int64) (bool, error)) ([]Swap, error) {
	disk = DiskName(disk)
	var out []Swap
	sc := bufio.NewScanner(swaps)
	for first := true; sc.Scan(); first = false {
		f := strings.Fields(sc.Text())
		if first || len(f) < 5 {
			continue
		}
		path := unescape(f[0])
		sizeKiB, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "size of swap %s", path)
		}
		prio, err := strconv.Atoi(f[4])
		if err != nil {
			return nil, errors.Wrapf(err, "priority of swap %s", path)
		}
		var on bool
		if f[1] == "file" {
			if on, err = fileOnDisk(path, sizeKiB); err != nil {
				return nil, err
			}
		} else {
			majmin, err := devOf(path)
			if err != nil {
				return nil, errors.Wrapf(err, "find device of swap %s", path)
			}
			on = onDisk(sysfs, filepath.Join(sysfs, "dev/block", majmin), disk, 0)
		}
		if on {
			out = append(out, Swap{Path: path, Prio: prio})
		}
	}
	return out, errors.Wrap(sc.Err(), "read swaps")
}

// fileOnDiskBy places a file by the mount id of an open descriptor of it.
func fileOnDiskBy(mounts []mount) func(string, int64) (bool, error) {
	return func(path string, sizeKiB int64) (bool, error) {
		f, err := os.Open(path)
		if err != nil {
			return false, errors.Wrapf(ErrUnplaceable, "swap file %s: %v", path, err)
		}
		defer f.Close()
		// The path may now lead to another file, under a mount over the
		// active one's directory. /proc/swaps counts every page but the
		// header, and a few at the end that do not make a whole page.
		st, err := f.Stat()
		if err != nil {
			return false, errors.Wrapf(ErrUnplaceable, "swap file %s: %v", path, err)
		}
		page := int64(os.Getpagesize())
		if usable := st.Size()/page*page - page; usable < sizeKiB*1024 || usable-sizeKiB*1024 >= page {
			return false, errors.Wrapf(ErrUnplaceable, "%s is %d bytes, not the active swap of %d KiB", path, st.Size(), sizeKiB)
		}
		id, err := mountID(f)
		if err != nil {
			return false, errors.Wrapf(ErrUnplaceable, "swap file %s: %v", path, err)
		}
		for _, m := range mounts {
			if m.id == id {
				return m.onDisk, nil
			}
		}
		return false, errors.Wrapf(ErrUnplaceable, "swap file %s is on no mount listed", path)
	}
}

// MountsOffDisk returns one mount point per filesystem that is not on the
// disk.
func MountsOffDisk(mountinfo io.Reader, sysfs, disk string, devOf func(string) (string, error)) ([]string, error) {
	mounts, err := readMounts(mountinfo, sysfs, disk, devOf)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range offDiskGroups(mounts) {
		out = append(out, g[0].point)
	}
	return out, nil
}

// SyncOthers flushes every filesystem not on the disk before the reboot,
// one by one: sync(2) would also flush the disk's old filesystems over the
// new image. It gives up after timeout, so a dead network mount cannot keep
// the machine from rebooting.
func SyncOthers(disk string, timeout time.Duration) {
	mi, err := os.Open(mountinfoPath)
	if err != nil {
		log.Printf("cannot flush the other disks: %v", err)
		return
	}
	mounts, err := readMounts(mi, "/sys", disk, DevOf)
	mi.Close()
	if err != nil {
		log.Printf("cannot flush the other disks: %v", err)
		return
	}
	var wg sync.WaitGroup
	for _, g := range offDiskGroups(mounts) {
		cands := make([]Mount, 0, len(g))
		for _, m := range g {
			cands = append(cands, Mount{ID: m.id, Point: m.point})
		}
		wg.Go(func() {
			// Through a descriptor checked to be on the filesystem, as a
			// path may have been mounted over.
			f, _, err := OpenMount(cands)
			if err != nil {
				log.Printf("cannot flush %s: %v", cands[0].Point, err)
				return
			}
			_ = unix.Syncfs(int(f.Fd()))
			f.Close()
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// RawWriters returns the processes that hold a block device on the disk open
// for writing. blockOf returns major:minor for a block device and "" for
// anything else; skip lists pids to leave out.
func RawWriters(proc, sysfs, disk string, blockOf func(string) (string, error), skip []string) []string {
	disk = DiskName(disk)
	fds, _ := filepath.Glob(filepath.Join(proc, "[0-9]*", "fd", "*"))
	seen := map[string]bool{}
	var out []string
	for _, fd := range fds {
		pid := filepath.Base(filepath.Dir(filepath.Dir(fd)))
		if seen[pid] || slices.Contains(skip, pid) {
			continue
		}
		// Reading the link touches no filesystem; following it to a file on
		// a dead network mount would block.
		if target, err := os.Readlink(fd); err != nil || !strings.HasPrefix(target, "/dev/") {
			continue
		}
		majmin, err := blockOf(fd)
		if err != nil || majmin == "" || !onDisk(sysfs, filepath.Join(sysfs, "dev/block", majmin), disk, 0) {
			continue
		}
		if !writable(filepath.Join(proc, pid, "fdinfo", filepath.Base(fd))) {
			continue
		}
		seen[pid] = true
		comm, _ := os.ReadFile(filepath.Join(proc, pid, "comm"))
		out = append(out, pid+" ("+strings.TrimSpace(string(comm))+")")
	}
	return out
}

// writable reads the open flags from an fdinfo file.
func writable(fdinfo string) bool {
	b, err := os.ReadFile(fdinfo)
	if err != nil {
		return false
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "flags:"); ok {
			flags, err := strconv.ParseUint(strings.TrimSpace(v), 8, 64)
			return err == nil && flags&unix.O_ACCMODE != unix.O_RDONLY
		}
	}
	return false
}

// BlockOf returns major:minor of the block device path leads to, or "" when
// it is anything else.
func BlockOf(path string) (string, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return "", nil
	}
	return strconv.FormatUint(uint64(unix.Major(st.Rdev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(st.Rdev)), 10), nil
}

// Swap is an active swap area and its priority.
type Swap struct {
	Path string
	Prio int
}

// swapFlags asks swapon for prio, SWAP_FLAG_PREFER and SWAP_FLAG_PRIO_MASK
// from linux/swap.h. A negative priority is one the kernel handed out
// itself, and cannot be asked for.
func swapFlags(prio int) int {
	const prefer, mask = 0x8000, 0x7fff
	if prio < 0 {
		return 0
	}
	return prefer | prio&mask
}

// offOrder turns swap off lowest priority first, so the undo, which runs
// in reverse, turns the highest back on first: the kernel hands out
// falling negative priorities in that order, which keeps their order,
// though not always their values.
func offOrder(swaps []Swap) []Swap {
	out := slices.Clone(swaps)
	slices.SortStableFunc(out, func(a, b Swap) int { return a.Prio - b.Prio })
	return out
}

// watchInterval is how often Run says which step it is still waiting on.
var watchInterval = 30 * time.Second //nolint:gochecknoglobals // test seam

// watched runs the step and logs, every watchInterval, that it is still
// waiting on it: a freeze waits for writers, and one stuck in I/O never
// finishes.
func watched(s Step) (func() error, error) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	// Stop the watch and wait for it, so it never speaks after the step.
	defer wg.Wait()
	defer close(done)
	wg.Go(func() {
		t := time.NewTicker(watchInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				log.Printf("still waiting on %s", s.Name)
			}
		}
	})
	return s.Do()
}

// Namespace is the mountinfo of a mount namespace, as one of its processes
// sees it.
type Namespace struct {
	PID       string
	Mountinfo io.Reader
}

// remountUndo splits the flags a mount point had before it was remounted
// read-only into what the superblock gets back, read-write, and whether
// the point itself was read-only, which a bind remount then restores:
// remounting the superblock with MS_RDONLY would make every mount of it
// read-only.
func remountUndo(stFlags int64) (sb uintptr, bindRO bool) {
	return uintptr(stFlags) & mountFlags, stFlags&unix.ST_RDONLY != 0
}

var mountinfoPath = "/proc/self/mountinfo" //nolint:gochecknoglobals // test seam

// parseDmTargets reads the target types out of a DM_TABLE_STATUS reply:
// after the header, one target spec per target, each followed by its
// parameters; next is counted from the start of the data area.
func parseDmTargets(buf []byte) ([]string, error) {
	hdrSize := int(unsafe.Sizeof(unix.DmIoctl{}))
	specSize := int(unsafe.Sizeof(unix.DmTargetSpec{}))
	if len(buf) < hdrSize {
		return nil, errors.New("device-mapper reply shorter than its header")
	}
	var hdr unix.DmIoctl
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), hdrSize), buf)
	targets := make([]string, 0, hdr.Target_count)
	off := int(hdr.Data_start)
	for range hdr.Target_count {
		if off < 0 || off+specSize > len(buf) {
			return nil, errors.New("device-mapper reply cut short")
		}
		var spec unix.DmTargetSpec
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&spec)), specSize), buf[off:])
		typ, _, _ := strings.Cut(string(spec.Target_type[:]), "\x00")
		targets = append(targets, typ)
		off = int(hdr.Data_start) + int(spec.Next)
	}
	return targets, nil
}

// offDiskGroups groups the mounts of filesystems not on the disk by
// filesystem, every point each is mounted at, automount points left out:
// opening one mounts what is behind it.
func offDiskGroups(mounts []mount) [][]mount {
	var out [][]mount
	at := map[string]int{}
	for _, m := range mounts {
		if m.onDisk || m.fstype == "autofs" {
			continue
		}
		i, ok := at[m.dev]
		if !ok {
			i = len(out)
			at[m.dev] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], m)
	}
	return out
}

// dmTableRequest fills words, which keep the buffer aligned for the
// kernel's structures, with a DM_TABLE_STATUS request for the device. A
// dm-crypt table carries its key unless that sits in the keyring, so the
// data is asked for as secure: the kernel wipes its own copy.
func dmTableRequest(words []uint64, major, minor uint32) *unix.DmIoctl {
	hdr := (*unix.DmIoctl)(unsafe.Pointer(&words[0]))
	hdr.Version = [3]uint32{unix.DM_VERSION_MAJOR, 0, 0}
	hdr.Data_size = uint32(len(words) * 8)
	hdr.Data_start = uint32(unsafe.Sizeof(*hdr))
	hdr.Flags = unix.DM_STATUS_TABLE_FLAG | unix.DM_SECURE_DATA_FLAG
	hdr.Dev = unix.Mkdev(major, minor)
	return hdr
}

// dmTargetsFrom reads the target types out of a reply and wipes it, key
// and all: it was allocated before the process locked its memory.
func dmTargetsFrom(buf []byte) ([]string, error) {
	defer clear(buf)
	return parseDmTargets(buf)
}
