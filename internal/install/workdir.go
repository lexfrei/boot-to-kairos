//go:build linux

package install

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/image"
	"github.com/lexfrei/boot-to-kairos/internal/quiesce"
)

// dataName is the directory made under --workdir for the disk image and the
// staged layers.
const dataName = "boot-to-kairos"

const (
	// imageSlack is what the disk image holds beside the agent's three
	// images and the persistent partition's journal: the EFI and OEM
	// partitions and the other filesystems' metadata.
	imageSlack = 256 << 20
	// probeSize is what the holes probe truncates its file to.
	probeSize = 16 << 20
	// lowSpace is what is left of --workdir when a write to it may have
	// failed for want of room.
	lowSpace = 64 << 20
)

var (
	ErrBadWorkDir     = errors.New("--workdir cannot hold the disk image")
	ErrNotEnoughSpace = errors.New("not enough space in --workdir")
)

// dataDir is the directory under --workdir that the build writes to,
// reached through a descriptor held on --workdir: the path is never looked
// up again, so neither a mount over it nor a rename moves the data, and a
// remove after the quiesce walks nothing on the frozen disk.
type dataDir struct {
	dir *os.File
	// path leads through the descriptor; shown is what the user named.
	path, shown string
	// keep is set once the disk image is the only good copy left.
	keep bool
}

var holesProbe = probeHoles //nolint:gochecknoglobals // test seam

// openWorkDir checks that dir can hold the disk image while it is written
// over disk and makes the data dir in it. unfit says why the filesystem of
// an open directory cannot, as quiesce.WorkDirUnfit does.
// size is the size of the disk, which the disk image takes as a file.
func openWorkDir(dir, disk string, size int64, unfit func(*os.File, string) (string, error)) (*dataDir, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, errors.Wrapf(ErrBadWorkDir, "%v", err)
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	why, err := unfit(f, disk)
	if err != nil {
		return nil, errors.Mark(errors.Wrapf(err, "--workdir %s", dir), ErrBadWorkDir)
	}
	if why != "" {
		return nil, errors.Wrapf(ErrBadWorkDir, "%s: %s", dir, why)
	}
	d := &dataDir{dir: f, path: filepath.Join("/proc/self/fd", strconv.Itoa(int(f.Fd())), dataName), shown: filepath.Join(dir, dataName)}
	// Taken under the lock: no other run can be using it.
	if err := os.Mkdir(d.path, 0o700); errors.Is(err, os.ErrExist) {
		return nil, errors.Wrapf(ErrBadWorkDir, "%s was left by a run that did not finish; it holds only that run's disk image and staged layers: remove it", d.shown)
	} else if err != nil {
		return nil, errors.Wrapf(ErrBadWorkDir, "create %s: %v", d.shown, err)
	}
	if err := holesProbe(d.path, size); err != nil {
		_ = os.Remove(d.path)
		return nil, errors.Wrapf(ErrBadWorkDir, "%s cannot hold a sparse file as large as the disk: %v", dir, err)
	}
	ok = true
	return d, nil
}

// workDirUnfit places an open directory with the mounts of this process.
func workDirUnfit(f *os.File, disk string) (string, error) {
	id, err := quiesce.MountIDOf(f)
	if err != nil {
		return "", errors.Wrap(err, "find the mount of --workdir")
	}
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", errors.Wrap(err, "read mountinfo")
	}
	return quiesce.WorkDirUnfit(bytes.NewReader(mi), "/sys", disk, id, quiesce.DevOf)
}

// inWorkDir runs next with the data dir of --workdir, if one is given,
// opened by open into o, and removes the data dir after it unless it is to
// be kept.
func inWorkDir(o *Options, open func() (*dataDir, error), next func() error) error {
	if o.WorkDir == "" {
		return next()
	}
	w, err := open()
	if err != nil {
		return err
	}
	o.work = w
	// Past the point of no return too: the work dir is not on the disk.
	defer w.remove()
	return next()
}

// remove deletes the data dir and everything in it, unless it is to be
// kept; a failure is only logged, as nothing depends on it.
func (d *dataDir) remove() {
	if d.keep {
		return
	}
	if err := os.RemoveAll(d.path); err != nil {
		log.Printf("remove %s: %v", d.shown, err)
	}
}

// probeHoles makes a sparse file in dir, the way the disk image is made,
// checks that it stays one, and that it can grow to size.
func probeHoles(dir string, size int64) error {
	f, err := os.CreateTemp(dir, "probe-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Truncate(probeSize); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	_, serr := unix.Seek(int(f.Fd()), 0, unix.SEEK_DATA)
	if err := holesKept(st.Blocks, serr); err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		return errors.Wrapf(err, "a file cannot be %d GiB on it", size>>30)
	}
	return nil
}

// holesKept judges the probe: the truncated file must have no blocks, and
// SEEK_DATA must find no data in it, or the write would copy the whole disk
// image as data.
func holesKept(blocks int64, seekErr error) error {
	if blocks != 0 {
		// st_blocks counts 512-byte units whatever the block size.
		return errors.Newf("a %d MiB truncate allocated %d KiB", probeSize>>20, blocks/2)
	}
	if !errors.Is(seekErr, unix.ENXIO) {
		return errors.Newf("a hole reads as data (SEEK_DATA: %v)", seekErr)
	}
	return nil
}

// freeBytes is what an unprivileged writer may still put on dir's
// filesystem.
func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, errors.Wrapf(err, "statfs %s", dir)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// spaceFor refuses when dir has less than need bytes free for what.
func spaceFor(dir string, need uint64, what string) error {
	free, err := freeBytes(dir)
	if err != nil {
		return err
	}
	if free < need {
		return errors.Wrapf(ErrNotEnoughSpace, "%s needs %d MiB, %d MiB are free", what, need>>20, free>>20)
	}
	return nil
}

// imageEstimate is what the disk image may come to for an unpacked image of
// rootfs bytes and a disk of disk bytes. kairos-agent sizes the active,
// passive and recovery images each to the size of its source plus 100 MiB,
// and mke2fs (1.47) gives the persistent partition, most of the disk, a
// journal of 1/256 to 1/128 of it, from 64 MiB up to 1 GiB; 1/128 is taken.
func imageEstimate(rootfs uint64, disk int64) uint64 {
	journal := min(max(uint64(disk)/128, 64<<20), 1<<30)
	return 3*(rootfs+100<<20) + journal + imageSlack
}

// roomLeft refuses a built disk image when the build left less than low
// bytes in dir: the loop device writes back on its own, and a write that
// failed for want of room may not have failed the agent.
func roomLeft(dir string, low uint64, onDisk bool) error {
	free, err := freeBytes(dir)
	if err != nil {
		return err
	}
	if free >= low {
		return nil
	}
	why := fmt.Sprintf("the build left %d MiB, and the disk image may be incomplete", free>>20)
	if onDisk {
		return errors.Wrap(ErrNotEnoughSpace, why)
	}
	return errors.Wrap(ErrNotEnoughMemory, why)
}

// stagingFull says which of the two filled up when unpacking failed with
// ENOSPC: the staging dir on disk, or the rootfs tmpfs.
func stagingFull(err error) error {
	switch {
	case !errors.Is(err, unix.ENOSPC):
		return err
	case errors.Is(err, image.ErrStage):
		return fmt.Errorf("%w: a staged layer filled --workdir: %w", ErrNotEnoughSpace, err)
	}
	return fmt.Errorf("%w: the unpacked image outgrew the memory the build may use: %w", ErrNotEnoughMemory, err)
}

// unpackedFit refuses an image before anything is fetched when its layers
// would not fit in the budget beside the headroom even if no layer unpacked
// to more than its stored size: with the layers staged on disk, the
// unpacked image is all the build keeps in memory.
func unpackedFit(budget uint64, sizes []int64) error {
	total := uint64(rootfsHeadroom)
	for n, size := range sizes {
		// A negative size converts to more than any budget.
		if uint64(size) > budget || total > budget-uint64(size) {
			return errors.Wrapf(ErrNotEnoughMemory, "layer %d: the layers take more than the %d MiB the build may hold in memory", n, budget>>20)
		}
		total += uint64(size)
	}
	return nil
}

// rootfsFits is the size of the rootfs tmpfs once rootfsUsed bytes are
// unpacked into it, when nothing else of the build is in memory.
func rootfsFits(budget, rootfsUsed uint64) (uint64, error) {
	rootfs := rootfsUsed + rootfsHeadroom
	if rootfs > budget {
		return 0, errors.Wrapf(ErrNotEnoughMemory, "the unpacked image takes %d MiB, and with the headroom more than %d MiB", rootfsUsed>>20, budget>>20)
	}
	return rootfs, nil
}

// outOfSpace marks a failed build as out of space when --workdir is all but
// full after it: the agent sees a full disk image only as I/O errors.
func outOfSpace(err error, dir string, low uint64) error {
	if err == nil {
		return nil
	}
	if serr := spaceFor(dir, low, "the build"); serr != nil && errors.Is(serr, ErrNotEnoughSpace) {
		return fmt.Errorf("%w: %w", serr, err)
	}
	return err
}

// addWorkDir says where the build keeps what it makes.
func addWorkDir(p *Plan, d *dataDir) {
	if d == nil {
		p.Add("work dir", workDir+", a tmpfs")
		return
	}
	p.Add("work dir", d.shown+" for the disk image and the staged layers; the unpacked image stays in a tmpfs at "+workDir)
}
