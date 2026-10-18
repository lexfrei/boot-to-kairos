//go:build linux

// Package flash writes a sparse disk image over a block device and proves the
// device holds exactly the image afterwards.
package flash

import (
	"bytes"
	"io"
	"os"
	"unsafe"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

const (
	pageSize = 4096
	chunk    = 4 << 20
)

// Extent is a contiguous range of the image: data to copy, or a hole to zero.
type Extent struct {
	Off  int64
	Len  int64
	Data bool
}

// Stage names a pass over the image that reports its progress.
type Stage string

const (
	StageCopy   Stage = "copy"
	StageVerify Stage = "verify"
)

// Progress is told how many of the image's total bytes a pass has done. It
// runs on the writing goroutine, between chunks, so it must not block. Nil
// is allowed.
type Progress func(stage Stage, done, total int64)

func (p Progress) report(stage Stage, done, total int64) {
	if p != nil {
		p(stage, done, total)
	}
}

// Stats reports how many bytes were copied and zeroed, and how many repair
// rounds the read-back needed.
type Stats struct {
	Copied  int64
	Zeroed  int64
	Repairs int
}

var (
	// ErrTargetTooSmall means the target cannot hold the whole image.
	ErrTargetTooSmall = errors.New("target smaller than image")
	// ErrUnrepaired means the read-back still differs after the allowed repair rounds.
	ErrUnrepaired = errors.New("read-back still differs from image")

	// ErrNothingWritten marks a failure before the first byte reached the
	// target.
	ErrNothingWritten = errors.New("nothing was written to the target")
)

// afterCopy lets tests simulate a write that lands between the copy and the
// read-back, the way a late filesystem flush does on a real disk.
var afterCopy = func(string) {} //nolint:gochecknoglobals // test seam

var zeroFn = zero //nolint:gochecknoglobals // test seam

// Extents splits f into data and hole ranges that together cover the file.
func Extents(f *os.File) ([]Extent, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "stat image")
	}
	size := st.Size()
	fd := int(f.Fd())

	var out []Extent
	var off int64
	for off < size {
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			data = size
		} else if err != nil {
			return nil, errors.Wrap(err, "seek data")
		}
		if data > off {
			out = append(out, Extent{Off: off, Len: data - off, Data: false})
		}
		if data >= size {
			break
		}
		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if err != nil {
			return nil, errors.Wrap(err, "seek hole")
		}
		out = append(out, Extent{Off: data, Len: hole - data, Data: true})
		off = hole
	}
	return out, nil
}

// Copy writes the data extents of src to dst and zeroes its holes, so dst ends
// up byte-identical to src over the length of src.
func Copy(src, dst string, progress Progress) (Stats, error) {
	var st Stats
	in, err := os.Open(src)
	if err != nil {
		return st, unwritten(errors.Wrap(err, "open image"))
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return st, unwritten(errors.Wrap(err, "open target"))
	}
	defer out.Close()

	if err := checkFits(in, out); err != nil {
		return st, unwritten(err)
	}
	ext, err := Extents(in)
	if err != nil {
		return st, unwritten(err)
	}

	// touched turns true right before the first write to the target, so a
	// failure is marked as leaving it intact only when that is true.
	touched := false
	fail := func(err error) error {
		if !touched {
			return unwritten(err)
		}
		return err
	}
	var total int64
	if len(ext) > 0 {
		total = ext[len(ext)-1].Off + ext[len(ext)-1].Len
	}
	buf := make([]byte, chunk)
	for _, e := range ext {
		if !e.Data {
			if err := zeroFn(out, e.Off, e.Len, &touched); err != nil {
				return st, fail(err)
			}
			st.Zeroed += e.Len
			progress.report(StageCopy, e.Off+e.Len, total)
			continue
		}
		for done := int64(0); done < e.Len; {
			n := min(int64(len(buf)), e.Len-done)
			if _, err := in.ReadAt(buf[:n], e.Off+done); err != nil && !errors.Is(err, io.EOF) {
				return st, fail(errors.Wrap(err, "read image"))
			}
			touched = true
			if _, err := out.WriteAt(buf[:n], e.Off+done); err != nil {
				return st, errors.Wrap(err, "write target")
			}
			done += n
			progress.report(StageCopy, e.Off+done, total)
		}
		st.Copied += e.Len
	}
	return st, errors.Wrap(out.Sync(), "sync target")
}

// Verify reads dst back, bypassing the page cache where the target allows it,
// and returns the offsets of the pages that differ from src.
func Verify(src, dst string, progress Progress) ([]int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return nil, errors.Wrap(err, "open image")
	}
	defer in.Close()
	out, err := openDirect(dst)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	st, err := in.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "stat image")
	}
	// O_DIRECT needs a page-aligned buffer; an anonymous mapping is one.
	got, err := unix.Mmap(-1, 0, chunk, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, errors.Wrap(err, "allocate aligned buffer")
	}
	defer func() { _ = unix.Munmap(got) }()
	want := make([]byte, chunk)

	var bad []int64
	for off := int64(0); off < st.Size(); off += chunk {
		n := int(min(int64(chunk), st.Size()-off))
		readLen := alignUp(n)
		if _, err := out.ReadAt(got[:readLen], off); err != nil && !errors.Is(err, io.EOF) {
			return nil, errors.Wrapf(err, "read back target at %d", off)
		}
		if _, err := in.ReadAt(want[:n], off); err != nil && !errors.Is(err, io.EOF) {
			return nil, errors.Wrap(err, "read image")
		}
		for p := 0; p < n; p += pageSize {
			end := min(p+pageSize, n)
			if !bytes.Equal(got[p:end], want[p:end]) {
				bad = append(bad, off+int64(p))
			}
		}
		progress.report(StageVerify, off+int64(n), st.Size())
	}
	return bad, nil
}

// Repair rewrites the given pages of dst from src.
func Repair(src, dst string, pages []int64) error {
	in, err := os.Open(src)
	if err != nil {
		return errors.Wrap(err, "open image")
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrap(err, "open target")
	}
	defer out.Close()

	buf := make([]byte, pageSize)
	for _, off := range pages {
		n, err := in.ReadAt(buf, off)
		if err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "read image")
		}
		if _, err := out.WriteAt(buf[:n], off); err != nil {
			return errors.Wrap(err, "rewrite target page")
		}
	}
	return errors.Wrap(out.Sync(), "sync target")
}

// WriteVerified copies src over dst and then verifies and repairs until the
// read-back matches, giving up after maxRounds repair rounds.
func WriteVerified(src, dst string, maxRounds int, progress Progress) (Stats, error) {
	st, err := Copy(src, dst, progress)
	if err != nil {
		return st, err
	}
	afterCopy(dst)
	for round := 0; ; round++ {
		st.Repairs = round
		bad, err := Verify(src, dst, progress)
		if err != nil {
			return st, err
		}
		if len(bad) == 0 {
			return st, nil
		}
		if round >= maxRounds {
			return st, errors.Wrapf(ErrUnrepaired, "%d pages after %d repair rounds, first at offset %d", len(bad), round, bad[0])
		}
		if err := Repair(src, dst, bad); err != nil {
			return st, err
		}
	}
}

func checkFits(in, out *os.File) error {
	ist, err := in.Stat()
	if err != nil {
		return errors.Wrap(err, "stat image")
	}
	size, err := deviceSize(out)
	if err != nil {
		return err
	}
	if size < ist.Size() {
		return errors.Wrapf(ErrTargetTooSmall, "target is %d bytes, image needs %d", size, ist.Size())
	}
	return nil
}

func unwritten(err error) error { return errors.Join(ErrNothingWritten, err) }

// DeviceSize returns the size of a block device or a regular file.
func DeviceSize(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrap(err, "open target")
	}
	defer f.Close()
	return deviceSize(f)
}

// SectorSize returns the logical sector size of a block device, or 512 for
// a regular file.
func SectorSize(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrap(err, "open target")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, errors.Wrap(err, "stat target")
	}
	if st.Mode()&os.ModeDevice == 0 {
		return 512, nil
	}
	n, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKSSZGET)
	return n, errors.Wrap(err, "BLKSSZGET")
}

func deviceSize(f *os.File) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, errors.Wrap(err, "stat target")
	}
	if st.Mode()&os.ModeDevice == 0 {
		return st.Size(), nil
	}
	var size uint64
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size))); errno != 0 {
		return 0, errors.Wrap(errno, "BLKGETSIZE64")
	}
	return int64(size), nil
}

// zero clears [off, off+n) of out: BLKZEROOUT on block devices (cheap on
// devices with write-zeroes support), plain zero writes everywhere else.
func zero(out *os.File, off, n int64, touched *bool) error {
	st, err := out.Stat()
	if err != nil {
		return errors.Wrap(err, "stat target")
	}
	if st.Mode()&os.ModeDevice != 0 {
		r := [2]uint64{uint64(off), uint64(n)}
		*touched = true
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, out.Fd(), unix.BLKZEROOUT, uintptr(unsafe.Pointer(&r)))
		if errno == 0 {
			return nil
		}
		if errno != unix.EOPNOTSUPP && errno != unix.ENOTTY && errno != unix.EINVAL {
			return errors.Wrap(errno, "BLKZEROOUT")
		}
	}
	buf := make([]byte, min(n, chunk))
	for done := int64(0); done < n; {
		w := min(int64(len(buf)), n-done)
		*touched = true
		if _, err := out.WriteAt(buf[:w], off+done); err != nil {
			return errors.Wrap(err, "write zeroes")
		}
		done += w
	}
	return nil
}

// openDirect opens path for O_DIRECT reads, falling back to buffered reads on
// filesystems that refuse O_DIRECT (tmpfs, used by the tests).
func openDirect(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECT, 0)
	if errors.Is(err, unix.EINVAL) {
		f, err = os.Open(path)
	}
	return f, errors.Wrap(err, "open target for read-back")
}

func alignUp(n int) int {
	return (n + pageSize - 1) &^ (pageSize - 1)
}
