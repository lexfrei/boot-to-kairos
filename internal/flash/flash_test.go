//go:build linux

package flash

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const page = 4096

// sparseSource writes data at the given offsets into a file of the given size,
// leaving everything else as holes.
func sparseSource(t *testing.T, size int64, chunks map[int64][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.raw")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	for off, b := range chunks {
		if _, err := f.WriteAt(b, off); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// dirtyTarget stands in for a disk that still carries the previous OS.
func dirtyTarget(t *testing.T, size int64) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(p, bytes.Repeat([]byte{0xAA}, int(size)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtentsCoverWholeFile(t *testing.T) {
	size := int64(64 * page)
	src := sparseSource(t, size, map[int64][]byte{
		4 * page:  bytes.Repeat([]byte{1}, page),
		40 * page: bytes.Repeat([]byte{2}, 2*page),
	})
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ext, err := Extents(f)
	if err != nil {
		t.Fatal(err)
	}
	var next int64
	var data int64
	for _, e := range ext {
		if e.Off != next {
			t.Fatalf("gap or overlap at %d, extent starts at %d", next, e.Off)
		}
		next = e.Off + e.Len
		if e.Data {
			data += e.Len
		}
	}
	if next != size {
		t.Fatalf("extents end at %d, want %d", next, size)
	}
	if data < 3*page {
		t.Fatalf("data extents cover %d bytes, want at least %d", data, 3*page)
	}
}

func TestWriteVerifiedReplacesPreviousContent(t *testing.T) {
	size := int64(256 * page)
	src := sparseSource(t, size, map[int64][]byte{
		0:          bytes.Repeat([]byte{0x11}, page),
		100 * page: bytes.Repeat([]byte{0x22}, 3*page),
		255 * page: bytes.Repeat([]byte{0x33}, page),
	})
	dst := dirtyTarget(t, size)

	if _, err := WriteVerified(src, dst, 3); err != nil {
		t.Fatal(err)
	}

	want, _ := os.ReadFile(src)
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(want, got) {
		t.Fatal("target differs from source: holes were not zeroed or data not copied")
	}
}

func TestVerifyFindsPagesChangedAfterWrite(t *testing.T) {
	size := int64(32 * page)
	src := sparseSource(t, size, map[int64][]byte{8 * page: bytes.Repeat([]byte{7}, page)})
	dst := dirtyTarget(t, size)
	if _, err := Copy(src, dst); err != nil {
		t.Fatal(err)
	}

	// A late flush from the old filesystem lands after the copy.
	f, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("stale"), 20*page+17); err != nil {
		t.Fatal(err)
	}
	f.Close()

	bad, err := Verify(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 || bad[0] != 20*page {
		t.Fatalf("bad pages = %v, want [%d]", bad, 20*page)
	}

	if err := Repair(src, dst, bad); err != nil {
		t.Fatal(err)
	}
	if bad, err = Verify(src, dst); err != nil || len(bad) != 0 {
		t.Fatalf("after repair: bad=%v err=%v", bad, err)
	}
}

func lateWrite(t *testing.T, off int64) {
	t.Helper()
	afterCopy = func(dst string) {
		f, err := os.OpenFile(dst, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteAt([]byte("stale"), off); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { afterCopy = func(string) {} })
}

func TestWriteVerifiedRepairsLateWrite(t *testing.T) {
	size := int64(32 * page)
	src := sparseSource(t, size, map[int64][]byte{2 * page: bytes.Repeat([]byte{9}, page)})
	dst := dirtyTarget(t, size)
	lateWrite(t, 5*page+3)

	st, err := WriteVerified(src, dst, 2)
	if err != nil {
		t.Fatal(err)
	}
	if st.Repairs != 1 {
		t.Fatalf("repairs = %d, want 1", st.Repairs)
	}
	want, _ := os.ReadFile(src)
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(want, got) {
		t.Fatal("target differs from source after repair")
	}
}

func TestWriteVerifiedFailsWhenRepairsAreNotAllowed(t *testing.T) {
	size := int64(16 * page)
	src := sparseSource(t, size, nil)
	dst := dirtyTarget(t, size)
	lateWrite(t, 3*page)

	if _, err := WriteVerified(src, dst, 0); !errors.Is(err, ErrUnrepaired) {
		t.Fatalf("err = %v, want ErrUnrepaired", err)
	}
}

func TestWriteVerifiedRejectsTargetSmallerThanImage(t *testing.T) {
	src := sparseSource(t, 16*page, nil)
	dst := dirtyTarget(t, 8*page)
	if _, err := WriteVerified(src, dst, 1); !errors.Is(err, ErrTargetTooSmall) {
		t.Fatalf("err = %v, want ErrTargetTooSmall", err)
	}
}

func TestWriteVerifiedSaysWhenNothingWasWritten(t *testing.T) {
	src := sparseSource(t, 16*page, nil)
	// Failing before the first byte leaves the disk as it was: the caller
	// can undo the freeze instead of declaring the disk lost.
	if _, err := WriteVerified(src, filepath.Join(t.TempDir(), "missing"), 1); !errors.Is(err, ErrNothingWritten) {
		t.Fatalf("err = %v, want ErrNothingWritten for a target that cannot be opened", err)
	}
	if _, err := WriteVerified(src, dirtyTarget(t, 8*page), 1); !errors.Is(err, ErrNothingWritten) {
		t.Fatalf("err = %v, want ErrNothingWritten for a target that is too small", err)
	}
	orig := afterCopy
	t.Cleanup(func() { afterCopy = orig })
	afterCopy = func(dst string) {
		f, err := os.OpenFile(dst, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		for off := int64(0); off < 16*page; off += page {
			if _, err := f.WriteAt([]byte{0xff}, off); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err := WriteVerified(src, dirtyTarget(t, 16*page), 0)
	if !errors.Is(err, ErrUnrepaired) || errors.Is(err, ErrNothingWritten) {
		t.Fatalf("err = %v, want ErrUnrepaired alone once the disk was written", err)
	}
}

func TestCopyMarksOnlyFailuresBeforeTheFirstTouch(t *testing.T) {
	orig := zeroFn
	t.Cleanup(func() { zeroFn = orig })
	src := sparseSource(t, 16*page, nil) // all hole: the first step zeroes
	for name, tc := range map[string]struct {
		touch bool
		want  bool
	}{
		"fails before touching": {touch: false, want: true},
		"fails after touching":  {touch: true, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			zeroFn = func(_ *os.File, _, _ int64, touched *bool) error {
				*touched = tc.touch
				return os.ErrPermission
			}
			_, err := Copy(src, dirtyTarget(t, 16*page))
			if got := errors.Is(err, ErrNothingWritten); got != tc.want {
				t.Fatalf("err = %v, ErrNothingWritten = %v, want %v", err, got, tc.want)
			}
		})
	}
}
