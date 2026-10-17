//go:build linux

package install

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"

	cerrors "github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

func TestMemBudget(t *testing.T) {
	meminfo := "MemTotal:        8000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4194304 kB\n"
	got, err := memBudget(strings.NewReader(meminfo))
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(4194304<<10) - memReserve; got != want {
		t.Fatalf("budget = %d, want %d: what is available now, less a reserve", got, want)
	}
	if _, err := memBudget(strings.NewReader("MemAvailable: 1024 kB\n")); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory", err)
	}
}

func TestSplitBudget(t *testing.T) {
	budget := uint64(4 << 30)
	rootfs, work, err := splitBudget(budget, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if rootfs != 1<<30+rootfsHeadroom || rootfs+work != budget {
		t.Fatalf("rootfs = %d, work = %d: the two together must stay within %d", rootfs, work, budget)
	}
	if _, _, err := splitBudget(budget, budget); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory when the unpacked image leaves nothing for the disk image", err)
	}
}

func TestBlobFits(t *testing.T) {
	budget := uint64(2 << 30)
	if err := blobFits(budget, 1<<30, int64(budget-1<<30-rootfsHeadroom)); err != nil {
		t.Fatalf("a layer that just fits beside the unpacked image and the headroom: %v", err)
	}
	if err := blobFits(budget, 1<<30, int64(budget-1<<30-rootfsHeadroom+1)); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory for a layer one byte too large", err)
	}
	if err := blobFits(budget, 0, int64(budget)+1); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory for a layer larger than the budget", err)
	}
	if err := blobFits(budget, 0, -1); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory for a negative size", err)
	}
}

func TestLayersFit(t *testing.T) {
	budget := uint64(1100 << 20)
	// 100 then 520 MiB: the second passes blobFits at 100+520+256 MiB, but
	// unpacked to 620 MiB it overflows the 580 MiB cap its copy leaves.
	// 520 then 100 MiB peaks at 620+100 and fits.
	if err := layersFit(budget, []int64{520 << 20, 100 << 20}); err != nil {
		t.Fatalf("520 then 100 MiB in 1100: %v", err)
	}
	if err := layersFit(budget, []int64{100 << 20, 520 << 20}); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory: 100 then 520 MiB overflows the cap", err)
	}
	// What the install itself would pass must pass here: 100 then 400 MiB
	// peaks at 500+400 MiB, and one 500 MiB layer at 500+500.
	for _, sizes := range [][]int64{{100 << 20, 400 << 20}, {500 << 20}} {
		if err := layersFit(budget, sizes); err != nil {
			t.Fatalf("%v in 1100 MiB: %v", sizes, err)
		}
	}
	if err := layersFit(budget, []int64{900 << 20}); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory: 900 MiB staged leaves no headroom", err)
	}
	if err := layersFit(budget, []int64{-1}); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory for a negative size", err)
	}
	if err := blobFits(budget, math.MaxUint64-rootfsHeadroom, 1); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory for use past the budget, not a sum that wraps around", err)
	}
}

func TestCapRootfsLeavesRoomForTheStagedLayer(t *testing.T) {
	var got []string
	t.Cleanup(func() { remount = unix.Mount })
	remount = func(source, target, fstype string, flags uintptr, data string) error {
		if flags != unix.MS_REMOUNT {
			t.Errorf("flags = %#x, want MS_REMOUNT", flags)
		}
		got = append(got, target+" "+data)
		return nil
	}
	budget := uint64(1 << 30)
	if err := capRootfs("/root", budget, 300<<20, 100<<20); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("/root size=%d", budget-100<<20); len(got) != 1 || got[0] != want {
		t.Fatalf("remounts = %q, want %q: the unpacked image may grow only into what the staged layer leaves", got, want)
	}
	if err := capRootfs("/root", budget, 900<<20, 100<<20); !errors.Is(err, ErrNotEnoughMemory) || len(got) != 1 {
		t.Fatalf("err = %v after %d remounts, want ErrNotEnoughMemory before any", err, len(got))
	}
}

func TestOutOfRoomIsNotEnoughMemory(t *testing.T) {
	// Wrapped as Extract and extractTar wrap it.
	full := cerrors.Wrapf(cerrors.Wrapf(&os.PathError{Op: "write", Path: "usr/lib/x", Err: unix.ENOSPC}, "extract %s", "usr/lib/x"), "layer %d", 1)
	if err := outOfRoom(full); !errors.Is(err, ErrNotEnoughMemory) || !errors.Is(err, unix.ENOSPC) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory that keeps the ENOSPC", err)
	}
	other := os.ErrClosed
	if err := outOfRoom(other); !errors.Is(err, other) || errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want any other error left as it was", err)
	}
}
