//go:build linux

package install

import (
	"errors"
	"strings"
	"testing"
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
