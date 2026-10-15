//go:build linux

package loop

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexfrei/boot-to-kairos/internal/flash"
)

func TestAttachExposesPartitions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to attach loop devices")
	}
	sgdisk, err := exec.LookPath("sgdisk")
	if err != nil {
		t.Skip("needs sgdisk to build a partitioned image")
	}
	img := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 64<<20); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), sgdisk, "--new=1:0:+8M", img).CombinedOutput(); err != nil {
		t.Fatalf("sgdisk: %v: %s", err, out)
	}

	d, err := Attach(img, 512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Detach() })

	part := d.Path + "p1"
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(part); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear: the loop device was attached without partition scanning", part)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := d.Detach(); err != nil {
		t.Fatal(err)
	}
	backing, _ := os.ReadFile(filepath.Join("/sys/block", filepath.Base(d.Path), "loop/backing_file"))
	if len(backing) != 0 {
		t.Fatalf("%s still backed by %s after Detach", d.Path, backing)
	}
}

func TestAttachUsesTheTargetSectorSize(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to attach loop devices")
	}
	img := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 64<<20); err != nil {
		t.Fatal(err)
	}
	d, err := Attach(img, 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Detach() })

	b, err := os.ReadFile(filepath.Join("/sys/block", filepath.Base(d.Path), "queue/logical_block_size"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "4096" {
		t.Fatalf("logical block size = %s, want 4096: a GPT written for 512-byte sectors is invalid on a 4Kn disk", got)
	}
	if n, err := flash.SectorSize(d.Path); err != nil || n != 4096 {
		t.Fatalf("flash.SectorSize(%s) = %d, %v, want 4096", d.Path, n, err)
	}
}
