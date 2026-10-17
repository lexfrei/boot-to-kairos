//go:build linux

package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/loop"
)

// scratchFS makes a filesystem of type fs on a loop device over a file of
// its own and mounts it on a temp dir.
func scratchFS(t *testing.T, mkfs string, args ...string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to attach and mount a loop device")
	}
	bin, err := exec.LookPath(mkfs)
	if err != nil {
		t.Skipf("needs %s", mkfs)
	}
	img := filepath.Join(t.TempDir(), "fs.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 128<<20); err != nil {
		t.Fatal(err)
	}
	d, err := loop.Attach(img, 512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Detach() })
	if out, err := exec.CommandContext(t.Context(), bin, append(args, d.Path)...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", mkfs, err, out)
	}
	mnt := t.TempDir()
	fstype := strings.TrimPrefix(mkfs, "mkfs.")
	if err := unix.Mount(d.Path, mnt, fstype, 0, ""); err != nil {
		t.Fatalf("mount %s: %v", fstype, err)
	}
	// Registered last, so it runs before the detach.
	t.Cleanup(func() { _ = unix.Unmount(mnt, 0) })
	return mnt
}

func TestProbeHolesOnRealFilesystems(t *testing.T) {
	ext4 := scratchFS(t, "mkfs.ext4", "-q", "-b", "4096")
	if err := probeHoles(ext4, 1<<40); err != nil {
		t.Errorf("ext4: %v, want it to keep holes and take a 1 TiB file", err)
	}
	// 4 KiB blocks cap an ext4 file at 16 TiB.
	if err := probeHoles(ext4, 32<<40); err == nil || !strings.Contains(err.Error(), "32768 GiB") {
		t.Errorf("ext4 with a 32 TiB disk: %v, want a refusal naming the size", err)
	}
	err := probeHoles(scratchFS(t, "mkfs.vfat"), 1<<30)
	if err == nil || !strings.Contains(err.Error(), "allocated") {
		t.Errorf("vfat: %v, want a refusal: it keeps no holes", err)
	}
}

func TestOpenWorkDirRefusesAFileBackedLoopDevice(t *testing.T) {
	mnt := scratchFS(t, "mkfs.ext4", "-q")
	_, err := openWorkDir(mnt, "/dev/vda", 1<<30, workDirUnfit)
	if !errors.Is(err, ErrBadWorkDir) || !strings.Contains(err.Error(), "backed by a file") {
		t.Fatalf("openWorkDir = %v, want a refusal of the loop device the scratch filesystem is on", err)
	}
}
