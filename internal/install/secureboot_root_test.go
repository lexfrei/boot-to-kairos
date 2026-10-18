//go:build linux

package install

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/efiboot"
	"github.com/lexfrei/boot-to-kairos/internal/loop"
)

// espImage attaches a GPT image with a vfat ESP as its second partition,
// holding files, and returns the loop device.
func espImage(t *testing.T, files map[string]string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to attach and mount a loop device")
	}
	for _, bin := range []string{"sfdisk", "mkfs.vfat"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("needs %s", bin)
		}
	}
	img := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 96<<20); err != nil {
		t.Fatal(err)
	}
	table := "label: gpt\n,16M,L\n,64M,U\n"
	cmd := exec.CommandContext(t.Context(), "sfdisk", "--quiet", img)
	cmd.Stdin = strings.NewReader(table)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sfdisk: %v: %s", err, out)
	}
	d, err := loop.Attach(img, 512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Detach() })
	part := d.Path + "p2"
	for i := 0; ; i++ {
		if _, err := os.Stat(part); err == nil {
			break
		} else if i == 50 {
			t.Fatalf("%s never appeared: %v", part, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if out, err := exec.CommandContext(t.Context(), "mkfs.vfat", part).CombinedOutput(); err != nil {
		t.Fatalf("mkfs.vfat: %v: %s", err, out)
	}
	mnt := t.TempDir()
	if err := unix.Mount(part, mnt, "vfat", 0, ""); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		p := filepath.Join(mnt, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Unmount(mnt, 0); err != nil {
		t.Fatal(err)
	}
	return d.Path
}

// bootFiles names the fallback loader and GRUB for this machine.
func bootFiles(t *testing.T) (string, string) {
	t.Helper()
	loader, err := efiboot.LoaderPath(runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	loader = path.Base(strings.ReplaceAll(loader, `\`, "/"))
	return loader, grubName(loader)
}

func kernelRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "boot"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot/vmlinuz-1"), []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/boot/vmlinuz-1", filepath.Join(root, "boot/vmlinuz")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestReadChainFromTheESP(t *testing.T) {
	// kairos-agent writes EFI/boot in lower case; the firmware and vfat do
	// not care.
	loader, grub := bootFiles(t)
	dev := espImage(t, map[string]string{"EFI/boot/" + strings.ToLower(loader): "shim", "EFI/boot/" + grub: "grub"})
	mnt := filepath.Join(t.TempDir(), "esp")
	c, err := readChain(dev, 512, kernelRoot(t), mnt)
	if err != nil {
		t.Fatal(err)
	}
	if c.Loader != loader || string(c.LoaderPE) != "shim" || c.Grub != grub || string(c.GrubPE) != "grub" || string(c.KernelPE) != "kernel" {
		t.Errorf("chain %s=%q %s=%q kernel=%q", c.Loader, c.LoaderPE, c.Grub, c.GrubPE, c.KernelPE)
	}
	if _, err := os.Stat(mnt); !os.IsNotExist(err) {
		t.Errorf("the mount point stayed: %v", err)
	}
}

func TestReadChainWithoutGrubOrKernel(t *testing.T) {
	loader, _ := bootFiles(t)
	dev := espImage(t, map[string]string{"EFI/BOOT/" + loader: "grub"})
	c, err := readChain(dev, 512, t.TempDir(), filepath.Join(t.TempDir(), "esp"))
	if err != nil {
		t.Fatal(err)
	}
	if c.GrubPE != nil || c.KernelPE != nil || string(c.LoaderPE) != "grub" {
		t.Errorf("absent files must read as nil: grub %q, kernel %q", c.GrubPE, c.KernelPE)
	}
}

func TestReadChainWithoutLoader(t *testing.T) {
	dev := espImage(t, map[string]string{"EFI/other/x.efi": "x"})
	mnt := filepath.Join(t.TempDir(), "esp")
	if _, err := readChain(dev, 512, t.TempDir(), mnt); err == nil {
		t.Error("an ESP without the fallback loader has nothing for the firmware to boot")
	}
	if _, err := os.Stat(mnt); !os.IsNotExist(err) {
		t.Errorf("the mount point stayed after a failure: %v", err)
	}
}
