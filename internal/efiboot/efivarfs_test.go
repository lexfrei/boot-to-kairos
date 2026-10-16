//go:build linux

package efiboot

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEfivarfsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SecureBoot-"+globalVendor), []byte{6, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Boot0000-0000-other-vendor"), []byte{7, 0, 0, 0, 1}, 0o644); err != nil {
		t.Fatal(err)
	}
	e := efivarfs(dir)
	if err := e.write("Boot0001", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "Boot0001-"+globalVendor))
	if err != nil || !bytes.Equal(raw, []byte{7, 0, 0, 0, 1, 2, 3}) {
		t.Fatalf("file %x, %v; want attributes then data", raw, err)
	}
	if got, err := e.read("Boot0001"); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("read %x, %v", got, err)
	}
	names, err := e.names()
	slices.Sort(names)
	if err != nil || !slices.Equal(names, []string{"Boot0001", "SecureBoot"}) {
		t.Fatalf("names %v, %v", names, err)
	}
	if err := e.remove("Boot0001"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.read("Boot0001"); !os.IsNotExist(err) {
		t.Fatalf("after remove: %v", err)
	}
}

func TestEfivarfsShortVariable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "BootOrder-"+globalVendor), []byte{7, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := efivarfs(dir).read("BootOrder"); err == nil {
		t.Fatal("a variable without its attributes was read")
	}
}

func TestAvailable(t *testing.T) {
	if err := Available(t.TempDir()); err == nil {
		t.Fatal("a plain directory taken for efivarfs")
	}
	if err := usable(&unix.Statfs_t{Type: unix.EFIVARFS_MAGIC}); err != nil {
		t.Fatal(err)
	}
	if err := usable(&unix.Statfs_t{Type: unix.EFIVARFS_MAGIC, Flags: unix.ST_RDONLY}); err == nil {
		t.Fatal("a read-only efivarfs taken as writable")
	}
}

// The kernel marks variables outside its allowlist immutable, and anyone
// can chattr one; Apply has to clear that to replace or remove it. Needs
// root and a filesystem with inode flags, which the tmpfs under /tmp may
// lack, so it works in the package directory.
func TestEfivarfsImmutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set the immutable flag")
	}
	dir, err := os.MkdirTemp(".", "efivars-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setFlags(t, dir, "Boot0001", 0); setFlags(t, dir, "BootOrder", 0); os.RemoveAll(dir) })
	e := efivarfs(dir)
	for _, name := range []string{"Boot0001", "BootOrder"} {
		if err := e.write(name, []byte{1, 0}); err != nil {
			t.Fatal(err)
		}
		setFlags(t, dir, name, fsImmutable)
	}
	if err := e.write("BootOrder", []byte{2, 0}); err != nil {
		t.Fatalf("write over an immutable variable: %v", err)
	}
	if got, _ := e.read("BootOrder"); !bytes.Equal(got, []byte{2, 0}) {
		t.Fatalf("BootOrder %x", got)
	}
	if err := e.remove("Boot0001"); err != nil {
		t.Fatalf("remove an immutable variable: %v", err)
	}
}

func setFlags(t *testing.T, dir, name string, flags int) {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, name+"-"+globalVendor))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, flags); err != nil {
		t.Fatal(err)
	}
}
