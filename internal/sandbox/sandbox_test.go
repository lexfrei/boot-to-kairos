//go:build linux

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

//nolint:dupword // mountinfo repeats the fstype as the source for pseudo filesystems
const mountinfo = `22 1 253:1 / / rw - ext4 /dev/vda1 rw
40 22 0:5 / /run/btk/root/proc rw - proc proc rw
41 22 0:21 / /run/btk/root/sys rw - sysfs sysfs rw
42 41 0:30 / /run/btk/root/sys/fs/cgroup rw - cgroup2 cgroup2 rw
43 22 0:6 / /run/btk/root/dev rw - devtmpfs udev rw
44 22 0:40 / /run/btk/root-other rw - tmpfs tmpfs rw
45 22 0:41 / /run/btk/root/btk\040src rw - ext4 /dev/vda1 rw
`

func TestMountsUnderListsDeepestFirstAndOnlyUnderRoot(t *testing.T) {
	got, err := MountsUnder(strings.NewReader(mountinfo), "/run/btk/root")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/run/btk/root/sys/fs/cgroup",
		"/run/btk/root/btk src",
		"/run/btk/root/dev",
		"/run/btk/root/sys",
		"/run/btk/root/proc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts = %q,\nwant %q", got, want)
	}
}

func TestHostBindsCoverWhatKairosAgentNeeds(t *testing.T) {
	var dst []string
	for _, b := range HostBinds() {
		dst = append(dst, b.Dst)
	}
	want := []string{"proc", "sys", "dev", "run/udev"}
	if !reflect.DeepEqual(dst, want) {
		t.Fatalf("host binds = %v, want %v", dst, want)
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount")
	}
}

// fixture builds an image tree and stand-ins for the host directories. The
// tests never bind real host paths: with broken code under test, the worst a
// cleanup can delete is these stand-ins.
func fixture(t *testing.T) (string, []Bind) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	for _, d := range []string{"usr/bin", "etc"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var binds []Bind
	for _, name := range []string{"proc", "dev"} {
		host := filepath.Join(base, "host-"+name)
		if err := os.MkdirAll(filepath.Join(host, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(host, "marker"), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		binds = append(binds, Bind{Src: host, Dst: name})
	}
	t.Cleanup(func() { lazyUnmountUnder(t, root) })
	return root, binds
}

// lazyUnmountUnder is the test's own safety net and deliberately does not
// call the code under test.
func lazyUnmountUnder(t *testing.T, root string) {
	t.Helper()
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		f := strings.Fields(lines[i])
		if len(f) > 4 && strings.HasPrefix(f[4], root+"/") {
			_ = umountLazy(f[4])
		}
	}
}

func umountLazy(p string) error { return unix.Unmount(p, unix.MNT_DETACH) }

func TestSetupTeardownLeavesNoMounts(t *testing.T) {
	requireRoot(t)
	root, binds := fixture(t)

	if err := Setup(root, binds); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "dev/marker")); err != nil || string(b) != "dev" {
		t.Fatalf("bind not visible in the sandbox: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(root, SourceDir, "etc")); err != nil {
		t.Fatalf("source bind missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, SourceDir, "dev/marker")); !os.IsNotExist(err) {
		t.Fatalf("source bind must not carry the other binds: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, SourceDir, "etc/x"), nil, 0o600); err == nil {
		t.Fatal("source bind is writable, want read-only")
	}

	if err := Teardown(root); err != nil {
		t.Fatal(err)
	}
	mi, _ := os.Open("/proc/self/mountinfo")
	defer mi.Close()
	if left, _ := MountsUnder(mi, root); len(left) != 0 {
		t.Fatalf("mounts left after teardown: %v", left)
	}
}

// The source tree is what kairos-agent copies into the installed system, so
// nothing the installer adds to the sandbox may show up in it.
func TestSourceCarriesNothingTheInstallerAdds(t *testing.T) {
	requireRoot(t)
	root, binds := fixture(t)
	if err := Setup(root, binds); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Teardown(root) })

	if err := os.WriteFile(filepath.Join(root, "run/btk-config.yaml"), []byte("#cloud-config\n"), 0o600); err != nil {
		t.Fatalf("installer files must go to the sandbox's private /run: %v", err)
	}

	src := filepath.Join(root, SourceDir)
	var leaked []string
	err := filepath.WalkDir(src, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		switch rel {
		case ".", "run", "usr", "usr/bin", "etc":
		case "proc", "dev":
			// mount points the image would have anyway
		default:
			leaked = append(leaked, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaked) != 0 {
		t.Fatalf("installer artifacts visible in the install source: %v", leaked)
	}
}

type mountCall struct {
	src, target, fstype string
	flags               uintptr
}

func recordMounts(calls *[]mountCall, err error) func(string, string, string, uintptr, string) error {
	return func(src, target, fstype string, flags uintptr, _ string) error {
		*calls = append(*calls, mountCall{src, target, fstype, flags})
		return err
	}
}

// kairos-agent must not reach NVRAM before the disk it installs onto has
// been written and verified, so the variables are covered for the build.
// Kernels before 6.0 also expose the variables through the sysfs vars
// directory, which libefivar falls back to when efivars is not efivarfs.
func TestHideEFIVarsCoversThemReadOnly(t *testing.T) {
	for _, dirs := range [][]string{{"efivars"}, {"vars"}, {"efivars", "vars"}} {
		root := t.TempDir()
		var want []string
		for _, d := range dirs {
			want = append(want, filepath.Join(root, "sys/firmware/efi", d))
			if err := os.MkdirAll(want[len(want)-1], 0o755); err != nil {
				t.Fatal(err)
			}
		}
		var calls []mountCall
		if err := hideEFIVars(root, recordMounts(&calls, nil)); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, c := range calls {
			if c.fstype != "tmpfs" || c.flags&unix.MS_RDONLY == 0 {
				t.Errorf("mount %+v is not a read-only tmpfs", c)
			}
			got = append(got, c.target)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("mounted on %v, want %v", got, want)
		}
	}
}

func TestHideEFIVarsWithoutEFI(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/firmware"), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []mountCall
	if err := hideEFIVars(root, recordMounts(&calls, nil)); err != nil || len(calls) != 0 {
		t.Fatalf("%v, mounts %+v; nothing to hide", err, calls)
	}
}

func TestHideEFIVarsFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/firmware/efi/efivars"), 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []mountCall
	if err := hideEFIVars(root, recordMounts(&calls, unix.EPERM)); !errors.Is(err, unix.EPERM) {
		t.Fatalf("mount failure gave %v", err)
	}
	// A path that cannot be checked is not taken as absent.
	file := t.TempDir()
	if err := os.MkdirAll(filepath.Join(file, "sys/firmware"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(file, "sys/firmware/efi"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hideEFIVars(file, recordMounts(&calls, nil)); err == nil {
		t.Fatal("an unreadable efivars path taken as absent")
	}
}

// The real mounts, on stand-ins: the build sees no variables while the
// stand-in for the host's efivarfs keeps them.
func TestSetupHidesEFIVars(t *testing.T) {
	requireRoot(t)
	root, binds := fixture(t)
	host := filepath.Join(filepath.Dir(root), "host-sys")
	hostVars := filepath.Join(host, "firmware/efi/efivars")
	if err := os.MkdirAll(hostVars, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(host, "firmware/efi/vars/new_var")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	boot := filepath.Join(hostVars, "Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err := os.WriteFile(boot, []byte{7, 0, 0, 0, 1}, 0o644); err != nil {
		t.Fatal(err)
	}
	binds = append(binds, Bind{Src: host, Dst: "sys"})
	if err := Setup(root, binds); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "sys/firmware/efi/efivars")
	for _, d := range []string{inside, filepath.Join(root, "sys/firmware/efi/vars")} {
		if ents, err := os.ReadDir(d); err != nil || len(ents) != 0 {
			t.Fatalf("the build sees %v, %v in %s", ents, err, d)
		}
	}
	if err := os.WriteFile(filepath.Join(inside, "Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c"), []byte{7, 0, 0, 0}, 0o644); !errors.Is(err, unix.EROFS) {
		t.Fatalf("writing a variable in the build: %v, want EROFS", err)
	}
	if err := Teardown(root); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(boot); err != nil || len(b) != 5 {
		t.Fatalf("host stand-in variable after teardown: %x, %v", b, err)
	}
	if ents, _ := os.ReadDir(hostVars); len(ents) != 1 {
		t.Fatalf("host stand-in holds %v", ents)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("host stand-in for the legacy interface: %v", err)
	}
}
