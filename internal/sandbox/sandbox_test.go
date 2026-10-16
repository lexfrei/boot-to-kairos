//go:build linux

package sandbox

import (
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
