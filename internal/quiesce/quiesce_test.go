//go:build linux

package quiesce

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fakeSysfs builds /sys/class/block and /sys/dev/block for a disk vda with
// partitions vda1..vda3, an LVM volume dm-0 on vda3, and an unrelated disk vdb.
func fakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	devices := filepath.Join(root, "devices/virtual/block")
	mk := func(rel string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, name string) {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	vda := mk("devices/pci0000:00/virtio1/block/vda")
	for _, p := range []string{"vda1", "vda2", "vda3"} {
		part := mk("devices/pci0000:00/virtio1/block/vda/" + p)
		if err := os.WriteFile(filepath.Join(part, "partition"), []byte(p[3:]+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vdb := mk("devices/pci0000:00/virtio2/block/vdb")
	dm := mk("devices/virtual/block/dm-0")
	_ = devices
	link(filepath.Join(vda, "vda3"), filepath.Join(dm, "slaves/vda3"))

	cls := filepath.Join(root, "class/block")
	link(vda, filepath.Join(cls, "vda"))
	link(vdb, filepath.Join(cls, "vdb"))
	link(dm, filepath.Join(cls, "dm-0"))
	for _, p := range []string{"vda1", "vda2", "vda3"} {
		link(filepath.Join(vda, p), filepath.Join(cls, p))
	}

	dev := filepath.Join(root, "dev/block")
	link(filepath.Join(vda, "vda1"), filepath.Join(dev, "253:1"))
	link(filepath.Join(vda, "vda2"), filepath.Join(dev, "253:2"))
	link(filepath.Join(vda, "vda3"), filepath.Join(dev, "253:3"))
	link(vdb, filepath.Join(dev, "253:16"))
	link(dm, filepath.Join(dev, "252:0"))
	return root
}

//nolint:dupword // "tmpfs tmpfs" is how mountinfo spells fstype and source
const mountinfo = `22 1 253:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
23 22 253:2 / /boot/efi rw,relatime shared:2 - vfat /dev/vda2 rw
24 22 0:21 / /run rw,nosuid shared:3 - tmpfs tmpfs rw
25 22 252:0 / /var/lib/data rw,relatime shared:4 - xfs /dev/mapper/vg-data rw
26 22 253:16 / /mnt/other rw,relatime shared:5 - ext4 /dev/vdb rw
27 22 253:1 /srv /srv rw,relatime shared:1 - ext4 /dev/vda1 rw
`

func TestMountsOnDiskIncludesPartitionsAndStackedDevices(t *testing.T) {
	sys := fakeSysfs(t)
	got, err := MountsOnDisk(strings.NewReader(mountinfo), sys, "vda", noDevOf)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/var/lib/data", "/boot/efi", "/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts = %v, want %v (deepest first, one per filesystem, nothing from vdb or tmpfs)", got, want)
	}
}

func noDevOf(path string) (string, error) { return "", os.ErrNotExist }

// btrfsSysfs adds a partition vda4 and a btrfs filesystem spanning vdb and
// vda4 to the fake sysfs.
func btrfsSysfs(t *testing.T) string {
	t.Helper()
	sys := fakeSysfs(t)
	vda4 := filepath.Join(sys, "devices/pci0000:00/virtio1/block/vda/vda4")
	if err := os.MkdirAll(vda4, 0o755); err != nil {
		t.Fatal(err)
	}
	devs := filepath.Join(sys, "fs/btrfs/0b5e1f3a-uuid/devices")
	if err := os.MkdirAll(devs, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		filepath.Join(sys, "class/block/vda4"): vda4,
		filepath.Join(sys, "dev/block/253:4"):  vda4,
		filepath.Join(devs, "vda4"):            vda4,
		filepath.Join(devs, "vdb"):             filepath.Join(sys, "devices/pci0000:00/virtio2/block/vdb"),
	} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	return sys
}

func TestMountsOnDiskResolvesBtrfsAcrossItsDevices(t *testing.T) {
	sys := btrfsSysfs(t)
	// btrfs reports an anonymous 0:N device; the source names only one of
	// its devices, here the one that is not on vda.
	mi := `22 1 253:1 / / rw - ext4 /dev/vda1 rw
40 22 0:40 /@home /home rw - btrfs /dev/vdb rw
`
	devOf := func(path string) (string, error) {
		if path == "/dev/vdb" {
			return "253:16", nil
		}
		return "", os.ErrNotExist
	}
	got, err := MountsOnDisk(strings.NewReader(mi), sys, "vda", devOf)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/home", "/"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts = %v, want %v: a btrfs filesystem with a device on the disk must be quiesced", got, want)
	}
}

func TestMountsOnDiskRefusesWhatItCannotPlace(t *testing.T) {
	for name, mi := range map[string]string{
		"zfs":        "30 1 0:50 / /tank rw - zfs tank/data rw\n",
		"unresolved": "31 1 0:51 / /mnt/x rw - btrfs /dev/gone rw\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := MountsOnDisk(strings.NewReader(mi), fakeSysfs(t), "vda", noDevOf)
			if !errors.Is(err, ErrUnplaceable) {
				t.Fatalf("err = %v, want ErrUnplaceable: a filesystem that may live on the disk must stop the install before anything changes", err)
			}
		})
	}
}

//nolint:dupword // mountinfo spells fstype and source alike for these
func TestMountsOnDiskIgnoresVirtualFilesystems(t *testing.T) {
	mi := `24 22 0:21 / /run rw - tmpfs tmpfs rw
28 22 0:5 / /dev rw - devtmpfs udev rw
29 22 0:30 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw
`
	got, err := MountsOnDisk(strings.NewReader(mi), fakeSysfs(t), "vda", noDevOf)
	if err != nil || len(got) != 0 {
		t.Fatalf("mounts = %v, %v, want none", got, err)
	}
}

func TestDiskNameAcceptsDevPath(t *testing.T) {
	if got := DiskName("/dev/nvme0n1"); got != "nvme0n1" {
		t.Fatalf("DiskName = %q", got)
	}
}

func TestRunUndoesCompletedStepsWhenOneFails(t *testing.T) {
	var log []string
	step := func(name string, fail bool) Step {
		return Step{Name: name, Do: func() (func() error, error) {
			if fail {
				return nil, os.ErrPermission
			}
			log = append(log, "do "+name)
			return func() error { log = append(log, "undo "+name); return nil }, nil
		}}
	}
	_, err := Run([]Step{step("swapoff", false), step("freeze /", false), step("freeze /boot", true), step("never", false)})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("err = %v", err)
	}
	want := []string{"do swapoff", "do freeze /", "undo freeze /", "undo swapoff"}
	if !reflect.DeepEqual(log, want) {
		t.Fatalf("log = %v, want %v: a failed quiesce must leave the running system as it was", log, want)
	}

	log = nil
	undo, err := Run([]Step{step("a", false), step("b", false)})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"do a", "do b"}; !reflect.DeepEqual(log, want) {
		t.Fatalf("log = %v, want %v", log, want)
	}
	// A write that fails before its first byte hands the disk back intact,
	// so what quiesced it is undone after all.
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"do a", "do b", "undo b", "undo a"}; !reflect.DeepEqual(log, want) {
		t.Fatalf("log = %v, want %v", log, want)
	}
}

func TestMountsOnDiskJudgesReadOnlyByTheSuperblock(t *testing.T) {
	// A read-only snapshot as / with writable subvolumes of the same btrfs
	// beside it: the filesystem writes, whatever the first mount says.
	mi := `22 1 0:33 /@/.snapshots/1/snapshot / ro,relatime shared:1 - btrfs /dev/vda1 rw,space_cache=v2
23 22 0:33 /@/var /var rw,relatime shared:2 - btrfs /dev/vda1 rw,space_cache=v2
24 22 253:2 / /boot/efi ro,relatime shared:3 - vfat /dev/vda2 ro
`
	devOf := func(path string) (string, error) {
		if path == "/dev/vda1" {
			return "253:1", nil
		}
		return "", os.ErrNotExist
	}
	got, err := MountsOnDisk(strings.NewReader(mi), fakeSysfs(t), "vda", devOf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || (got[0] != "/" && got[0] != "/var") {
		t.Fatalf("mounts = %v, want the btrfs once and not the read-only vfat", got)
	}
}

//nolint:dupword // mountinfo spells fstype and source alike for tmpfs
func TestMountsOnDiskSkipsMountPointsThatAreMountedOver(t *testing.T) {
	// Opening /mnt/a reaches the tmpfs on top, so it cannot freeze vda1.
	mi := `30 1 253:1 / /mnt/a rw - ext4 /dev/vda1 rw
31 30 0:40 / /mnt/a rw - tmpfs tmpfs rw
32 1 253:1 / /srv rw - ext4 /dev/vda1 rw
`
	got, err := MountsOnDisk(strings.NewReader(mi), fakeSysfs(t), "vda", noDevOf)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/srv"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts = %v, want %v", got, want)
	}

	only := `30 1 253:1 / /mnt/a rw - ext4 /dev/vda1 rw
31 30 0:40 / /mnt/a rw - tmpfs tmpfs rw
`
	if _, err := MountsOnDisk(strings.NewReader(only), fakeSysfs(t), "vda", noDevOf); !errors.Is(err, ErrUnplaceable) {
		t.Fatalf("err = %v, want ErrUnplaceable when every mount point of a filesystem is covered", err)
	}
}

// mdSysfs adds an md array md0 built on vda3 and vdb, with a partition
// md0p1, to the fake sysfs.
func mdSysfs(t *testing.T) string {
	t.Helper()
	sys := fakeSysfs(t)
	md0 := filepath.Join(sys, "devices/virtual/block/md0")
	vda3 := filepath.Join(sys, "devices/pci0000:00/virtio1/block/vda/vda3")
	for _, d := range []string{filepath.Join(md0, "md0p1"), filepath.Join(md0, "slaves"), filepath.Join(vda3, "holders")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(md0, "md0p1/partition"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		filepath.Join(md0, "slaves/vda3"):     vda3,
		filepath.Join(md0, "slaves/vdb"):      filepath.Join(sys, "devices/pci0000:00/virtio2/block/vdb"),
		filepath.Join(vda3, "holders/md0"):    md0,
		filepath.Join(sys, "class/block/md0"): md0,
		filepath.Join(sys, "dev/block/9:1"):   filepath.Join(md0, "md0p1"),
	} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	return sys
}

func TestMountsOnDiskFollowsPartitionsOfStackedDevices(t *testing.T) {
	mi := "40 1 9:1 / /data rw - ext4 /dev/md0p1 rw\n"
	got, err := MountsOnDisk(strings.NewReader(mi), mdSysfs(t), "vda", noDevOf)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/data"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts = %v, want %v: a partition of an array on the disk is on the disk", got, want)
	}
}

func noDM(string) ([]string, error) { return nil, os.ErrNotExist }

// holderSysfs stacks a device named holder on vda2.
func holderSysfs(t *testing.T, holder string) string {
	t.Helper()
	sys := fakeSysfs(t)
	h := filepath.Join(sys, "devices/virtual/block", holder)
	vda2 := filepath.Join(sys, "devices/pci0000:00/virtio1/block/vda/vda2")
	if err := os.MkdirAll(h, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(vda2, "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h, filepath.Join(vda2, "holders", holder)); err != nil {
		t.Fatal(err)
	}
	return sys
}

func TestStackedWriter(t *testing.T) {
	targets := func(tt []string, err error) func(string) ([]string, error) {
		return func(string) ([]string, error) { return tt, err }
	}
	for name, tc := range map[string]struct {
		sys    string
		dm     func(string) ([]string, error)
		refuse bool
	}{
		"plain disk":          {fakeSysfs(t), noDM, false},
		"md member":           {mdSysfs(t), noDM, true},
		"bcache backing":      {holderSysfs(t, "bcache0"), noDM, true},
		"LVM linear":          {holderSysfs(t, "dm-1"), targets([]string{"linear", "linear"}, nil), false},
		"dm-crypt":            {holderSysfs(t, "dm-1"), targets([]string{"crypt"}, nil), false},
		"multipath":           {holderSysfs(t, "dm-1"), targets([]string{"multipath"}, nil), false},
		"LVM cache":           {holderSysfs(t, "dm-1"), targets([]string{"cache"}, nil), true},
		"LVM writecache":      {holderSysfs(t, "dm-1"), targets([]string{"writecache"}, nil), true},
		"dm table unreadable": {holderSysfs(t, "dm-1"), noDM, true},
	} {
		t.Run(name, func(t *testing.T) {
			got := StackedWriter(tc.sys, "vda", tc.dm)
			if (got != "") != tc.refuse {
				t.Fatalf("StackedWriter = %q, refuse = %v: a device that writes to the disk on its own survives a freeze", got, tc.refuse)
			}
		})
	}
}

func TestHiddenMounts(t *testing.T) {
	own := "22 1 253:1 / / rw - ext4 /dev/vda1 rw\n"
	sameFS := "50 49 253:1 /var/lib/x /data rw - ext4 /dev/vda1 rw\n"
	hidden := "60 59 253:2 / /mnt rw - vfat /dev/vda2 rw\n"
	elsewhere := "70 69 253:16 / /mnt rw - ext4 /dev/vdb rw\n"
	sys := fakeSysfs(t)
	if err := HiddenMounts(strings.NewReader(own), []Namespace{{"49", strings.NewReader(sameFS)}, {"69", strings.NewReader(elsewhere)}}, sys, "vda", noDevOf); err != nil {
		t.Fatalf("err = %v: a filesystem this namespace also mounts gets frozen through it", err)
	}
	err := HiddenMounts(strings.NewReader(own), []Namespace{{"4242", strings.NewReader(hidden)}}, sys, "vda", noDevOf)
	if !errors.Is(err, ErrUnplaceable) {
		t.Fatalf("err = %v, want ErrUnplaceable for a filesystem on the disk mounted only in another namespace", err)
	}
	if !strings.Contains(err.Error(), "4242") {
		t.Fatalf("err = %v: it must name a process in that namespace, or the user cannot find it", err)
	}
}

func TestRunReportsAFailedUndo(t *testing.T) {
	stuck := Step{Name: "freeze /", Do: func() (func() error, error) {
		return func() error { return os.ErrPermission }, nil
	}}
	fail := Step{Name: "freeze /boot", Do: func() (func() error, error) { return nil, os.ErrInvalid }}
	_, err := Run([]Step{stuck, fail})
	if !errors.Is(err, os.ErrInvalid) || !errors.Is(err, ErrUndoIncomplete) {
		t.Fatalf("err = %v, want the failure marked ErrUndoIncomplete: a filesystem may still be frozen", err)
	}
	clean := Step{Name: "freeze /", Do: func() (func() error, error) { return func() error { return nil }, nil }}
	if _, err := Run([]Step{clean, fail}); errors.Is(err, ErrUndoIncomplete) {
		t.Fatalf("err = %v, marked incomplete although every undo worked", err)
	}
}

func TestOpenMountChecksTheMountID(t *testing.T) {
	// Reads this process's real mountinfo and only opens /proc.
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var procID string
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 4 && f[4] == "/proc" {
			procID = f[0]
		}
	}
	if procID == "" {
		t.Skip("no /proc mount")
	}
	// A path reaches whatever is mounted on top now, which need not be the
	// mount that was picked: an ancestor may have been mounted over.
	f, m, err := OpenMount([]Mount{{ID: "999999999", Point: "/proc"}, {ID: procID, Point: "/proc"}})
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if m.ID != procID {
		t.Fatalf("picked mount %s, want %s", m.ID, procID)
	}
	if _, _, err := OpenMount([]Mount{{ID: "999999999", Point: "/proc"}}); !errors.Is(err, ErrUnplaceable) {
		t.Fatalf("err = %v, want ErrUnplaceable when no path reaches the mount", err)
	}
}

func TestPickNamespacesSurvivesAProcessThatExits(t *testing.T) {
	ns := map[string]string{"10": "mnt:[A]", "11": "mnt:[A]", "12": "mnt:[B]", "13": "mnt:[self]"}
	nsOf := func(pid string) (string, error) {
		if v, ok := ns[pid]; ok {
			return v, nil
		}
		return "", os.ErrNotExist
	}
	mountinfoOf := func(pid string) ([]byte, error) {
		if pid == "10" {
			return nil, os.ErrNotExist // exited after its namespace was read
		}
		return []byte("mountinfo of " + pid), nil
	}
	got := pickNamespaces([]string{"10", "11", "12", "13"}, "mnt:[self]", nsOf, mountinfoOf)
	want := []string{"11: mountinfo of 11", "12: mountinfo of 12"}
	var gotS []string
	for _, n := range got {
		b, _ := io.ReadAll(n.Mountinfo)
		gotS = append(gotS, n.PID+": "+string(b))
	}
	if !reflect.DeepEqual(gotS, want) {
		t.Fatalf("namespaces = %v, want %v: a namespace is done only once its mountinfo was read", gotS, want)
	}
}

func TestSwapsToStop(t *testing.T) {
	swaps := `Filename				Type		Size		Used		Priority
/dev/vda3                               partition	1048572		0		-2
/swap/swap\040file                       file		2097148		0		5
/data/swapfile                          file		2097148		0		-3
/dev/vdb                                partition	1048572		0		-4
/dev/zram0                              partition	4194300		0		100
`
	devOf := func(path string) (string, error) {
		m := map[string]string{"/dev/vda3": "253:3", "/dev/vdb": "253:16", "/dev/zram0": "251:0"}
		if d, ok := m[path]; ok {
			return d, nil
		}
		return "", os.ErrNotExist
	}
	// Files are placed by the mount their open descriptor is on, not by
	// their path, which can be mounted over.
	fileOnDisk := func(path string, _ int64) (bool, error) {
		return map[string]bool{"/swap/swap file": true}[path], nil
	}
	got, err := SwapsToStop(strings.NewReader(swaps), fakeSysfs(t), "vda", devOf, fileOnDisk)
	if err != nil {
		t.Fatal(err)
	}
	// Swap elsewhere stays on: turning it off pulls its pages back into
	// memory the build has filled, for no gain.
	want := []Swap{{Path: "/dev/vda3", Prio: -2}, {Path: "/swap/swap file", Prio: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("swaps = %+v, want %+v", got, want)
	}
	unplaceable := func(string, int64) (bool, error) { return false, os.ErrNotExist }
	if _, err := SwapsToStop(strings.NewReader(swaps), fakeSysfs(t), "vda", devOf, unplaceable); err == nil {
		t.Fatal("a swap file that cannot be placed must stop the install")
	}
}

func TestSwapFlagsKeepThePriority(t *testing.T) {
	// A priority set by the admin comes back on undo; a negative one is the
	// kernel's own and cannot be asked for.
	for prio, want := range map[int]int{5: 0x8005, 0: 0x8000, -2: 0} {
		if got := swapFlags(prio); got != want {
			t.Errorf("swapFlags(%d) = %#x, want %#x", prio, got, want)
		}
	}
}

func TestMountsOffDisk(t *testing.T) {
	got, err := MountsOffDisk(strings.NewReader(mountinfo), fakeSysfs(t), "vda", noDevOf)
	if err != nil {
		t.Fatal(err)
	}
	// One point per filesystem not on the disk: those are synced before the
	// reboot, which the disk's own frozen filesystems must not be.
	if want := []string{"/run", "/mnt/other"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts = %v, want %v", got, want)
	}
}

// fakeProc builds /proc/<pid>/{comm,fd/<n>,fdinfo/<n>}: each fd a link to
// its target, as in the real /proc.
func fakeProc(t *testing.T, fds map[string][2]string) string {
	t.Helper()
	proc := t.TempDir()
	for pidfd, tf := range fds {
		pid, fd, _ := strings.Cut(pidfd, "/")
		for _, d := range []string{"fd", "fdinfo"} {
			if err := os.MkdirAll(filepath.Join(proc, pid, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(tf[0], filepath.Join(proc, pid, "fd", fd)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "fdinfo", fd), []byte("pos:\t0\nflags:\t"+tf[1]+"\nmnt_id:\t1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "comm"), []byte("proc"+pid+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return proc
}

func TestRawWriters(t *testing.T) {
	proc := fakeProc(t, map[string][2]string{
		"100/3": {"/dev/vda1", "0100002"},       // read-write: a VM using the partition as its disk
		"200/4": {"/dev/vda1", "0100000"},       // read-only: blkid probing
		"300/5": {"/dev/vdb", "0100002"},        // read-write on another disk
		"400/6": {"/srv/data.db", "0100002"},    // a file on vda1's filesystem
		"450/8": {"/net/stale/file", "0100002"}, // a file on a dead NFS mount
		"500/7": {"/dev/vda1", "0100002"},       // read-write, but it is us
	})
	blockOf := func(path string) (string, error) {
		// Following an fd to a file on a dead network mount blocks; only
		// device nodes may be looked at.
		target, _ := os.Readlink(path)
		if !strings.HasPrefix(target, "/dev/") {
			t.Errorf("blockOf(%s) followed %s, not a device node", path, target)
		}
		return map[string]string{"/dev/vda1": "253:1", "/dev/vdb": "253:16"}[target], nil
	}
	got := RawWriters(proc, fakeSysfs(t), "vda", blockOf, []string{"500"})
	if want := []string{"100 (proc100)"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("writers = %v, want %v: a process writing to the disk's device bypasses every freeze", got, want)
	}
}

func TestMountsOnDiskFollowsLoopBacking(t *testing.T) {
	sys := fakeSysfs(t)
	for name, backing := range map[string]string{"loop0": "/dev/vda3", "loop1": "/srv/image.raw"} {
		dev := filepath.Join(sys, "devices/virtual/block", name)
		if err := os.MkdirAll(filepath.Join(dev, "loop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dev, "loop/backing_file"), []byte(backing+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for majmin, name := range map[string]string{"7:0": "loop0", "7:1": "loop1"} {
		if err := os.Symlink(filepath.Join(sys, "devices/virtual/block", name), filepath.Join(sys, "dev/block", majmin)); err != nil {
			t.Fatal(err)
		}
	}
	mi := `50 1 7:0 / /mnt/part rw - ext4 /dev/loop0 rw
51 1 7:1 / /mnt/file rw - ext4 /dev/loop1 rw
`
	got, err := MountsOnDisk(strings.NewReader(mi), sys, "vda", noDevOf)
	if err != nil {
		t.Fatal(err)
	}
	// A file-backed loop writes through the filesystem holding the file,
	// which is frozen with the rest; a device-backed one writes to the disk.
	if want := []string{"/mnt/part"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mounts = %v, want %v", got, want)
	}
}

func TestMountsOffDiskSkipsAutomountPoints(t *testing.T) {
	// Opening an autofs point mounts what is behind it, which can be the
	// target disk's own ESP, over the image just written.
	mi := mountinfo + "60 22 0:55 / /efi rw,relatime shared:9 - autofs systemd-1 rw,fd=50\n"
	got, err := MountsOffDisk(strings.NewReader(mi), fakeSysfs(t), "vda", noDevOf)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, "/efi") {
		t.Fatalf("mounts = %v: syncing an automount point triggers it", got)
	}
}

func TestFileOnDiskByUsesTheDescriptorsMount(t *testing.T) {
	file := filepath.Join(t.TempDir(), "swapfile")
	page := int64(os.Getpagesize())
	// Three pages; /proc/swaps counts all but the header one.
	if err := os.WriteFile(file, make([]byte, 3*page), 0o600); err != nil {
		t.Fatal(err)
	}
	active := 2 * page / 1024
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	id, err := mountID(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	place := fileOnDiskBy([]mount{{id: "999999999", onDisk: false}, {id: id, onDisk: true}})
	if on, err := place(file, active); err != nil || !on {
		t.Fatalf("on = %v, %v, want the onDisk of mount %s, the one the file is on", on, err, id)
	}
	if _, err := place(filepath.Join(t.TempDir(), "gone"), active); !errors.Is(err, ErrUnplaceable) {
		t.Fatalf("err = %v, want ErrUnplaceable for a swap file that cannot be opened", err)
	}
	// Another file at the same path, say under a mount over the real one's
	// directory, is not the active swap.
	for _, claimed := range []int64{100 * active, active - page/1024} {
		if _, err := place(file, claimed); !errors.Is(err, ErrUnplaceable) {
			t.Fatalf("err = %v for %d KiB, want ErrUnplaceable when the file is not the size of the active swap", err, claimed)
		}
	}
}

func TestSwapOffOrderKeepsTheKernelsPriorities(t *testing.T) {
	// Undo runs in reverse: the highest priority goes back on first, and
	// the kernel hands out falling negative priorities in that order.
	got := offOrder([]Swap{{Path: "a", Prio: -2}, {Path: "b", Prio: 5}, {Path: "c", Prio: -4}, {Path: "d", Prio: -3}})
	var paths []string
	for _, s := range got {
		paths = append(paths, s.Path)
	}
	if want := []string{"c", "d", "a", "b"}; !slices.Equal(paths, want) {
		t.Fatalf("order = %v, want %v", paths, want)
	}
}

func TestRunSaysWhichStepItIsWaitingOn(t *testing.T) {
	orig := watchInterval
	t.Cleanup(func() { watchInterval = orig })
	watchInterval = 20 * time.Millisecond
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// A freeze waits for writers to finish, and one stuck in I/O never
	// does; past the point of no return nothing else would say so.
	slow := Step{Name: "freeze /srv", Do: func() (func() error, error) {
		time.Sleep(100 * time.Millisecond)
		return func() error { return nil }, nil
	}}
	if _, err := Run([]Step{slow}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "still waiting on freeze /srv") {
		t.Fatalf("log = %q, want a line naming the step it waits on", out.String())
	}
}

func TestRemountUndoKeepsAReadOnlyMountPoint(t *testing.T) {
	// The superblock goes back to read-write; a mount point that was itself
	// read-only stays so, through a bind remount of its own.
	sb, bindRO := remountUndo(unix.ST_RDONLY | unix.ST_NOSUID)
	if sb&unix.MS_RDONLY != 0 || sb&unix.MS_NOSUID == 0 || !bindRO {
		t.Fatalf("sb = %#x, bindRO = %v, want rw superblock keeping nosuid, and the point back to ro", sb, bindRO)
	}
	if _, bindRO := remountUndo(unix.ST_NOSUID); bindRO {
		t.Fatal("a read-write mount point must not be made read-only")
	}
}

func TestSyncOthersSaysWhenItFlushesNothing(t *testing.T) {
	orig := mountinfoPath
	t.Cleanup(func() { mountinfoPath = orig })
	mountinfoPath = filepath.Join(t.TempDir(), "missing")
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	SyncOthers("vda", time.Second)
	if !strings.Contains(out.String(), "flush") {
		t.Fatalf("log = %q: when the other disks cannot be flushed, the user must be told", out.String())
	}
}

// dmStatus builds a DM_TABLE_STATUS reply the way the kernel lays it out:
// the header, then each target spec and its parameters, next counted from
// the start of the data area.
func dmStatus(t *testing.T, targets ...string) []byte {
	t.Helper()
	hdr := unix.DmIoctl{Data_start: uint32(unsafe.Sizeof(unix.DmIoctl{})), Target_count: uint32(len(targets))}
	specSize := int(unsafe.Sizeof(unix.DmTargetSpec{}))
	data := make([]byte, 0, 256)
	for i, typ := range targets {
		var spec unix.DmTargetSpec
		copy(spec.Target_type[:], typ)
		params := []byte("8:16 0\x00\x00")
		if i < len(targets)-1 {
			spec.Next = uint32(len(data) + specSize + len(params))
		}
		data = append(data, unsafe.Slice((*byte)(unsafe.Pointer(&spec)), specSize)...)
		data = append(data, params...)
	}
	buf := append(unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), int(hdr.Data_start)), data...)
	return buf
}

func TestParseDmTargets(t *testing.T) {
	got, err := parseDmTargets(dmStatus(t, "linear", "cache", "linear"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"linear", "cache", "linear"}; !slices.Equal(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if _, err := parseDmTargets(dmStatus(t, "linear")[:10]); err == nil {
		t.Fatal("a reply shorter than its header must not parse")
	}
	cut := dmStatus(t, "linear")
	if _, err := parseDmTargets(cut[:int(unsafe.Sizeof(unix.DmIoctl{}))+8]); err == nil {
		t.Fatal("a reply that ends inside a target spec must not parse")
	}
}

func TestDmTargetsReadsTheKernelTable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a device-mapper device")
	}
	dmsetup, err := exec.LookPath("dmsetup")
	if err != nil {
		t.Skip("needs dmsetup to set the test device up")
	}
	// A linear mapping of its own over a loop device on a temporary file:
	// nothing of the host is touched.
	img := filepath.Join(t.TempDir(), "dm.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 8<<20); err != nil {
		t.Fatal(err)
	}
	loopDev, err := exec.CommandContext(t.Context(), "losetup", "--find", "--show", img).Output()
	if err != nil {
		t.Fatal(err)
	}
	ldev := strings.TrimSpace(string(loopDev))
	t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "losetup", "--detach", ldev).Run() })
	name := fmt.Sprintf("btk-test-%d", os.Getpid())
	if out, err := exec.CommandContext(t.Context(), dmsetup, "create", name, "--table", "0 16384 linear "+ldev+" 0").CombinedOutput(); err != nil {
		t.Fatalf("dmsetup create: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.CommandContext(context.Background(), dmsetup, "remove", name).Run() })
	kname, err := filepath.EvalSymlinks("/dev/mapper/" + name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := dmTargets(filepath.Base(kname))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"linear"}) {
		t.Fatalf("targets = %v, want [linear]", got)
	}
}

func TestOffDiskGroupsKeepEveryMountPoint(t *testing.T) {
	// Each filesystem with every point it is mounted at, so the flush can
	// open the one that really leads to it.
	mi := mountinfo + "61 22 253:16 / /srv/other rw - ext4 /dev/vdb rw\n"
	mounts, err := readMounts(strings.NewReader(mi), fakeSysfs(t), "vda", noDevOf)
	if err != nil {
		t.Fatal(err)
	}
	var vdb []string
	for _, g := range offDiskGroups(mounts) {
		if g[0].dev == "253:16" {
			for _, m := range g {
				vdb = append(vdb, m.point)
			}
		}
	}
	if want := []string{"/mnt/other", "/srv/other"}; !slices.Equal(vdb, want) {
		t.Fatalf("vdb points = %v, want %v", vdb, want)
	}
}

func TestDmTableRequestAsksForSecureData(t *testing.T) {
	// A dm-crypt table carries its key unless it sits in the keyring; with
	// DM_SECURE_DATA_FLAG the kernel wipes its own copy of the reply.
	words := make([]uint64, 2048)
	hdr := dmTableRequest(words, 252, 1)
	if hdr.Flags&unix.DM_SECURE_DATA_FLAG == 0 || hdr.Flags&unix.DM_STATUS_TABLE_FLAG == 0 {
		t.Fatalf("flags = %#x, want the table, as secure data", hdr.Flags)
	}
	if hdr.Dev != unix.Mkdev(252, 1) || hdr.Data_size != uint32(len(words)*8) {
		t.Fatalf("dev = %#x, size = %d", hdr.Dev, hdr.Data_size)
	}
}

func TestDmTargetsFromWipesTheReply(t *testing.T) {
	reply := dmStatus(t, "crypt")
	copy(reply[len(reply)-4:], "KEY!")
	got, err := dmTargetsFrom(reply)
	if err != nil || !slices.Equal(got, []string{"crypt"}) {
		t.Fatalf("targets = %v, %v", got, err)
	}
	for i, b := range reply {
		if b != 0 {
			t.Fatalf("byte %d of the reply is %#x after parsing: a crypt key would stay in memory", i, b)
		}
	}
}
