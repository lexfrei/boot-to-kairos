//go:build linux

package quiesce

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workDirSysfs adds to the fake sysfs a loop device over a file, a loop
// device over vdb, an nbd device, an iSCSI disk and a dm device on the
// file-backed loop device.
func workDirSysfs(t *testing.T) string {
	t.Helper()
	sys := fakeSysfs(t)
	mk := func(rel string) string {
		p := filepath.Join(sys, rel)
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
	for name, backing := range map[string]string{"loop0": "/srv/data.img", "loop1": "/dev/vdb", "loop2": "/dev/nbd0"} {
		dev := mk("devices/virtual/block/" + name)
		mk("devices/virtual/block/" + name + "/loop")
		if err := os.WriteFile(filepath.Join(dev, "loop/backing_file"), []byte(backing+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		link(dev, filepath.Join(sys, "class/block", name))
	}
	link(filepath.Join(sys, "devices/virtual/block/loop0"), filepath.Join(sys, "dev/block/7:0"))
	link(filepath.Join(sys, "devices/virtual/block/loop1"), filepath.Join(sys, "dev/block/7:1"))
	link(filepath.Join(sys, "devices/virtual/block/loop2"), filepath.Join(sys, "dev/block/7:2"))
	part := mk("devices/virtual/block/loop0/loop0p1")
	if err := os.WriteFile(filepath.Join(part, "partition"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link(part, filepath.Join(sys, "dev/block/259:0"))
	// The btrfs filesystem of mount 38 spans vdb and the file-backed loop
	// device; mountinfo names only vdb.
	devs := mk("fs/btrfs/5d1c-uuid/devices")
	link(filepath.Join(sys, "devices/pci0000:00/virtio2/block/vdb"), filepath.Join(devs, "vdb"))
	link(filepath.Join(sys, "devices/virtual/block/loop0"), filepath.Join(devs, "loop0"))
	nbd := mk("devices/virtual/block/nbd0")
	link(nbd, filepath.Join(sys, "class/block/nbd0"))
	link(nbd, filepath.Join(sys, "dev/block/43:0"))
	sdb := mk("devices/platform/host3/session1/target3:0:0/3:0:0:0/block/sdb")
	link(sdb, filepath.Join(sys, "class/block/sdb"))
	link(sdb, filepath.Join(sys, "dev/block/8:16"))
	write := func(rel, body string) {
		if err := os.WriteFile(filepath.Join(sys, rel), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// NVMe: a PCIe namespace with a partition, one over TCP, and a native
	// multipath head whose second path is over TCP.
	pcie := mk("devices/pci0000:00/0000:00:04.0/nvme/nvme0/nvme0n1")
	write("devices/pci0000:00/0000:00:04.0/nvme/nvme0/transport", "pcie")
	pciePart := mk("devices/pci0000:00/0000:00:04.0/nvme/nvme0/nvme0n1/nvme0n1p1")
	write("devices/pci0000:00/0000:00:04.0/nvme/nvme0/nvme0n1/nvme0n1p1/partition", "1")
	tcp := mk("devices/virtual/nvme-fabrics/ctl/nvme1/nvme1n1")
	write("devices/virtual/nvme-fabrics/ctl/nvme1/transport", "tcp")
	head := mk("devices/virtual/nvme-subsystem/nvme-subsys2/nvme2n1")
	for ctrl, transport := range map[string]string{"nvme2": "pcie", "nvme3": "tcp"} {
		mk("devices/virtual/nvme-subsystem/nvme-subsys2/" + ctrl)
		write("devices/virtual/nvme-subsystem/nvme-subsys2/"+ctrl+"/transport", transport)
	}
	// A multipath head with PCIe paths only, and a namespace whose
	// transport cannot be read.
	allPCIe := mk("devices/virtual/nvme-subsystem/nvme-subsys5/nvme5n1")
	mk("devices/virtual/nvme-subsystem/nvme-subsys5/nvme5")
	write("devices/virtual/nvme-subsystem/nvme-subsys5/nvme5/transport", "pcie")
	unknown := mk("devices/virtual/nvme-subsystem/nvme-subsys6/nvme6n1")
	aoe := mk("devices/virtual/block/etherd!e0.1")
	drbd := mk("devices/virtual/block/drbd0")
	for majmin, d := range map[string]string{"259:1": pcie, "259:2": pciePart, "259:3": tcp, "259:4": head, "152:16": aoe, "147:0": drbd, "259:5": allPCIe, "259:6": unknown} {
		link(d, filepath.Join(sys, "dev/block", majmin))
	}
	dm := mk("devices/virtual/block/dm-1")
	link(filepath.Join(sys, "devices/virtual/block/loop0"), filepath.Join(dm, "slaves/loop0"))
	link(dm, filepath.Join(sys, "class/block/dm-1"))
	link(dm, filepath.Join(sys, "dev/block/252:1"))
	return sys
}

//nolint:dupword // mountinfo spells fstype and source alike for some of these
const workDirMountinfo = `22 1 253:1 / / rw - ext4 /dev/vda1 rw
25 22 252:0 / /var/lib/data rw - xfs /dev/mapper/vg-data rw
26 22 253:16 / /mnt/other rw - ext4 /dev/vdb rw
27 22 253:1 /srv /srv rw - ext4 /dev/vda1 rw
30 22 0:40 / /mnt/nfs rw - nfs4 server:/export rw
31 22 0:41 / /mnt/sshfs rw - fuse.sshfs host:/ rw
32 22 0:21 / /run rw - tmpfs tmpfs rw
33 22 7:0 / /mnt/fileloop rw - ext4 /dev/loop0 rw
34 22 7:1 / /mnt/devloop rw - ext4 /dev/loop1 rw
35 22 43:0 / /mnt/nbd rw - ext4 /dev/nbd0 rw
36 22 8:16 / /mnt/iscsi rw - ext4 /dev/sdb rw
37 22 252:1 / /mnt/crypt rw - ext4 /dev/mapper/crypt rw
38 22 0:42 / /mnt/btrfs rw - btrfs /dev/vdb rw
39 22 0:43 / /mnt/overlay rw - overlay overlay rw
40 22 7:2 / /mnt/nbdloop rw - ext4 /dev/loop2 rw
43 22 8:16 / /mnt/ntfs rw - fuseblk /dev/sdb rw
44 22 253:16 / /mnt/fusedev rw - fuse /dev/vdb rw
45 22 259:2 / /mnt/nvme rw - ext4 /dev/nvme0n1p1 rw
46 22 259:3 / /mnt/nvmetcp rw - ext4 /dev/nvme1n1 rw
47 22 259:4 / /mnt/nvmemp rw - ext4 /dev/nvme2n1 rw
48 22 152:16 / /mnt/aoe rw - ext4 /dev/etherd/e0.1 rw
49 22 147:0 / /mnt/drbd rw - ext4 /dev/drbd0 rw
50 22 259:5 / /mnt/nvmepcie rw - ext4 /dev/nvme5n1 rw
51 22 259:6 / /mnt/nvmeunknown rw - ext4 /dev/nvme6n1 rw
41 22 259:0 / /mnt/looppart rw - ext4 /dev/loop0p1 rw
`

func TestWorkDirUnfit(t *testing.T) {
	sys := workDirSysfs(t)
	devOf := func(path string) (string, error) {
		switch path {
		case "/dev/vdb":
			return "253:16", nil
		}
		return "", os.ErrNotExist
	}
	for id, want := range map[string]string{
		"26": "",
		"34": "",
		"38": "backed by a file",
		"40": "network block device",
		"43": "FUSE",
		"44": "FUSE",
		"45": "",
		"46": "network block device",
		"47": "network block device",
		"48": "network block device",
		"49": "network block device",
		"50": "",
		"51": "network block device",
		"41": "backed by a file",
		"22": "on vda",
		"25": "on vda",
		"27": "on vda",
		"30": "not on a local block device",
		"31": "FUSE",
		"32": "not on a local block device",
		"39": "not on a local block device",
		"33": "backed by a file",
		"37": "backed by a file",
		"35": "network block device",
		"36": "network block device",
	} {
		t.Run(id, func(t *testing.T) {
			why, err := WorkDirUnfit(strings.NewReader(workDirMountinfo), sys, "/dev/vda", id, devOf)
			if err != nil {
				t.Fatal(err)
			}
			if want == "" && why != "" || !strings.Contains(why, want) {
				t.Fatalf("WorkDirUnfit(mount %s) = %q, want %q", id, why, want)
			}
		})
	}
}

func TestWorkDirUnfitPlacesBtrfsByEveryDevice(t *testing.T) {
	sys := btrfsSysfs(t)
	mi := "40 1 0:40 / /mnt/pool rw - btrfs /dev/vdb rw\n"
	devOf := func(string) (string, error) { return "253:16", nil }
	why, err := WorkDirUnfit(strings.NewReader(mi), sys, "vda", "40", devOf)
	if err != nil || !strings.Contains(why, "on vda") {
		t.Fatalf("WorkDirUnfit = %q, %v: a btrfs filesystem with a member on the disk is on the disk", why, err)
	}
}

func TestWorkDirUnfitTakesABtrfsFilesystemOffTheDisk(t *testing.T) {
	mi := "38 1 0:42 / /mnt/btrfs rw - btrfs /dev/vdb rw\n"
	devOf := func(string) (string, error) { return "253:16", nil }
	why, err := WorkDirUnfit(strings.NewReader(mi), fakeSysfs(t), "vda", "38", devOf)
	if err != nil || why != "" {
		t.Fatalf("WorkDirUnfit = %q, %v, want a btrfs filesystem on vdb alone taken", why, err)
	}
}

func TestWorkDirUnfitCannotPlace(t *testing.T) {
	for name, c := range map[string]struct{ mi, id string }{
		"no such mount": {"22 1 253:1 / / rw - ext4 /dev/vda1 rw\n", "99"},
		"zfs anywhere":  {"22 1 253:16 / /mnt rw - ext4 /dev/vdb rw\n30 1 0:50 / /tank rw - zfs tank/data rw\n", "22"},
		"btrfs gone":    {"40 1 0:40 / /mnt rw - btrfs /dev/gone rw\n", "40"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := WorkDirUnfit(strings.NewReader(c.mi), fakeSysfs(t), "vda", c.id, noDevOf)
			if !errors.Is(err, ErrUnplaceable) {
				t.Fatalf("err = %v, want ErrUnplaceable", err)
			}
		})
	}
}

func TestMountIDOf(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	id, err := MountIDOf(f)
	if err != nil || id == "" {
		t.Fatalf("MountIDOf = %q, %v", id, err)
	}
}
