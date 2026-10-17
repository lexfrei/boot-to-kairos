//go:build linux

package quiesce

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
)

// WorkDirUnfit says why the filesystem of the mount with id mountID cannot
// hold the disk image while it is written over disk, or returns "". After
// the quiesce the image is read from it, so it must be off the disk and
// readable without the network, a userspace daemon or a file that may live
// on the disk, any of which can stall or tear the write half way.
func WorkDirUnfit(mountinfo io.Reader, sysfs, disk, mountID string, devOf func(string) (string, error)) (string, error) {
	mounts, err := readMounts(mountinfo, sysfs, disk, devOf)
	if err != nil {
		return "", err
	}
	i := -1
	for n := range mounts {
		if mounts[n].id == mountID {
			i = n
		}
	}
	if i < 0 {
		return "", errors.Wrapf(ErrUnplaceable, "mount %s is not listed", mountID)
	}
	m := mounts[i]
	if m.onDisk {
		return "it is on " + DiskName(disk), nil
	}
	// fuseblk carries the major:minor of the device its daemon reads.
	if m.fstype == "fuse" || m.fstype == "fuseblk" || strings.HasPrefix(m.fstype, "fuse.") {
		return "it is served by a FUSE daemon (" + m.fstype + ")", nil
	}
	var links []string
	switch {
	case !strings.HasPrefix(m.dev, "0:"):
		links = []string{filepath.Join(sysfs, "dev/block", m.dev)}
	case strings.HasPrefix(m.source, "/dev/"):
		dev, err := devOf(m.source)
		if err != nil {
			return "", errors.Wrapf(ErrUnplaceable, "%s: %v", m.source, err)
		}
		links = fsDevices(sysfs, filepath.Join(sysfs, "dev/block", dev))
	default:
		return "it is not on a local block device but on " + m.fstype, nil
	}
	for _, l := range links {
		if why := stackUnfit(sysfs, l, 0); why != "" {
			return why, nil
		}
	}
	return "", nil
}

// stackUnfit walks the devices under the sysfs block device at link the
// way onDisk does, looking for one the image cannot be read from safely.
func stackUnfit(sysfs, link string, level int) string {
	if level > 8 {
		return "its devices are stacked too deep to check"
	}
	dev, err := filepath.EvalSymlinks(link)
	if err != nil {
		return "cannot tell what device " + filepath.Base(link) + " is"
	}
	name := filepath.Base(dev)
	if networked(dev) {
		return "it is on " + name + ", a network block device"
	}
	if b, err := os.ReadFile(filepath.Join(dev, "loop/backing_file")); err == nil {
		backing := strings.TrimSpace(string(b))
		// The path is as the process that attached it saw it, so the file
		// cannot be placed.
		if !strings.HasPrefix(backing, "/dev/") {
			return "it is on " + name + ", a loop device backed by a file"
		}
		if resolved, err := filepath.EvalSymlinks(backing); err == nil {
			backing = resolved
		}
		return stackUnfit(sysfs, filepath.Join(sysfs, "class/block", filepath.Base(backing)), level+1)
	}
	slaves, err := os.ReadDir(filepath.Join(dev, "slaves"))
	if err != nil {
		if _, perr := os.Stat(filepath.Join(dev, "partition")); perr == nil {
			return stackUnfit(sysfs, filepath.Dir(dev), level+1)
		}
		return ""
	}
	for _, s := range slaves {
		if why := stackUnfit(sysfs, filepath.Join(sysfs, "class/block", s.Name()), level+1); why != "" {
			return why
		}
	}
	return ""
}

// networked reports whether reads of the sysfs block device dev may go over
// the network. iSCSI disks sit under the session that carries them; DRBD
// may read from its peer.
func networked(dev string) bool {
	name := filepath.Base(dev)
	for _, p := range []string{"nbd", "rbd", "etherd", "drbd"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	if strings.Contains(dev, "/session") {
		return true
	}
	if !strings.HasPrefix(name, "nvme") {
		return false
	}
	if _, err := os.Stat(filepath.Join(dev, "partition")); err == nil {
		return false
	}
	// A namespace sits under its controller, or, with native multipath,
	// beside every controller of its subsystem.
	transports, _ := filepath.Glob(filepath.Join(filepath.Dir(dev), "transport"))
	more, _ := filepath.Glob(filepath.Join(filepath.Dir(dev), "nvme*", "transport"))
	transports = append(transports, more...)
	if len(transports) == 0 {
		return true
	}
	for _, t := range transports {
		b, err := os.ReadFile(t)
		if err != nil || strings.TrimSpace(string(b)) != "pcie" {
			return true
		}
	}
	return false
}

// MountIDOf returns the id of the mount f is on.
func MountIDOf(f *os.File) (string, error) { return mountID(f) }
