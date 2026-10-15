//go:build linux

// Package loop attaches a disk image as a partition-scanned loop device.
package loop

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

// Device is an attached loop device. It stays attached while it is open.
type Device struct {
	Path string
	f    *os.File
}

// Attach binds path to a free loop device with partition scanning, so the
// kernel creates <dev>p1, <dev>p2... for whatever partition table it gets.
// sectorSize must be the logical sector size of the disk the image is meant
// for: GPT and filesystems record offsets in sectors, so a table built on a
// 512-byte loop device is unreadable on a 4Kn disk.
func Attach(path string, sectorSize int) (*Device, error) {
	backing, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Wrap(err, "open backing file")
	}
	defer backing.Close()
	ctrl, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Wrap(err, "open loop-control")
	}
	defer ctrl.Close()

	// Another process can take the free device between the two ioctls.
	for range 5 {
		n, err := unix.IoctlRetInt(int(ctrl.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return nil, errors.Wrap(err, "LOOP_CTL_GET_FREE")
		}
		dev := fmt.Sprintf("/dev/loop%d", n)
		f, err := os.OpenFile(dev, os.O_RDWR, 0)
		if err != nil {
			return nil, errors.Wrapf(err, "open %s", dev)
		}
		if err := unix.IoctlSetInt(int(f.Fd()), unix.LOOP_SET_FD, int(backing.Fd())); err != nil {
			f.Close()
			if errors.Is(err, unix.EBUSY) {
				continue
			}
			return nil, errors.Wrap(err, "LOOP_SET_FD")
		}
		info := unix.LoopInfo64{Flags: unix.LO_FLAGS_PARTSCAN | unix.LO_FLAGS_AUTOCLEAR}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.LOOP_SET_STATUS64, uintptr(unsafe.Pointer(&info))); errno != 0 {
			_ = unix.IoctlSetInt(int(f.Fd()), unix.LOOP_CLR_FD, 0)
			f.Close()
			return nil, errors.Wrap(errno, "LOOP_SET_STATUS64")
		}
		if err := unix.IoctlSetInt(int(f.Fd()), unix.LOOP_SET_BLOCK_SIZE, sectorSize); err != nil {
			_ = unix.IoctlSetInt(int(f.Fd()), unix.LOOP_CLR_FD, 0)
			f.Close()
			return nil, errors.Wrapf(err, "LOOP_SET_BLOCK_SIZE %d", sectorSize)
		}
		return &Device{Path: dev, f: f}, nil
	}
	return nil, errors.New("no free loop device after retries")
}

// Detach flushes the loop device into its backing file and waits until the
// kernel has really released it: LOOP_CLR_FD only marks the device for
// release while anyone else (udev probing the partitions) still has it open.
func (d *Device) Detach() error {
	if d.f == nil {
		return nil
	}
	if err := d.f.Sync(); err != nil {
		return errors.Wrap(err, "flush loop device")
	}
	err := unix.IoctlSetInt(int(d.f.Fd()), unix.LOOP_CLR_FD, 0)
	cerr := d.f.Close()
	d.f = nil
	if err != nil && !errors.Is(err, unix.ENXIO) {
		return errors.Wrap(err, "LOOP_CLR_FD")
	}
	if cerr != nil {
		return errors.Wrap(cerr, "close loop device")
	}
	backing := filepath.Join("/sys/block", filepath.Base(d.Path), "loop/backing_file")
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(backing); os.IsNotExist(err) {
			return nil
		}
	}
	return errors.Newf("%s was not released within 30s", d.Path)
}
