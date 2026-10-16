//go:build linux

// Package sandbox prepares a chroot of the Kairos image in which kairos-agent
// can partition and format a loop device, and takes it apart safely.
package sandbox

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

// SourceDir is where the clean, read-only copy of the image tree is bound.
// kairos-agent sizes its images by walking the install source, and a source
// that carries the proc/sys/dev mounts makes that walk fail. It lives on the
// sandbox's private /run tmpfs, which the non-recursive bind does not carry,
// so neither it nor anything else the installer puts there ends up in the
// installed system.
const SourceDir = "run/btk-src"

// ErrStillMounted reports mounts that survived Teardown. The tree must not be
// deleted then: the binds reach the host's /dev and /sys.
var ErrStillMounted = errors.New("mounts still present under the sandbox")

// Bind binds the host directory Src at Dst, relative to the sandbox root.
type Bind struct {
	Src string
	Dst string
}

// HostBinds are the host filesystems kairos-agent needs inside the sandbox.
// run/udev carries udevd's control socket, which `udevadm settle` talks to.
func HostBinds() []Bind {
	return []Bind{
		{Src: "/proc", Dst: "proc"},
		{Src: "/sys", Dst: "sys"},
		{Src: "/dev", Dst: "dev"},
		{Src: "/run/udev", Dst: "run/udev"},
	}
}

// MountsUnder returns the mount points strictly below root, deepest first and,
// at equal depth, most recently mounted first.
func MountsUnder(mountinfo io.Reader, root string) ([]string, error) {
	root = filepath.Clean(root)
	var out []string
	sc := bufio.NewScanner(mountinfo)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		mnt := unescape(f[4])
		if strings.HasPrefix(mnt, root+"/") {
			out = append(out, mnt)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, errors.Wrap(err, "read mountinfo")
	}
	slices.Reverse(out)
	sort.SliceStable(out, func(i, j int) bool { return strings.Count(out[i], "/") > strings.Count(out[j], "/") })
	return out, nil
}

// Setup recursively binds each existing Src at root/Dst, hides the EFI
// variables under the bound /sys and the kernel command line under the
// bound /proc, and adds a read-only, non-recursive bind of
// root itself at root/SourceDir.
func Setup(root string, binds []Bind) error {
	run := filepath.Join(root, "run")
	if err := os.MkdirAll(run, 0o755); err != nil {
		return errors.Wrap(err, "create run")
	}
	if err := unix.Mount("tmpfs", run, "tmpfs", 0, "mode=0755,size=64m"); err != nil {
		return errors.Wrap(err, "mount the sandbox's private run")
	}
	for _, b := range binds {
		src := b.Src
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(root, b.Dst)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return errors.Wrapf(err, "create %s", dst)
		}
		if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return errors.Wrapf(err, "bind %s", src)
		}
		// Unmounting inside the sandbox must never propagate to the host.
		if err := unix.Mount("", dst, "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
			return errors.Wrapf(err, "make %s a slave mount", dst)
		}
	}
	if err := hideEFIVars(root, unix.Mount); err != nil {
		return err
	}
	if err := hideCmdline(root, unix.Mount); err != nil {
		return err
	}
	src := filepath.Join(root, SourceDir)
	if err := os.MkdirAll(src, 0o755); err != nil {
		return errors.Wrapf(err, "create %s", src)
	}
	if err := unix.Mount(root, src, "", unix.MS_BIND, ""); err != nil {
		return errors.Wrap(err, "bind the image tree")
	}
	if err := unix.Mount("", src, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		return errors.Wrap(err, "make the image tree read-only")
	}
	return nil
}

// Teardown detaches every mount below root and fails if any survive.
func Teardown(root string) error {
	mounts, err := current(root)
	if err != nil {
		return err
	}
	for _, m := range mounts {
		// EINVAL: already gone with a parent's recursive detach.
		if err := unix.Unmount(m, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
			return errors.Wrapf(err, "unmount %s", m)
		}
	}
	left, err := current(root)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return errors.Wrapf(ErrStillMounted, "%v", left)
	}
	return nil
}

func current(root string) ([]string, error) {
	mi, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, errors.Wrap(err, "open mountinfo")
	}
	defer mi.Close()
	return MountsUnder(mi, root)
}

// unescape decodes the \ooo octal escapes the kernel uses in mountinfo.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// hideEFIVars covers the firmware's variables with an empty read-only tmpfs:
// efivarfs, and the sysfs interface kernels before 6.0 also offer, which
// libefivar falls back to. NVRAM must not change before the disk is written
// and verified, and the agent or a cloud-config stage could otherwise write
// a boot entry from the build. The mounts stay in the sandbox: its /sys is a
// slave of the host's. EFI mode itself stays visible.
func hideEFIVars(root string, mount func(string, string, string, uintptr, string) error) error {
	for _, d := range []string{"efivars", "vars"} {
		dir := filepath.Join(root, "sys/firmware/efi", d)
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return errors.Wrap(err, "check the EFI variables")
		}
		if err := mount("tmpfs", dir, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0555,size=4k"); err != nil {
			return errors.Wrapf(err, "hide %s from the build", dir)
		}
	}
	return nil
}

// hideCmdline covers the bound /proc/cmdline with an empty read-only file.
// kairos-agent merges install keys from it over the cloud-config, each
// token evaluated as a jq assignment, and runs the stages it names; on a
// host that is not Kairos nothing on it is meant for the agent. The file
// lives on the sandbox's private /run.
func hideCmdline(root string, mount func(string, string, string, uintptr, string) error) error {
	target := filepath.Join(root, "proc/cmdline")
	if _, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.Wrap(err, "check the kernel command line")
	}
	empty := filepath.Join(root, "run/btk-cmdline")
	if err := os.WriteFile(empty, nil, 0o444); err != nil {
		return errors.Wrap(err, "create the build's kernel command line")
	}
	if err := mount(empty, target, "", unix.MS_BIND, ""); err != nil {
		return errors.Wrap(err, "hide the kernel command line from the build")
	}
	if err := mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		return errors.Wrap(err, "make the build's kernel command line read-only")
	}
	return nil
}
