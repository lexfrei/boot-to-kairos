//go:build linux

package install

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/efiboot"
	"github.com/lexfrei/boot-to-kairos/internal/kairos"
	"github.com/lexfrei/boot-to-kairos/internal/secureboot"
)

// ErrSecureBoot means Secure Boot is on and the firmware would not boot the
// installed system, or its keys cannot be read to tell.
var ErrSecureBoot = secureboot.ErrUntrusted

// legacyEFIVars is the sysfs interface to EFI variables of kernels before 6.0.
const legacyEFIVars = "/sys/firmware/efi/vars"

// secureBoot is what the firmware says about Secure Boot. check is set when
// it is on.
type secureBoot struct {
	firmware string
	state    secureboot.State
	unknown  error
	// unchecked says why the keys could not be read with Secure Boot on.
	unchecked error
	check     func(secureboot.Chain) (string, error)
}

// readSecureBoot reads the state, and the keys when it is on, from the
// installer's own view of /sys: the build's sandbox hides the EFI variables.
func readSecureBoot(firmware, efivars, legacy string, isEfivarfs func(string) bool) (*secureBoot, error) {
	sb := &secureBoot{firmware: firmware}
	if firmware == kairos.BIOS {
		return sb, nil
	}
	vars, err := secureboot.OpenVars(efivars, legacy, isEfivarfs)
	if err == nil {
		sb.state, err = secureboot.ReadState(vars)
	}
	sb.unknown = err
	switch sb.state {
	case secureboot.Unknown:
		log.Printf("warning: this machine booted through UEFI, not legacy BIOS, but whether Secure Boot is on cannot be told: %v. If it is on, the installed system boots only if the image's shim, GRUB and kernel are signed by keys this firmware trusts", sb.unknown)
	case secureboot.On:
		keys, err := secureboot.ReadKeys(vars)
		if errors.Is(err, secureboot.ErrUnreadable) && vars.Legacy() {
			log.Printf("warning: Secure Boot is on, but its keys cannot be read from %s: %v. That interface hands out at most 1024 bytes of a variable, which db and dbx usually exceed; "+
				"mount efivarfs on %s to have the image's boot chain checked. Going ahead without the check", legacy, err, efivars)
			sb.unchecked = err
			return sb, nil
		}
		if err != nil {
			return sb, errors.Mark(errors.Wrap(err, "Secure Boot is on, and its keys cannot be read to check the image's boot chain"), ErrSecureBoot)
		}
		if keys.Skipped > 0 {
			log.Printf("warning: %d certificates in db or MokListRT cannot be parsed and are not counted as trusted", keys.Skipped)
		}
		sb.check = keys.Check
	case secureboot.Off:
	}
	return sb, nil
}

// checkSecureBoot puts the state in the plan and, when Secure Boot is on,
// refuses a boot chain the firmware would not load: the machine reboots on
// its own, into firmware that then refuses the disk until someone turns
// Secure Boot off in its setup.
func checkSecureBoot(sb *secureBoot, read func() (secureboot.Chain, error), plan *Plan) error {
	switch {
	case sb.firmware == kairos.BIOS:
		plan.Add("Secure Boot", "off: legacy BIOS")
	case sb.state == secureboot.Off:
		plan.Add("Secure Boot", "off")
	case sb.state == secureboot.Unknown:
		plan.Add("Secure Boot", "unknown: "+sb.unknown.Error())
	case sb.unchecked != nil:
		plan.Add("Secure Boot", "on; not checked: "+sb.unchecked.Error())
	default:
		chain, err := read()
		if err != nil {
			return errors.Wrap(err, "read the installed boot chain for Secure Boot")
		}
		summary, err := sb.check(chain)
		if err != nil {
			return errors.Mark(errors.Newf("Secure Boot is on, and the firmware would not boot the installed system: %v. "+
				"Turn Secure Boot off in the firmware setup, or install an image whose shim, GRUB and kernel are signed by keys this firmware trusts", err), ErrSecureBoot)
		}
		plan.Add("Secure Boot", "on; "+summary)
	}
	return nil
}

// readChain reads what the firmware would load from the image on dev: the
// fallback loader and the GRUB beside it from the ESP, mounted read-only on
// mnt for the time, and the kernel from the image tree at root, which the
// active system is made of.
func readChain(dev string, sector int, root, mnt string) (secureboot.Chain, error) {
	var c secureboot.Chain
	num, err := efiboot.ESPNumber(dev, sector)
	if err != nil {
		return c, err
	}
	loader, err := efiboot.LoaderPath(runtime.GOARCH)
	if err != nil {
		return c, err
	}
	rel := strings.ReplaceAll(strings.TrimPrefix(loader, `\`), `\`, "/")
	c.Loader = path.Base(rel)
	c.Grub = grubName(c.Loader)
	if err := os.Mkdir(mnt, 0o700); err != nil {
		return c, errors.Wrap(err, "create the ESP mount point")
	}
	defer os.Remove(mnt)
	part := fmt.Sprintf("%sp%d", dev, num)
	if err := unix.Mount(part, mnt, "vfat", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return c, errors.Wrapf(err, "mount the image's ESP %s", part)
	}
	defer func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) }()
	if c.LoaderPE, err = os.ReadFile(filepath.Join(mnt, rel)); err != nil {
		return c, errors.Wrap(err, "read the image's UEFI loader")
	}
	if c.GrubPE, err = absentIsNil(os.ReadFile(filepath.Join(mnt, path.Dir(rel), c.Grub))); err != nil {
		return c, errors.Wrap(err, "read the image's GRUB")
	}
	if c.KernelPE, err = absentIsNil(readInRoot(root, "boot/vmlinuz")); err != nil {
		return c, errors.Wrap(err, "read the image's kernel")
	}
	return c, nil
}

func absentIsNil(b []byte, err error) ([]byte, error) {
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// readInRoot reads name with every symlink resolved inside root, as a
// chroot would: /boot/vmlinuz in the image is an absolute link, which a
// plain open would follow to the host's own kernel. Resolved by hand rather
// than with openat2(RESOLVE_IN_ROOT), which kernels before 5.6 lack.
func readInRoot(root, name string) ([]byte, error) {
	var cur []string
	pending := strings.Split(name, "/")
	for links := 0; len(pending) > 0; {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}
		next := append(slices.Clip(cur), c)
		p := filepath.Join(append([]string{root}, next...)...)
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		links++
		// The kernel gives up after 40 links too.
		if links > 40 {
			return nil, &os.PathError{Op: "resolve", Path: filepath.Join(root, name), Err: unix.ELOOP}
		}
		target, err := os.Readlink(p)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(target, "/") {
			cur = nil
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return os.ReadFile(filepath.Join(append([]string{root}, cur...)...))
}

// grubName is the file shim loads beside BOOT<ARCH>.EFI: grub<arch>.efi.
func grubName(loader string) string {
	return "grub" + strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(loader, "BOOT"), ".EFI")) + ".efi"
}

func isEfivarfs(dir string) bool {
	var st unix.Statfs_t
	return unix.Statfs(dir, &st) == nil && uint32(st.Type) == unix.EFIVARFS_MAGIC
}
