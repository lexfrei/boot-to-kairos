//go:build linux

package kairos

import (
	"fmt"

	"github.com/cockroachdb/errors"
)

// The firmware modes kairos-agent installs for, spelled as it does.
const (
	EFI  = "efi"
	BIOS = "bios"
)

// CheckFirmware refuses an install.firmware in cfg other than host. The
// agent takes the mode from it over the one it detects, and a disk laid
// out for the other mode does not boot.
func CheckFirmware(cfg []byte, host string) error {
	_, install, err := parseConfig(cfg)
	if err != nil {
		return err
	}
	if v := install["firmware"]; v != nil && fmt.Sprint(v) != host {
		return errors.Newf("the cloud-config sets install.firmware to %v, but this machine booted in %s mode", v, host)
	}
	return nil
}
