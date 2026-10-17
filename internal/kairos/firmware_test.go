//go:build linux

package kairos

import "testing"

// The agent picks EFI or BIOS from /sys/firmware/efi, which the sandbox
// shows as the host has it, unless install.firmware says otherwise; a
// mode the machine did not boot in leaves it unbootable.
func TestCheckFirmware(t *testing.T) {
	for _, tc := range []struct {
		name, cfg, host string
		ok              bool
	}{
		{name: "unset", cfg: "#cloud-config\n", host: BIOS, ok: true},
		{name: "null", cfg: "#cloud-config\ninstall: {firmware: null}\n", host: BIOS, ok: true},
		{name: "same", cfg: "#cloud-config\ninstall: {firmware: bios}\n", host: BIOS, ok: true},
		{name: "other", cfg: "#cloud-config\ninstall: {firmware: efi}\n", host: BIOS},
		{name: "other on EFI", cfg: "#cloud-config\ninstall: {firmware: bios}\n", host: EFI},
		{name: "mixed case key", cfg: "#cloud-config\nInstall: {Firmware: efi}\n", host: BIOS},
		{name: "value in another case", cfg: "#cloud-config\ninstall: {firmware: BIOS}\n", host: BIOS},
		{name: "not YAML", cfg: "#cloud-config\ninstall: [", host: BIOS},
		{name: "dotted at the top", cfg: "#cloud-config\ninstall.firmware: bios\n", host: BIOS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFirmware([]byte(tc.cfg), tc.host)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok = %v", err, tc.ok)
			}
		})
	}
}
