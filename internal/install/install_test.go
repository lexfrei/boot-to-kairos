//go:build linux

package install

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	cerrors "github.com/cockroachdb/errors"
	"github.com/lexfrei/boot-to-kairos/internal/efiboot"
	"github.com/lexfrei/boot-to-kairos/internal/flash"
	"github.com/lexfrei/boot-to-kairos/internal/kairos"
	"github.com/lexfrei/boot-to-kairos/internal/signature"
)

// fakeSys builds just enough of /sys for disk and firmware checks.
func fakeSys(t *testing.T, uefi bool) string {
	t.Helper()
	sys := t.TempDir()
	vda := filepath.Join(sys, "devices/virtio1/block/vda")
	if err := os.MkdirAll(filepath.Join(vda, "vda1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vda, "vda1/partition"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sys, "dev/block"), 0o755); err != nil {
		t.Fatal(err)
	}
	lv := filepath.Join(sys, "devices/virtual/block/dm-0")
	if err := os.MkdirAll(lv, 0o755); err != nil {
		t.Fatal(err)
	}
	for majmin, target := range map[string]string{"253:0": vda, "253:1": filepath.Join(vda, "vda1"), "252:0": lv} {
		if err := os.Symlink(target, filepath.Join(sys, "dev/block", majmin)); err != nil {
			t.Fatal(err)
		}
	}
	if uefi {
		if err := os.MkdirAll(filepath.Join(sys, "firmware/efi"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return sys
}

// fakeDevOf stands in for stat(2) on /dev: by-id links resolve to the disk,
// and a regular file is no block device.
func fakeDevOf(path string) (string, error) {
	m := map[string]string{"/dev/vda": "253:0", "/dev/disk/by-id/virtio-root": "253:0", "/dev/vda1": "253:1", "/dev/sdz": "8:0", "/dev/mapper/vg-root": "252:0"}
	if d, ok := m[path]; ok {
		return d, nil
	}
	return "", errNotBlockDevice
}

func config(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidate(t *testing.T) {
	good := config(t, "#cloud-config\nusers: []\n")
	base := Options{Image: "quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0", Disk: "/dev/vda", ConfigPath: good}

	cases := []struct {
		name string
		mod  func(*Options)
		uefi bool
		want error
	}{
		{name: "valid", mod: func(*Options) {}, uefi: true, want: nil},
		{name: "no image", mod: func(o *Options) { o.Image = "" }, uefi: true, want: ErrMissingImage},
		{name: "no disk", mod: func(o *Options) { o.Disk = "" }, uefi: true, want: ErrMissingDisk},
		{name: "no config", mod: func(o *Options) { o.ConfigPath = "" }, uefi: true, want: ErrMissingConfig},
		{name: "no config, identity carried", mod: func(o *Options) { o.ConfigPath, o.KeepIdentity = "", true }, uefi: true, want: nil},
		{name: "partition", mod: func(o *Options) { o.Disk = "/dev/vda1" }, uefi: true, want: ErrNotWholeDisk},
		{name: "unknown disk", mod: func(o *Options) { o.Disk = "/dev/sdz" }, uefi: true, want: ErrNotWholeDisk},
		{name: "regular file", mod: func(o *Options) { o.Disk = "/tmp/vda" }, uefi: true, want: ErrNotWholeDisk},
		{name: "logical volume", mod: func(o *Options) { o.Disk = "/dev/mapper/vg-root" }, uefi: true, want: ErrNotWholeDisk},
		{name: "by-id link", mod: func(o *Options) { o.Disk = "/dev/disk/by-id/virtio-root" }, uefi: true, want: nil},
		{name: "bad config", mod: func(o *Options) { o.ConfigPath = config(t, "users: []\n") }, uefi: true, want: ErrBadConfig},
		{name: "bios", mod: func(*Options) {}, uefi: false, want: nil},
		{name: "json output", mod: func(o *Options) { o.Output = OutputJSON }, uefi: true, want: nil},
		{name: "unknown output", mod: func(o *Options) { o.Output = "yaml" }, uefi: true, want: ErrBadOutput},
		{name: "own signer", mod: func(o *Options) {
			o.Signature = &SignatureOptions{Signer: signature.Policy{Identity: "^https://github\\.com/example/", Issuer: "https://example.com"}}
		}, uefi: true, want: nil},
		{name: "identity without issuer", mod: func(o *Options) {
			o.Signature = &SignatureOptions{Signer: signature.Policy{Identity: "^https://github\\.com/example/"}}
		}, uefi: true, want: ErrSignatureFlags},
		{name: "issuer without identity", mod: func(o *Options) {
			o.Signature = &SignatureOptions{Signer: signature.Policy{Issuer: "https://example.com"}}
		}, uefi: true, want: ErrSignatureFlags},
		{name: "identity not a regexp", mod: func(o *Options) {
			o.Signature = &SignatureOptions{Signer: signature.Policy{Identity: "(", Issuer: "https://example.com"}}
		}, uefi: true, want: ErrSignatureFlags},
		{name: "signer with verification off", mod: func(o *Options) {
			o.Signature, o.SkipSignature = &SignatureOptions{Signer: signature.Policy{Identity: "^https://github\\.com/example/", Issuer: "https://example.com"}}, true
		}, uefi: true, want: ErrSignatureFlags},
		{name: "trusted root alone", mod: func(o *Options) { o.Signature = &SignatureOptions{TrustedRoot: "/root.json"} }, uefi: true, want: nil},
		{name: "trusted root with verification off", mod: func(o *Options) { o.Signature, o.SkipSignature = &SignatureOptions{TrustedRoot: "/root.json"}, true }, uefi: true, want: ErrSignatureFlags},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mod(&o)
			_, err := Validate(&o, fakeSys(t, tc.uefi), fakeDevOf)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestFirmware(t *testing.T) {
	for uefi, want := range map[bool]string{true: kairos.EFI, false: kairos.BIOS} {
		if got, err := Firmware(fakeSys(t, uefi)); err != nil || got != want {
			t.Errorf("uefi %v: %q, %v, want %q", uefi, got, err, want)
		}
	}
	// Only a /sys/firmware/efi known to be absent means legacy BIOS.
	sys := t.TempDir()
	if err := os.WriteFile(filepath.Join(sys, "firmware"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Firmware(sys); err == nil {
		t.Fatalf("got %q from a firmware path that cannot be read", got)
	}
}

// SeaBIOS does not even list a disk with 4096-byte sectors, and legacy
// firmware commonly cannot read one either.
func TestCheckBootable(t *testing.T) {
	for _, tc := range []struct {
		firmware string
		sector   int
		ok       bool
	}{
		{kairos.BIOS, 512, true},
		{kairos.BIOS, 4096, false},
		{kairos.EFI, 4096, true},
		{kairos.EFI, 512, true},
	} {
		if err := checkBootable(tc.firmware, tc.sector); (err == nil) != tc.ok {
			t.Errorf("%s with %d-byte sectors: %v", tc.firmware, tc.sector, err)
		}
	}
}

func TestCheckFirmware(t *testing.T) {
	sectors := func(n int, err error) func(string) (int, error) {
		return func(string) (int, error) { return n, err }
	}
	plain := []byte("#cloud-config\n")
	for _, tc := range []struct {
		name   string
		cfg    []byte
		uefi   bool
		arch   string
		sector func(string) (int, error)
		want   error
	}{
		{name: "bios", cfg: plain, sector: sectors(512, nil)},
		// Without UEFI, an arm64 board booted its kernel from U-Boot or the
		// like: there is no legacy BIOS to install for.
		{name: "no UEFI on arm64", cfg: plain, arch: "arm64", sector: sectors(512, nil), want: ErrBIOSUnsupported},
		{name: "uefi on arm64", cfg: plain, uefi: true, arch: "arm64", sector: sectors(512, nil)},
		{name: "uefi with 4K sectors", cfg: plain, uefi: true, sector: sectors(4096, nil)},
		{name: "bios with 4K sectors", cfg: plain, sector: sectors(4096, nil), want: ErrBIOSUnsupported},
		{name: "bios told efi", cfg: []byte("#cloud-config\ninstall: {firmware: efi}\n"), sector: sectors(512, nil), want: ErrBadConfig},
		{name: "unknown sector size", cfg: plain, uefi: true, sector: sectors(512, errNotBlockDevice), want: errNotBlockDevice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch := tc.arch
			if arch == "" {
				arch = "amd64"
			}
			firmware, err := checkFirmware(tc.cfg, fakeSys(t, tc.uefi), arch, "/dev/vda", tc.sector)
			// errors.Mark is seen only by cockroachdb's Is, as errorClass uses.
			if !cerrors.Is(err, tc.want) || (tc.want == nil) != (err == nil) || (err != nil && firmware != "") {
				t.Fatalf("firmware %q, err = %v, want %v", firmware, err, tc.want)
			}
			if want := map[bool]string{true: kairos.EFI, false: kairos.BIOS}[tc.uefi]; err == nil && firmware != want {
				t.Fatalf("firmware %q, want %q", firmware, want)
			}
		})
	}
}

// Legacy BIOS boots the disk's boot sector and has no NVRAM entries: there
// is neither an entry to prepare nor a fallback to warn about.
func TestBootEntryOnBIOS(t *testing.T) {
	var logged strings.Builder
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	summary := &Plan{}
	plan, err := bootEntry(fakeSys(t, false), "/nonexistent/image.raw", "/nonexistent/disk", summary)
	var out strings.Builder
	summary.Print(&out)
	if plan != nil || err != nil || logged.Len() != 0 || !strings.Contains(out.String(), "legacy BIOS") {
		t.Fatalf("plan %v, err %v, logged %q, summary:\n%s", plan, err, logged.String(), out.String())
	}
	// An unreadable firmware path is not taken for legacy BIOS.
	sys := t.TempDir()
	if err := os.WriteFile(filepath.Join(sys, "firmware"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bootEntry(sys, "/nonexistent/image.raw", "/nonexistent/disk", &Plan{}); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("an unreadable firmware path gave %v", err)
	}
}

func TestValidateReturnsConfigContent(t *testing.T) {
	body := "#cloud-config\nhostname: test\n"
	cfg, err := Validate(&Options{Image: "x", Disk: "/dev/vda", ConfigPath: config(t, body)}, fakeSys(t, true), fakeDevOf)
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg) != body {
		t.Fatalf("config = %q", cfg)
	}
}

func TestValidateWithoutConfigStartsFromAnEmptyOne(t *testing.T) {
	cfg, err := Validate(&Options{Image: "x", Disk: "/dev/vda", KeepIdentity: true}, fakeSys(t, true), fakeDevOf)
	if err != nil || string(cfg) != "#cloud-config\n" {
		t.Fatalf("config = %q, %v", cfg, err)
	}
}

func TestValidateNamesTheDiskByItsKernelName(t *testing.T) {
	o := Options{Image: "x", Disk: "/dev/disk/by-id/virtio-root", ConfigPath: config(t, "#cloud-config\n")}
	if _, err := Validate(&o, fakeSys(t, true), fakeDevOf); err != nil {
		t.Fatal(err)
	}
	if o.Disk != "/dev/vda" {
		t.Fatalf("Disk = %q, want /dev/vda: mounts and swap are matched by the kernel name", o.Disk)
	}
}

func TestConfirmGivesUpOnCancel(t *testing.T) {
	r, w := io.Pipe() // a terminal nobody types into
	defer w.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan error, 1)
	go func() { done <- confirm(ctx, r, io.Discard, Options{Disk: "/dev/vda"}) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("confirm kept waiting for a line after Ctrl-C")
	}
}

func TestConfirmAcceptsTheDiskPath(t *testing.T) {
	if err := confirm(t.Context(), strings.NewReader("/dev/vda\n"), io.Discard, Options{Disk: "/dev/vda"}); err != nil {
		t.Fatal(err)
	}
	if err := confirm(t.Context(), strings.NewReader("yes\n"), io.Discard, Options{Disk: "/dev/vda"}); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}
}

// The firmware reads the ESP whether or not a boot entry can be written:
// without efivarfs it falls back to \EFI\BOOT on the same partition.
func TestBootEntryRefusesAnESPTheFirmwareCannotRead(t *testing.T) {
	const disk = "/dev/vda"
	var gotRaw string
	var gotSector int
	checkESP = func(raw string, sector int) error {
		gotRaw, gotSector = raw, sector
		return cerrors.Mark(cerrors.New("FAT32 with 8317 clusters"), efiboot.ErrESPUnreadable)
	}
	sectorSize = func(string) (int, error) { return 4096, nil }
	t.Cleanup(func() { checkESP, sectorSize = efiboot.CheckESP, flash.SectorSize })
	summary := &Plan{}
	plan, err := bootEntry(fakeSys(t, true), "/run/image.raw", disk, summary)
	if plan != nil || !cerrors.Is(err, efiboot.ErrESPUnreadable) || errorClass(err) != "bad-image" {
		t.Fatalf("bootEntry = %v, %v (class %s), want the refusal", plan, err, errorClass(err))
	}
	if gotRaw != "/run/image.raw" || gotSector != 4096 {
		t.Fatalf("checked %q with %d-byte sectors, want the image with the disk's", gotRaw, gotSector)
	}
	if !strings.Contains(err.Error(), "would not boot") || strings.Count(err.Error(), "EFI system partition") != 1 {
		t.Fatalf("the refusal does not say once what it prevents: %v", err)
	}
	// An image the check cannot read is not blamed on the firmware.
	checkESP = func(string, int) error { return cerrors.New("the image has no EFI system partition") }
	if _, err := bootEntry(fakeSys(t, true), "/run/image.raw", disk, &Plan{}); err == nil || errorClass(err) != "error" || strings.Contains(err.Error(), "would not boot") {
		t.Fatalf("an unreadable image gave %v (class %s)", err, errorClass(err))
	}
	// The efivarfs looked for is the one under the sysfs given, which here
	// has none, whatever the host running the test has.
	checkESP = func(string, int) error { return nil }
	if plan, err := bootEntry(fakeSys(t, true), "/run/image.raw", disk, &Plan{}); plan != nil || err != nil {
		t.Fatalf("without efivarfs bootEntry = %v, %v, want no entry and no error", plan, err)
	}
	// On legacy BIOS the firmware does not read the ESP.
	checkESP = func(string, int) error { t.Fatal("ESP checked on legacy BIOS"); return nil }
	if _, err := bootEntry(fakeSys(t, false), "/run/image.raw", disk, &Plan{}); err != nil {
		t.Fatal(err)
	}
}

func TestBootEntryNamesUEFI(t *testing.T) {
	summary := &Plan{}
	// Past the mode the disk cannot be read; the plan names the mode first.
	_, _ = bootEntry(fakeSys(t, true), "/nonexistent/image.raw", "/nonexistent/disk", summary)
	var out strings.Builder
	summary.Print(&out)
	if !strings.Contains(out.String(), "firmware") || !strings.Contains(out.String(), "UEFI") {
		t.Fatalf("summary:\n%s", out.String())
	}
}
