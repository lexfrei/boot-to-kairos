//go:build linux

package install

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{name: "partition", mod: func(o *Options) { o.Disk = "/dev/vda1" }, uefi: true, want: ErrNotWholeDisk},
		{name: "unknown disk", mod: func(o *Options) { o.Disk = "/dev/sdz" }, uefi: true, want: ErrNotWholeDisk},
		{name: "regular file", mod: func(o *Options) { o.Disk = "/tmp/vda" }, uefi: true, want: ErrNotWholeDisk},
		{name: "logical volume", mod: func(o *Options) { o.Disk = "/dev/mapper/vg-root" }, uefi: true, want: ErrNotWholeDisk},
		{name: "by-id link", mod: func(o *Options) { o.Disk = "/dev/disk/by-id/virtio-root" }, uefi: true, want: nil},
		{name: "bad config", mod: func(o *Options) { o.ConfigPath = config(t, "users: []\n") }, uefi: true, want: ErrBadConfig},
		{name: "bios", mod: func(*Options) {}, uefi: false, want: ErrBIOSUnsupported},
		{name: "json output", mod: func(o *Options) { o.Output = OutputJSON }, uefi: true, want: nil},
		{name: "unknown output", mod: func(o *Options) { o.Output = "yaml" }, uefi: true, want: ErrBadOutput},
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
