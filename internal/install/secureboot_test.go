//go:build linux

package install

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/kairos"
	"github.com/lexfrei/boot-to-kairos/internal/secureboot"
)

const (
	globalVar = "-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	dbVar     = "-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)

// fakeEFIVars is an efivarfs stand-in with SecureBoot set to on and, if
// withDB, a db holding one certificate.
func fakeEFIVars(t *testing.T, withDB bool) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "SecureBoot"+globalVar), []byte{6, 0, 0, 0, 1}, 0o644); err != nil {
		t.Fatal(err)
	}
	if !withDB {
		return d
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "db"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	// EFI_SIGNATURE_LIST of one EFI_CERT_X509_GUID entry.
	l := []byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}
	l = binary.LittleEndian.AppendUint32(l, uint32(28+16+len(der)))
	l = binary.LittleEndian.AppendUint32(l, 0)
	l = binary.LittleEndian.AppendUint32(l, uint32(16+len(der)))
	l = append(append(l, make([]byte, 16)...), der...)
	if err := os.WriteFile(filepath.Join(d, "db"+dbVar), append([]byte{7, 0, 0, 0}, l...), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func yesEfivarfs(string) bool { return true }
func noEfivarfs(string) bool  { return false }

func TestSecureBootOnLegacyBIOSIsOffWithoutAWarning(t *testing.T) {
	logs := captureLog(t)
	sb, err := readSecureBoot(kairos.BIOS, filepath.Join(t.TempDir(), "absent"), filepath.Join(t.TempDir(), "absent"), noEfivarfs)
	if err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Errorf("a legacy BIOS run must not warn about Secure Boot: %q", logs)
	}
	plan := &Plan{}
	if err := checkSecureBoot(sb, nil, plan); err != nil {
		t.Fatal(err)
	}
	if got := planValue(plan, "Secure Boot"); got != "off: legacy BIOS" {
		t.Errorf("plan says %q", got)
	}
}

func TestSecureBootUnknownOnUEFIWarnsAndProceeds(t *testing.T) {
	logs := captureLog(t)
	sb, err := readSecureBoot(kairos.EFI, filepath.Join(t.TempDir(), "absent"), filepath.Join(t.TempDir(), "absent"), noEfivarfs)
	if err != nil {
		t.Fatalf("an unknown state must not stop the install: %v", err)
	}
	for _, want := range []string{"warning:", "booted through UEFI, not legacy BIOS", "whether Secure Boot is on cannot be told", "signed by keys this firmware trusts"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("warning %q lacks %q", logs, want)
		}
	}
	plan := &Plan{}
	if err := checkSecureBoot(sb, nil, plan); err != nil {
		t.Fatal(err)
	}
	if got := planValue(plan, "Secure Boot"); !strings.HasPrefix(got, "unknown: neither efivarfs") || !strings.Contains(got, "EFI variables") {
		t.Errorf("plan says %q", got)
	}
}

func TestSecureBootOffNeedsNoChain(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "SecureBoot"+globalVar), []byte{6, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	sb, err := readSecureBoot(kairos.EFI, d, "", yesEfivarfs)
	if err != nil || logs.Len() != 0 {
		t.Fatalf("%v, %q", err, logs)
	}
	plan := &Plan{}
	read := func() (secureboot.Chain, error) {
		t.Error("the boot chain was read with Secure Boot off")
		return secureboot.Chain{}, nil
	}
	if err := checkSecureBoot(sb, read, plan); err != nil || planValue(plan, "Secure Boot") != "off" {
		t.Errorf("%v, plan says %q", err, planValue(plan, "Secure Boot"))
	}
}

func TestSecureBootOnReadsTheKeys(t *testing.T) {
	sb, err := readSecureBoot(kairos.EFI, fakeEFIVars(t, true), "", yesEfivarfs)
	if err != nil {
		t.Fatal(err)
	}
	if sb.state != secureboot.On || sb.check == nil {
		t.Fatalf("state %v, check set %v", sb.state, sb.check != nil)
	}
	_, err = readSecureBoot(kairos.EFI, fakeEFIVars(t, false), "", yesEfivarfs)
	if errorClass(err) != "secure-boot" || !strings.Contains(err.Error(), "Secure Boot is on, and its keys cannot be read") {
		t.Errorf("no db: %v (class %s)", err, errorClass(err))
	}
}

func TestSecureBootOnReadsTheKeysFromSysfsWithoutEfivarfs(t *testing.T) {
	ev := fakeEFIVars(t, true)
	legacy := t.TempDir()
	for _, name := range []string{"SecureBoot" + globalVar, "db" + dbVar} {
		b, err := os.ReadFile(filepath.Join(ev, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(legacy, name), 0o755); err != nil {
			t.Fatal(err)
		}
		// No attributes in front of the value in sysfs.
		if err := os.WriteFile(filepath.Join(legacy, name, "data"), b[4:], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sb, err := readSecureBoot(kairos.EFI, filepath.Join(t.TempDir(), "absent"), legacy, noEfivarfs)
	if err != nil || sb.state != secureboot.On || sb.check == nil {
		t.Errorf("state %v, check set %v, %v", sb.state, sb.check != nil, err)
	}
}

// The sysfs interface hands out at most 1024 bytes of a variable and fails
// on a longer one, which db and dbx with Microsoft's keys are.
func TestSecureBootOnWithKeysSysfsCannotReadGoesAheadUnchecked(t *testing.T) {
	legacy := t.TempDir()
	if err := os.Mkdir(filepath.Join(legacy, "SecureBoot"+globalVar), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "SecureBoot"+globalVar, "data"), []byte{1}, 0o644); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	sb, err := readSecureBoot(kairos.EFI, filepath.Join(t.TempDir(), "absent"), legacy, noEfivarfs)
	if err != nil {
		t.Fatalf("keys sysfs cannot hand out must not stop the install: %v", err)
	}
	for _, want := range []string{"warning: Secure Boot is on, but its keys cannot be read from " + legacy, "1024 bytes", "mount efivarfs"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("warning %q lacks %q", logs, want)
		}
	}
	plan := &Plan{}
	read := func() (secureboot.Chain, error) {
		t.Error("the boot chain was read with no keys to check it against")
		return secureboot.Chain{}, nil
	}
	if err := checkSecureBoot(sb, read, plan); err != nil {
		t.Fatal(err)
	}
	if got := planValue(plan, "Secure Boot"); !strings.HasPrefix(got, "on; not checked: read db") {
		t.Errorf("plan says %q", got)
	}
}

// Only a list sysfs cannot hand out goes unchecked; one it hands out and
// that does not parse is refused as through efivarfs.
func TestSecureBootOnWithAListSysfsReadsButCannotParseRefuses(t *testing.T) {
	ev := fakeEFIVars(t, true)
	legacy := t.TempDir()
	for name, data := range map[string][]byte{"SecureBoot" + globalVar: {1}, "dbx" + dbVar: append(dbList(t, ev), 0xff)} {
		if err := os.Mkdir(filepath.Join(legacy, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacy, name, "data"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(legacy, "db"+dbVar), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "db"+dbVar, "data"), dbList(t, ev), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readSecureBoot(kairos.EFI, filepath.Join(t.TempDir(), "absent"), legacy, noEfivarfs)
	if errorClass(err) != "secure-boot" {
		t.Errorf("a dbx that reads but does not parse: %v (class %s)", err, errorClass(err))
	}
}

// dbList is the value of the fake db, without its attributes.
func dbList(t *testing.T, efivars string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(efivars, "db"+dbVar))
	if err != nil {
		t.Fatal(err)
	}
	return b[4:]
}

func TestSecureBootWarnsAboutCertificatesItCannotParse(t *testing.T) {
	ev := fakeEFIVars(t, true)
	f, err := os.OpenFile(filepath.Join(ev, "db"+dbVar), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	// One EFI_CERT_X509_GUID entry that is not a certificate.
	bad := []byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}
	bad = binary.LittleEndian.AppendUint32(bad, 28+16+4)
	bad = binary.LittleEndian.AppendUint32(bad, 0)
	bad = binary.LittleEndian.AppendUint32(bad, 16+4)
	bad = append(append(bad, make([]byte, 16)...), "junk"...)
	if _, err := f.Write(bad); err != nil {
		t.Fatal(err)
	}
	f.Close()
	logs := captureLog(t)
	if _, err := readSecureBoot(kairos.EFI, ev, "", yesEfivarfs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "warning: 1 certificates in db or MokListRT cannot be parsed") {
		t.Errorf("log %q", logs)
	}
}

func TestSecureBootOnChecksTheChain(t *testing.T) {
	chain := secureboot.Chain{Loader: "BOOTX64.EFI"}
	read := func() (secureboot.Chain, error) { return chain, nil }
	trusted := &secureBoot{firmware: kairos.EFI, state: secureboot.On, check: func(c secureboot.Chain) (string, error) {
		if c.Loader != chain.Loader {
			t.Errorf("checked %+v, not the chain read", c)
		}
		return "BOOTX64.EFI signed by X", nil
	}}
	plan := &Plan{}
	if err := checkSecureBoot(trusted, read, plan); err != nil {
		t.Fatal(err)
	}
	if got := planValue(plan, "Secure Boot"); got != "on; BOOTX64.EFI signed by X" {
		t.Errorf("plan says %q", got)
	}

	refused := *trusted
	refused.check = func(secureboot.Chain) (string, error) {
		return "", untrustedError("BOOTX64.EFI is not signed")
	}
	err := checkSecureBoot(&refused, read, &Plan{})
	if errorClass(err) != "secure-boot" {
		t.Errorf("class %s for %v", errorClass(err), err)
	}
	for _, want := range []string{
		"Secure Boot is on, and the firmware would not boot the installed system: BOOTX64.EFI is not signed",
		"Turn Secure Boot off in the firmware setup",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v lacks %q", err, want)
		}
	}

	broken := os.ErrPermission
	err = checkSecureBoot(trusted, func() (secureboot.Chain, error) { return chain, broken }, &Plan{})
	if !errors.Is(err, broken) {
		t.Errorf("a chain that cannot be read must stop the install: %v", err)
	}
}

type untrustedError string

func (e untrustedError) Error() string        { return string(e) }
func (e untrustedError) Is(target error) bool { return target == secureboot.ErrUntrusted }

func TestReadInRootStaysInTheRoot(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"boot", "etc"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Kairos images link /boot/vmlinuz with an absolute target, which read
	// from the host would name the host's own file.
	for _, target := range []string{"/etc/os-release", "../../../../../etc/os-release"} {
		link := filepath.Join(root, "boot/vmlinuz")
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got, err := readInRoot(root, "boot/vmlinuz")
		if err != nil || string(got) != "inside" {
			t.Errorf("link to %s read %q, %v; want the root's own file", target, got, err)
		}
	}
	// A linked directory on the way resolves inside the root as well.
	if err := os.Symlink("/etc", filepath.Join(root, "conf")); err != nil {
		t.Fatal(err)
	}
	if got, err := readInRoot(root, "conf/../conf/os-release"); err != nil || string(got) != "inside" {
		t.Errorf("through a linked directory: %q, %v", got, err)
	}
	if err := os.Symlink("loop", filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	if _, err := readInRoot(root, "loop"); !errors.Is(err, unix.ELOOP) {
		t.Errorf("a link to itself: %v", err)
	}
	// 40 links in a row resolve, as in the kernel; the 41st does not.
	prev := "etc/os-release"
	for i := range 41 {
		name := fmt.Sprintf("hop%d", i)
		if err := os.Symlink(prev, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
		prev = name
	}
	if got, err := readInRoot(root, "hop39"); err != nil || string(got) != "inside" {
		t.Errorf("40 links: %q, %v", got, err)
	}
	if _, err := readInRoot(root, "hop40"); !errors.Is(err, unix.ELOOP) {
		t.Errorf("41 links: %v", err)
	}
	if _, err := readInRoot(root, "boot/absent"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent file: %v", err)
	}
}

func TestGrubName(t *testing.T) {
	for loader, want := range map[string]string{"BOOTX64.EFI": "grubx64.efi", "BOOTAA64.EFI": "grubaa64.efi", "BOOTRISCV64.EFI": "grubriscv64.efi"} {
		if got := grubName(loader); got != want {
			t.Errorf("%s: %s, want %s", loader, got, want)
		}
	}
}

func planValue(p *Plan, name string) string {
	for _, it := range p.items {
		if it.name == name {
			return it.value
		}
	}
	return ""
}
