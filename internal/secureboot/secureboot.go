// Package secureboot tells whether the firmware enforces Secure Boot and
// whether it would load the boot chain an image installed: the loader the
// firmware starts, GRUB when the loader is shim, and the kernel.
//
// A binary is refused when its Authenticode hash, or a certificate on the
// path of one of its signatures, is in a revocation list. It is trusted when
// its hash is in a list that trusts it, or when the signer of one of its
// signatures, or a certificate the signature embeds above it, is a key of
// such a list or is signed by one. The signature itself is not verified
// against the hash, and SBAT revocation levels are not read.
package secureboot

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
)

const (
	// globalGUID is EFI_GLOBAL_VARIABLE, the vendor of SecureBoot.
	globalGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	// dbGUID is EFI_IMAGE_SECURITY_DATABASE_GUID, the vendor of db and dbx.
	dbGUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	// shimGUID is SHIM_LOCK_GUID, the vendor of the MOK lists.
	shimGUID = "605dab50-e046-4300-abb6-3dd810dd8b23"
)

//nolint:gochecknoglobals // constants
var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// EFI_CERT_X509_GUID and EFI_CERT_SHA256_GUID in their byte order.
	certX509   = [16]byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}
	certSHA256 = [16]byte{0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}
)

// ErrUnreadable marks a list ReadKeys could not read, as opposed to one it
// read and could not parse.
var ErrUnreadable = errors.New("EFI variable cannot be read")

type unreadableError struct{ err error }

func (e unreadableError) Error() string        { return e.err.Error() }
func (e unreadableError) Unwrap() error        { return e.err }
func (e unreadableError) Is(target error) bool { return target == ErrUnreadable }

// ErrUntrusted marks a chain the firmware or shim would refuse to boot.
var ErrUntrusted = errors.New("Secure Boot would refuse the boot chain")

// untrustedError is ErrUntrusted with a reason that does not repeat it.
type untrustedError string

func (e untrustedError) Error() string        { return string(e) }
func (e untrustedError) Is(target error) bool { return target == ErrUntrusted }

func untrusted(format string, args ...any) error {
	return untrustedError(fmt.Sprintf(format, args...))
}

// State is whether the firmware enforces Secure Boot.
type State int

const (
	Unknown State = iota
	Off
	On
)

// Vars reads EFI variables from efivarfs, where each file holds the
// attributes and then the value, or from the sysfs interface that kernels
// before 6.0 offer, where a directory per variable holds the value in data.
type Vars struct {
	dir    string
	legacy bool
}

// OpenVars picks efivarfs at efivars when isEfivarfs says it is mounted
// there, and the sysfs interface at legacy otherwise.
func OpenVars(efivars, legacy string, isEfivarfs func(string) bool) (Vars, error) {
	if isEfivarfs(efivars) {
		return Vars{dir: efivars}, nil
	}
	if fi, err := os.Stat(legacy); err == nil && fi.IsDir() {
		return Vars{dir: legacy, legacy: true}, nil
	}
	return Vars{}, errors.Newf("neither efivarfs at %s nor %s is there to read EFI variables from", efivars, legacy)
}

// Legacy says the variables come from the sysfs interface.
func (v Vars) Legacy() bool { return v.legacy }

func (v Vars) read(name, guid string) ([]byte, error) {
	if v.legacy {
		return os.ReadFile(filepath.Join(v.dir, name+"-"+guid, "data"))
	}
	b, err := os.ReadFile(filepath.Join(v.dir, name+"-"+guid))
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, errors.Newf("%s: %d bytes, no attributes", name, len(b))
	}
	return b[4:], nil
}

// ReadState reads the SecureBoot variable. Firmware that keeps none cannot
// enforce Secure Boot. Unknown comes with the reason.
func ReadState(v Vars) (State, error) {
	b, err := v.read("SecureBoot", globalGUID)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Off, nil
	case err != nil:
		return Unknown, errors.Wrap(err, "read SecureBoot")
	case len(b) != 1:
		return Unknown, errors.Newf("SecureBoot in %s holds %d bytes", v.dir, len(b))
	case b[0] == 1:
		return On, nil
	}
	return Off, nil
}

// Sigs is one signature database: certificates and SHA-256 Authenticode
// hashes.
type Sigs struct {
	Certs  []*x509.Certificate
	Hashes [][sha256.Size]byte
}

// Keys are the firmware's and shim's lists, as the running system sees them.
// MokListRT is the copy of the MOK list that the shim this system booted
// through left, extended with that shim's own vendor certificates, so it
// can trust a key the installed shim would not.
type Keys struct {
	DB, DBX, MOK, MOKX Sigs
	// Skipped counts certificates of db and MokListRT that could not be
	// parsed, and so trust nothing here.
	Skipped int
}

// ReadKeys reads db, dbx and the MOK lists. db must be there: without it
// nothing could be trusted. A certificate that cannot be parsed is skipped
// in a list that trusts, and stops the read in one that revokes, as what it
// revokes cannot be told.
func ReadKeys(v Vars) (*Keys, error) {
	k := &Keys{}
	b, err := v.read("db", dbGUID)
	if err != nil {
		return nil, unreadableError{errors.Wrap(err, "read db")}
	}
	if k.DB, k.Skipped, err = parseESL(b, false); err != nil {
		return nil, errors.Wrap(err, "db")
	}
	for _, l := range []struct {
		name, guid string
		into       *Sigs
		revokes    bool
	}{
		{"dbx", dbGUID, &k.DBX, true},
		{"MokListRT", shimGUID, &k.MOK, false},
		{"MokListXRT", shimGUID, &k.MOKX, true},
	} {
		// shim splits a long list into MokListRT, MokListRT1, MokListRT2...
		for n := 0; ; n++ {
			name := l.name
			if n > 0 {
				name += fmt.Sprint(n)
			}
			b, err := v.read(name, l.guid)
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			if err != nil {
				return nil, unreadableError{errors.Wrapf(err, "read %s", name)}
			}
			sigs, skipped, err := parseESL(b, l.revokes)
			if err != nil {
				return nil, errors.Wrap(err, name)
			}
			k.Skipped += skipped
			l.into.Certs = append(l.into.Certs, sigs.Certs...)
			l.into.Hashes = append(l.into.Hashes, sigs.Hashes...)
		}
	}
	return k, nil
}

// parseESL reads EFI_SIGNATURE_LISTs (UEFI 2.10, 32.4.1): the X.509
// certificates and the SHA-256 hashes. Unless strict, a certificate that
// does not parse is counted instead of failing the read.
func parseESL(b []byte, strict bool) (Sigs, int, error) {
	var s Sigs
	skipped := 0
	for len(b) > 0 {
		if len(b) < 28 {
			return Sigs{}, 0, errors.Newf("signature list header of %d bytes", len(b))
		}
		var typ [16]byte
		copy(typ[:], b)
		list := uint64(binary.LittleEndian.Uint32(b[16:]))
		hdr := uint64(binary.LittleEndian.Uint32(b[20:]))
		size := uint64(binary.LittleEndian.Uint32(b[24:]))
		if list > uint64(len(b)) || 28+hdr > list || size < 16 || (list-28-hdr)%size != 0 {
			return Sigs{}, 0, errors.Newf("signature list of %d bytes, header %d, entries %d, in %d", list, hdr, size, len(b))
		}
		for e := b[28+hdr : list]; len(e) > 0; e = e[size:] {
			switch typ {
			case certX509:
				c, err := x509.ParseCertificate(e[16:size])
				switch {
				case err == nil:
					s.Certs = append(s.Certs, c)
				case strict:
					return Sigs{}, 0, errors.Wrap(err, "certificate in signature list")
				default:
					skipped++
				}
			case certSHA256:
				if size != 16+sha256.Size {
					return Sigs{}, 0, errors.Newf("SHA-256 entry of %d bytes", size)
				}
				s.Hashes = append(s.Hashes, [sha256.Size]byte(e[16:size]))
			}
		}
		b = b[list:]
	}
	return s, skipped, nil
}

// Chain is what the firmware would load from the installed disk.
type Chain struct {
	// Loader is the file name the firmware starts, LoaderPE its content.
	Loader   string
	LoaderPE []byte
	// Grub is the file shim loads next, GrubPE nil when absent.
	Grub   string
	GrubPE []byte
	// KernelPE is the kernel GRUB loads.
	KernelPE []byte
}

type list struct {
	name string
	sigs Sigs
}

// Check returns what each binary of the chain is trusted through, or
// ErrUntrusted naming the first one the firmware or shim would refuse.
func (k *Keys) Check(c Chain) (string, error) {
	db := list{"db", k.DB}
	revoked := []list{{"dbx", k.DBX}}
	loader, err := parsePE(c.LoaderPE)
	if err != nil {
		return "", untrusted("%s: %v", c.Loader, err)
	}
	first, err := verify(c.Loader, loader, []list{db}, revoked)
	if err != nil {
		return "", err
	}
	trust := []list{db}
	steps := []string{first}
	vendor, deauth, isShim, err := loader.vendorCerts()
	if err != nil {
		return "", untrusted("%s: %v", c.Loader, err)
	}
	if isShim {
		if c.GrubPE == nil {
			return "", untrusted("no %s beside the shim %s", c.Grub, c.Loader)
		}
		trust = []list{db, {"the shim's vendor certificate", vendor}, {"MokListRT", k.MOK}}
		revoked = append(revoked, list{"MokListXRT", k.MOKX}, list{"the shim's deauthorized list", deauth})
		s, err := verifyFile(c.Grub, c.GrubPE, trust, revoked)
		if err != nil {
			return "", err
		}
		steps = append(steps, s)
	}
	if c.KernelPE == nil {
		return "", untrusted("no kernel to check")
	}
	s, err := verifyFile("kernel", c.KernelPE, trust, revoked)
	if err != nil {
		return "", err
	}
	return strings.Join(append(steps, s), "; "), nil
}

func verifyFile(name string, image []byte, trust, revoked []list) (string, error) {
	p, err := parsePE(image)
	if err != nil {
		return "", untrusted("%s: %v", name, err)
	}
	return verify(name, p, trust, revoked)
}

// verify refuses the binary as soon as its hash or one of its signatures
// hits a revocation list, as firmware and shim do whatever its other
// signatures, and otherwise accepts it if its hash or any signature is
// trusted.
func verify(name string, p *peImage, trust, revoked []list) (string, error) {
	hash, err := p.hash()
	if err != nil {
		return "", untrusted("%s: %v", name, err)
	}
	sigs, err := p.signatures()
	if err != nil {
		return "", untrusted("%s: %v", name, err)
	}
	for _, l := range revoked {
		if hasHash(l.sigs, hash) {
			return "", untrusted("%s: its hash is in %s, which revokes it", name, l.name)
		}
	}
	for _, path := range sigs {
		if _, l := find(path, revoked); l != "" {
			return "", untrusted("%s: signed by %q, which %s revokes", name, cn(path[0]), l)
		}
	}
	for _, l := range trust {
		if hasHash(l.sigs, hash) {
			return fmt.Sprintf("%s trusted by its hash in %s", name, l.name), nil
		}
	}
	if len(sigs) == 0 {
		return "", untrusted("%s is not signed", name)
	}
	for _, path := range sigs {
		if c, l := find(path, trust); c != nil {
			return fmt.Sprintf("%s signed by %q, trusted through %q in %s", name, cn(path[0]), cn(c), l), nil
		}
	}
	var names, signers []string
	for _, l := range trust {
		names = append(names, l.name)
	}
	for _, path := range sigs {
		signers = append(signers, fmt.Sprintf("%q", cn(path[0])))
	}
	verb := "does"
	if len(names) > 1 {
		verb = "do"
	}
	return "", untrusted("%s: signed by %s, which %s %s not trust", name, strings.Join(signers, " and "), joinNames(names), verb)
}

func hasHash(s Sigs, h [sha256.Size]byte) bool {
	return slices.Contains(s.Hashes, h)
}

func joinNames(n []string) string {
	if len(n) < 2 {
		return strings.Join(n, "")
	}
	return strings.Join(n[:len(n)-1], ", ") + " and " + n[len(n)-1]
}

// find returns the first key of lists that is a certificate on path or
// signed one, and the name of its list. Revocation works the same way:
// firmware and shim verify the signature against each revoked certificate
// as if it were an anchor.
func find(path []*x509.Certificate, lists []list) (*x509.Certificate, string) {
	for _, c := range path {
		for _, l := range lists {
			for _, k := range l.sigs.Certs {
				if bytes.Equal(c.Raw, k.Raw) || signs(k, c) {
					return k, l.name
				}
			}
		}
	}
	return nil, ""
}

// signs reports whether parent's key signed c. Firmware takes any db
// certificate as an anchor, CA or not, which CheckSignatureFrom would
// refuse.
func signs(parent, c *x509.Certificate) bool {
	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func cn(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}
