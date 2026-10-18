package secureboot

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pki is a firmware CA in db, a shim signer under it, and a distro vendor
// CA with the signer of its GRUB and kernel.
type pki struct {
	msCA, shimSigner, vendorCA, distro *key
}

func newPKI(t *testing.T) pki {
	t.Helper()
	ms := newKey(t, "Firmware UEFI CA", nil, true)
	vendor := newKey(t, "Distro Master CA", nil, true)
	return pki{
		msCA:       ms,
		shimSigner: newKey(t, "UEFI Driver Publisher", ms, false),
		vendorCA:   vendor,
		distro:     newKey(t, "Distro Secure Boot Signing", vendor, false),
	}
}

// shim is a loader signed through the firmware CA that embeds vendor as
// its vendor certificate.
func (p pki) shim(t *testing.T, deauth []byte) []byte {
	t.Helper()
	return buildPE(t, winCerts(pkcs7(t, p.shimSigner.cert, p.shimSigner.cert)), section{".text", []byte("shim")}, vendorSection(p.vendorCA.cert.Raw, deauth))
}

func (p pki) keys() *Keys {
	return &Keys{DB: certs(p.msCA.cert)}
}

func certs(c ...*x509.Certificate) Sigs { return Sigs{Certs: c} }

func peHash(t *testing.T, image []byte) [sha256.Size]byte {
	t.Helper()
	p, err := parsePE(image)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (p pki) chain(t *testing.T) Chain {
	t.Helper()
	return Chain{
		Loader: "BOOTX64.EFI", LoaderPE: p.shim(t, nil),
		Grub: "grubx64.efi", GrubPE: signed(t, p.distro),
		KernelPE: buildPE(t, winCerts(pkcs7(t, p.distro.cert, p.distro.cert)), section{".text", []byte("kernel")}),
	}
}

func TestCheckTrustsASignedShimChain(t *testing.T) {
	p := newPKI(t)
	got, err := p.keys().Check(p.chain(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`BOOTX64.EFI signed by "UEFI Driver Publisher", trusted through "Firmware UEFI CA" in db`,
		`grubx64.efi signed by "Distro Secure Boot Signing", trusted through "Distro Master CA" in the shim's vendor certificate`,
		`kernel signed by "Distro Secure Boot Signing", trusted through "Distro Master CA" in the shim's vendor certificate`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q lacks %q", got, want)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	p := newPKI(t)
	stranger := newKey(t, "Someone Else", nil, false)
	for _, tc := range []struct {
		name  string
		edit  func(*Chain, *Keys)
		wants []string
	}{
		{"unsigned loader", func(c *Chain, _ *Keys) {
			c.LoaderPE = buildPE(t, nil, section{".text", []byte("x")})
		}, []string{"BOOTX64.EFI is not signed"}},
		{"loader signed by a key db lacks", func(_ *Chain, k *Keys) {
			k.DB = certs(stranger.cert)
		}, []string{`BOOTX64.EFI: signed by "UEFI Driver Publisher", which db does not trust`}},
		{"loader signer revoked in dbx", func(_ *Chain, k *Keys) {
			k.DBX = certs(p.shimSigner.cert)
		}, []string{`BOOTX64.EFI: signed by "UEFI Driver Publisher", which dbx revokes`}},
		{"loader CA revoked in dbx", func(_ *Chain, k *Keys) {
			k.DBX = certs(p.msCA.cert)
		}, []string{`which dbx revokes`}},
		{"unsigned grub", func(c *Chain, _ *Keys) {
			c.GrubPE = buildPE(t, nil, section{".text", []byte("x")})
		}, []string{"grubx64.efi is not signed"}},
		{"grub missing beside the shim", func(c *Chain, _ *Keys) {
			c.GrubPE = nil
		}, []string{"no grubx64.efi beside the shim"}},
		{"kernel signed by a stranger", func(c *Chain, _ *Keys) {
			c.KernelPE = signed(t, stranger)
		}, []string{`kernel: signed by "Someone Else", which db, the shim's vendor certificate and MokListRT do not trust`}},
		{"kernel missing", func(c *Chain, _ *Keys) {
			c.KernelPE = nil
		}, []string{"no kernel"}},
		{"grub signer in the shim's deauthorized list", func(c *Chain, _ *Keys) {
			c.LoaderPE = p.shim(t, esl(p.distro.cert))
		}, []string{`grubx64.efi: signed by "Distro Secure Boot Signing", which the shim's deauthorized list revokes`}},
		{"grub signer in MokListXRT", func(_ *Chain, k *Keys) {
			k.MOKX = certs(p.vendorCA.cert)
		}, []string{"which MokListXRT revokes"}},
		{"loader hash in dbx", func(c *Chain, k *Keys) {
			k.DBX = Sigs{Hashes: [][sha256.Size]byte{peHash(t, c.LoaderPE)}}
		}, []string{"BOOTX64.EFI: its hash is in dbx, which revokes it"}},
		{"kernel hash in the shim's deauthorized list", func(c *Chain, _ *Keys) {
			h := peHash(t, c.KernelPE)
			c.LoaderPE = p.shim(t, sigList(certSHA256, h[:]))
		}, []string{"kernel: its hash is in the shim's deauthorized list, which revokes it"}},
		{"certificate table past the end", func(c *Chain, _ *Keys) {
			c.GrubPE = c.GrubPE[:len(c.GrubPE)-1]
		}, []string{"grubx64.efi: certificate table ends at"}},
		{"WIN_CERTIFICATE shorter than its header", func(c *Chain, _ *Keys) {
			c.GrubPE = buildPE(t, []byte{4, 0, 0, 0, 0, 2, 2, 0}, section{".text", []byte("g")})
		}, []string{"grubx64.efi: WIN_CERTIFICATE of 4 bytes in 8"}},
		{"WIN_CERTIFICATE longer than the table", func(c *Chain, _ *Keys) {
			c.GrubPE = buildPE(t, []byte{64, 0, 0, 0, 0, 2, 2, 0}, section{".text", []byte("g")})
		}, []string{"grubx64.efi: WIN_CERTIFICATE of 64 bytes in 8"}},
		{"garbage instead of PKCS#7", func(c *Chain, _ *Keys) {
			c.GrubPE = buildPE(t, winCerts([]byte("garbage!")), section{".text", []byte("g")})
		}, []string{"grubx64.efi: PKCS#7 content info"}},
		{"signer not embedded", func(c *Chain, _ *Keys) {
			c.GrubPE = buildPE(t, winCerts(pkcs7(t, p.distro.cert, p.vendorCA.cert)), section{".text", []byte("g")})
		}, []string{"grubx64.efi: PKCS#7 signer certificate is not embedded"}},
		{"two signer infos", func(c *Chain, _ *Keys) {
			c.GrubPE = buildPE(t, winCerts(pkcs7Signers(t, 2, p.distro.cert)), section{".text", []byte("g")})
		}, []string{"grubx64.efi: 2 signer infos"}},
		{".vendor_cert offset past the section", func(c *Chain, _ *Keys) {
			v := vendorSection(p.vendorCA.cert.Raw, nil)
			v.data[8] = 0xff
			c.LoaderPE = buildPE(t, winCerts(pkcs7(t, p.shimSigner.cert, p.shimSigner.cert)), v)
		}, []string{"BOOTX64.EFI: .vendor_cert entry at"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, k := p.chain(t), p.keys()
			tc.edit(&c, k)
			_, err := k.Check(c)
			if !errors.Is(err, ErrUntrusted) {
				t.Fatalf("err = %v, want ErrUntrusted", err)
			}
			if strings.Contains(err.Error(), ErrUntrusted.Error()) {
				t.Errorf("%q repeats the sentinel's own text", err)
			}
			for _, w := range tc.wants {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%q lacks %q", err, w)
				}
			}
		})
	}
}

func TestCheckTrustsMOKAndDB(t *testing.T) {
	p := newPKI(t)
	// Issued by a CA none of the lists hold: only the key itself is in MOK.
	own := newKey(t, "Own Kernel Key", newKey(t, "Own CA", nil, true), false)
	c, k := p.chain(t), p.keys()
	c.KernelPE = signed(t, own)
	k.MOK = certs(own.cert)
	got, err := k.Check(c)
	if err != nil || !strings.Contains(got, `kernel signed by "Own Kernel Key", trusted through "Own Kernel Key" in MokListRT`) {
		t.Errorf("MOK: %q, %v", got, err)
	}
	c.KernelPE = signed(t, p.shimSigner)
	if got, err := k.Check(c); err != nil || !strings.Contains(got, `trusted through "Firmware UEFI CA" in db`) {
		t.Errorf("db for the kernel: %q, %v", got, err)
	}
}

func TestCheckWithoutShimTrustsOnlyDB(t *testing.T) {
	p := newPKI(t)
	k := p.keys()
	k.MOK = certs(p.vendorCA.cert)
	c := Chain{Loader: "BOOTRISCV64.EFI", LoaderPE: signed(t, p.shimSigner), KernelPE: signed(t, p.distro)}
	_, err := k.Check(c)
	if !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "kernel: signed by \"Distro Secure Boot Signing\", which db does not trust") {
		t.Fatalf("a kernel loaded without a shim must chain to db alone: %v", err)
	}
	c.KernelPE = signed(t, p.shimSigner)
	if _, err := k.Check(c); err != nil {
		t.Errorf("kernel chaining to db: %v", err)
	}
}

func TestCheckTakesAnyTrustedSignature(t *testing.T) {
	p := newPKI(t)
	stranger := newKey(t, "Someone Else", nil, false)
	c := p.chain(t)
	c.GrubPE = buildPE(t, winCerts(pkcs7(t, stranger.cert, stranger.cert), pkcs7(t, p.distro.cert, p.distro.cert)), section{".text", []byte("g")})
	if _, err := p.keys().Check(c); err != nil {
		t.Errorf("the second signature chains to the vendor CA: %v", err)
	}
}

func TestCheckFollowsEmbeddedIntermediates(t *testing.T) {
	root := newKey(t, "Root", nil, true)
	mid := newKey(t, "Intermediate", root, true)
	leaf := newKey(t, "Leaf", mid, false)
	k := &Keys{DB: certs(root.cert)}
	c := Chain{Loader: "BOOTX64.EFI", LoaderPE: signed(t, leaf, mid.cert), KernelPE: signed(t, leaf, mid.cert)}
	if _, err := k.Check(c); err != nil {
		t.Errorf("leaf → intermediate → db root: %v", err)
	}
	c.LoaderPE = signed(t, leaf)
	if _, err := k.Check(c); !errors.Is(err, ErrUntrusted) {
		t.Errorf("without the intermediate the chain must not reach db: %v", err)
	}
}

func TestShimWithDERAndESLVendorCerts(t *testing.T) {
	p := newPKI(t)
	c, k := p.chain(t), p.keys()
	c.LoaderPE = buildPE(t, winCerts(pkcs7(t, p.shimSigner.cert, p.shimSigner.cert)), vendorSection(esl(p.vendorCA.cert), nil))
	if _, err := k.Check(c); err != nil {
		t.Errorf("vendor db as a signature list: %v", err)
	}
}

func TestParseESL(t *testing.T) {
	p := newPKI(t)
	h := sha256.Sum256([]byte("x"))
	b := append(esl(p.msCA.cert, p.vendorCA.cert), sigList(certSHA256, h[:], h[:])...)
	sigs, skipped, err := parseESL(b, true)
	if err != nil || len(sigs.Certs) != 2 || len(sigs.Hashes) != 2 || skipped != 0 || sigs.Certs[1].Subject.CommonName != "Distro Master CA" || sigs.Hashes[1] != h {
		t.Fatalf("certs %d, hashes %d, skipped %d, err %v", len(sigs.Certs), len(sigs.Hashes), skipped, err)
	}
	for _, bad := range [][]byte{b[:20], b[:len(b)-1], append(append([]byte{}, b[:16]...), 0xff, 0xff, 0xff, 0x7f), sigList(certSHA256, h[:20]), sigList(certSHA256, append(h[:], h[:8]...))} {
		if _, _, err := parseESL(bad, false); err == nil {
			t.Errorf("truncated or oversized list of %d bytes parsed", len(bad))
		}
	}
	broken := append(sigList(certX509, []byte("not a certificate")), esl(p.msCA.cert)...)
	if sigs, skipped, err := parseESL(broken, false); err != nil || skipped != 1 || len(sigs.Certs) != 1 {
		t.Errorf("a list that trusts skips what it cannot parse: %d certs, %d skipped, %v", len(sigs.Certs), skipped, err)
	}
	if _, _, err := parseESL(broken, true); err == nil {
		t.Error("a list that revokes must not drop what it cannot parse")
	}
}

func writeVar(t *testing.T, dir, name, guid string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+"-"+guid), append([]byte{7, 0, 0, 0}, data...), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadState(t *testing.T) {
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	for _, tc := range []struct {
		name    string
		efivars []byte // nil: no variable
		legacy  []byte
		isFS    func(string) bool
		want    State
	}{
		{"on", []byte{1}, nil, yes, On},
		{"off", []byte{0}, nil, yes, Off},
		{"no variable on efivarfs: firmware without Secure Boot", nil, nil, yes, Off},
		{"efivarfs not mounted, sysfs vars on", nil, []byte{1}, no, On},
		{"efivarfs not mounted, sysfs vars off", nil, []byte{0}, no, Off},
		{"truncated variable", []byte{}, nil, yes, Unknown},
		{"sysfs variable of two bytes", nil, []byte{1, 0}, no, Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, lv := t.TempDir(), t.TempDir()
			if tc.efivars != nil {
				writeVar(t, ev, "SecureBoot", globalGUID, tc.efivars)
			}
			if tc.legacy != nil {
				writeLegacyVar(t, lv, "SecureBoot", globalGUID, tc.legacy)
			}
			v, err := OpenVars(ev, lv, tc.isFS)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadState(v)
			if got != tc.want {
				t.Errorf("state %v (%v), want %v", got, err, tc.want)
			}
			if (got == Unknown) != (err != nil) {
				t.Errorf("Unknown must come with its reason and only then: %v, %v", got, err)
			}
		})
	}
	if _, err := OpenVars(t.TempDir(), filepath.Join(t.TempDir(), "absent"), no); err == nil {
		t.Error("neither interface: nothing to read from")
	}
	ev := t.TempDir()
	if err := os.WriteFile(filepath.Join(ev, "SecureBoot-"+globalGUID), []byte{7, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadState(Vars{dir: ev}); got != Unknown || err == nil || !strings.Contains(err.Error(), "no attributes") {
		t.Errorf("an efivarfs file shorter than its attributes: %v, %v", got, err)
	}
}

func writeLegacyVar(t *testing.T, dir, name, guid string, data []byte) {
	t.Helper()
	d := filepath.Join(dir, name+"-"+guid)
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "data"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadKeys(t *testing.T) {
	p := newPKI(t)
	h := sha256.Sum256([]byte("x"))
	vars := map[string][]byte{
		"db-" + dbGUID:           append(append(esl(p.msCA.cert), sigList(certSHA256, h[:])...), sigList(certX509, []byte("unparsable"))...),
		"dbx-" + dbGUID:          append(esl(p.shimSigner.cert), sigList(certSHA256, h[:])...),
		"MokListRT-" + shimGUID:  append(esl(p.vendorCA.cert), sigList(certX509, []byte("unparsable"))...),
		"MokListRT1-" + shimGUID: esl(p.distro.cert),
		"MokListXRT-" + shimGUID: esl(p.msCA.cert),
	}
	for _, legacy := range []bool{false, true} {
		d := t.TempDir()
		for name, data := range vars {
			guid := name[strings.Index(name, "-")+1:]
			if legacy {
				writeLegacyVar(t, d, name[:strings.Index(name, "-")], guid, data)
			} else {
				writeVar(t, d, name[:strings.Index(name, "-")], guid, data)
			}
		}
		k, err := ReadKeys(Vars{dir: d, legacy: legacy})
		if err != nil {
			t.Fatalf("legacy %v: %v", legacy, err)
		}
		if len(k.DB.Certs) != 1 || len(k.DB.Hashes) != 1 || k.Skipped != 2 || len(k.DBX.Certs) != 1 || len(k.DBX.Hashes) != 1 || len(k.MOK.Certs) != 2 || len(k.MOKX.Certs) != 1 {
			t.Errorf("legacy %v: db %d+%d (skipped %d), dbx %d+%d, MOK %d, MOKX %d", legacy, len(k.DB.Certs), len(k.DB.Hashes), k.Skipped, len(k.DBX.Certs), len(k.DBX.Hashes), len(k.MOK.Certs), len(k.MOKX.Certs))
		}
	}
	d := t.TempDir()
	writeVar(t, d, "db", dbGUID, esl(p.msCA.cert))
	writeVar(t, d, "dbx", dbGUID, sigList(certX509, []byte("unparsable")))
	if _, err := ReadKeys(Vars{dir: d}); err == nil {
		t.Error("a dbx certificate that cannot be parsed must stop the read")
	}
	if _, err := ReadKeys(Vars{dir: d}); errors.Is(err, ErrUnreadable) {
		t.Errorf("a list that reads and does not parse is not unreadable: %v", err)
	}
	if _, err := ReadKeys(Vars{dir: t.TempDir()}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("Secure Boot on without a readable db must not pass, and says it could not read: %v", err)
	}
	// A dbx that is a directory reads as EISDIR, not as absent.
	d = t.TempDir()
	writeVar(t, d, "db", dbGUID, esl(p.msCA.cert))
	if err := os.Mkdir(filepath.Join(d, "dbx-"+dbGUID), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeys(Vars{dir: d}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a dbx that cannot be read: %v", err)
	}
}

func TestCheckPicksTheSignerBySerial(t *testing.T) {
	ca := newKey(t, "CA", nil, true)
	sibling := newKey(t, "Leaf", ca, false)
	leaf := newKey(t, "Leaf", ca, false)
	k := &Keys{DB: certs(ca.cert), DBX: certs(sibling.cert)}
	pe := buildPE(t, winCerts(pkcs7(t, leaf.cert, sibling.cert, leaf.cert)), section{".text", []byte("x")})
	if _, err := k.Check(Chain{Loader: "BOOTX64.EFI", LoaderPE: pe, KernelPE: pe}); err != nil {
		t.Errorf("the signer is the second Leaf, which dbx does not revoke: %v", err)
	}
}

func TestCheckSkipsCertificatesThatAreNotPKCS7(t *testing.T) {
	p := newPKI(t)
	c := p.chain(t)
	x509Entry := winCerts([]byte("not a signature"))
	x509Entry[6] = 1 // WIN_CERT_TYPE_X509
	c.GrubPE = buildPE(t, append(x509Entry, winCerts(pkcs7(t, p.distro.cert, p.distro.cert))...), section{".text", []byte("g")})
	if _, err := p.keys().Check(c); err != nil {
		t.Errorf("a non-PKCS#7 entry must be skipped: %v", err)
	}
}

func TestCheckRefusesWhenAnySignatureIsRevoked(t *testing.T) {
	p := newPKI(t)
	revoked := newKey(t, "Old Signer", p.msCA, false)
	c, k := p.chain(t), p.keys()
	k.DBX = certs(revoked.cert)
	c.LoaderPE = buildPE(t, winCerts(pkcs7(t, p.shimSigner.cert, p.shimSigner.cert), pkcs7(t, revoked.cert, revoked.cert)), section{".text", []byte("s")}, vendorSection(p.vendorCA.cert.Raw, nil))
	if _, err := k.Check(c); !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), `signed by "Old Signer", which dbx revokes`) {
		t.Errorf("a trusted signature does not save an image with a revoked one: %v", err)
	}
}

func TestCheckTrustsByHash(t *testing.T) {
	p := newPKI(t)
	c, k := p.chain(t), p.keys()
	unsigned := buildPE(t, nil, section{".text", []byte("plain")})
	c.LoaderPE, c.GrubPE, c.KernelPE = unsigned, nil, unsigned
	k.DB.Hashes = [][sha256.Size]byte{peHash(t, unsigned)}
	got, err := k.Check(c)
	if err != nil || !strings.Contains(got, "BOOTX64.EFI trusted by its hash in db") || !strings.Contains(got, "kernel trusted by its hash in db") {
		t.Errorf("an unsigned binary db allows by hash boots: %q, %v", got, err)
	}
	c = p.chain(t)
	k = p.keys()
	k.MOK.Hashes = [][sha256.Size]byte{peHash(t, c.GrubPE)}
	c.GrubPE = append([]byte{}, c.GrubPE...)
	if got, err := k.Check(c); err != nil || !strings.Contains(got, "grubx64.efi trusted by its hash in MokListRT") {
		t.Errorf("MokListRT by hash: %q, %v", got, err)
	}
}

// The Authenticode hash leaves out CheckSum, the certificate table entry
// and the table itself, and covers everything else in file order.
func TestAuthenticodeHash(t *testing.T) {
	p := newPKI(t)
	img := signed(t, p.distro)
	const opt = 64 + 4 + 20
	certs := len(winCerts(pkcs7(t, p.distro.cert, p.distro.cert)))
	var want []byte
	want = append(want, img[:opt+64]...)
	want = append(want, img[opt+68:opt+112+32]...)
	want = append(want, img[opt+112+40:len(img)-certs]...)
	if got := peHash(t, img); got != sha256.Sum256(want) {
		t.Errorf("hash %x, want %x", got, sha256.Sum256(want))
	}
	other := append([]byte{}, img...)
	copy(other[opt+64:], []byte{1, 2, 3, 4})
	other[len(other)-1] ^= 0xff
	if peHash(t, other) != peHash(t, img) {
		t.Error("CheckSum and the certificate table must not count")
	}
	// The one section's data follows the headers and its section header.
	other[opt+240+40] ^= 0xff
	if peHash(t, other) == peHash(t, img) {
		t.Error("the section data must count")
	}
}

// Sections are hashed in file order, whatever order their headers are in,
// and what follows them up to the certificate table counts too.
func TestAuthenticodeHashTakesSectionsInFileOrder(t *testing.T) {
	peReverse = true
	t.Cleanup(func() { peReverse = false })
	p := newPKI(t)
	certs := winCerts(pkcs7(t, p.distro.cert, p.distro.cert))
	img := buildPE(t, certs, section{".a", []byte("first...")}, section{".b", []byte("second..")})
	const opt = 64 + 4 + 20
	headers := uint32(opt + 240 + 2*40)
	if binary.LittleEndian.Uint32(img[opt+240+12+8:]) != headers+8 {
		t.Fatal("the first section header must describe the second section")
	}
	var want []byte
	want = append(want, img[:opt+64]...)
	want = append(want, img[opt+68:opt+112+32]...)
	want = append(want, img[opt+112+40:headers]...)
	want = append(want, "first..."...)
	want = append(want, "second.."...)
	// The COFF string table and padding sit between the sections and the
	// certificate table.
	want = append(want, img[headers+16:len(img)-len(certs)]...)
	if got := peHash(t, img); got != sha256.Sum256(want) {
		t.Errorf("hash %x, want %x", got, sha256.Sum256(want))
	}
}

func TestMoreDataDirectoriesThanPEReadsDoNotPanic(t *testing.T) {
	peDirs = 17
	t.Cleanup(func() { peDirs = 16 })
	p := newPKI(t)
	if _, err := p.keys().Check(Chain{Loader: "BOOTX64.EFI", LoaderPE: signed(t, p.shimSigner), KernelPE: signed(t, p.shimSigner)}); err != nil {
		t.Errorf("17 data directories: %v", err)
	}
}
