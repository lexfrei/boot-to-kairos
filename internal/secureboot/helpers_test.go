package secureboot

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"
)

type key struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

var serial int64

// newKey makes a certificate for cn, signed by parent, or self-signed when
// parent is nil.
func newKey(t *testing.T, cn string, parent *key, ca bool) *key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	issuer, signer := tmpl, crypto.Signer(priv)
	if parent != nil {
		issuer, signer = parent.cert, parent.signer
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, priv.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &key{cert: c, signer: priv}
}

// pkcs7 encodes a SignedData with the given signer and embedded certs. No
// digest or signature: the check does not verify those.
func pkcs7(t *testing.T, signer *x509.Certificate, certs ...*x509.Certificate) []byte {
	t.Helper()
	return pkcs7Signers(t, 1, signer, certs...)
}

// pkcs7Signers is pkcs7 with n signer infos, all naming signer.
func pkcs7Signers(t *testing.T, n int, signer *x509.Certificate, certs ...*x509.Certificate) []byte {
	t.Helper()
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	type issuerAndSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	type signerInfo struct {
		Version int
		IAS     issuerAndSerial
	}
	type contentInfo struct {
		Type asn1.ObjectIdentifier
	}
	sd := struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      contentInfo
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      []signerInfo  `asn1:"set"`
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		ContentInfo:      contentInfo{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
	}
	for range n {
		sd.SignerInfos = append(sd.SignerInfos, signerInfo{
			Version: 1,
			IAS:     issuerAndSerial{Issuer: asn1.RawValue{FullBytes: signer.RawIssuer}, Serial: signer.SerialNumber},
		})
	}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// winCerts lays out WIN_CERTIFICATE entries, each padded to 8 bytes.
func winCerts(sigs ...[]byte) []byte {
	var b []byte
	for _, s := range sigs {
		b = binary.LittleEndian.AppendUint32(b, uint32(8+len(s)))
		b = binary.LittleEndian.AppendUint16(b, 0x0200)
		b = binary.LittleEndian.AppendUint16(b, 0x0002)
		b = append(b, s...)
		for len(b)%8 != 0 {
			b = append(b, 0)
		}
	}
	return b
}

type section struct {
	name string
	data []byte
}

// buildPE makes a minimal PE32+ with the given sections and certificate
// table, which debug/pe parses like a real image.
// peDirs is the number of data directories buildPE writes, and
// peReverse makes it list the section headers last to first, with their
// data still in file order.
var (
	peDirs    uint32 = 16
	peReverse bool
)

func buildPE(t *testing.T, certs []byte, sections ...section) []byte {
	t.Helper()
	optSize := 112 + 8*peDirs
	off := 64 + 4 + 20 + optSize + uint32(40*len(sections))
	var hdrs []pe.SectionHeader32
	var body []byte
	// Names longer than 8 bytes go to the COFF string table as "/offset",
	// as linkers write .vendor_cert.
	strtab := []byte{0, 0, 0, 0}
	for i, s := range sections {
		var h pe.SectionHeader32
		if len(s.name) > 8 {
			copy(h.Name[:], fmt.Sprintf("/%d", len(strtab)))
			strtab = append(append(strtab, s.name...), 0)
		} else {
			copy(h.Name[:], s.name)
		}
		h.VirtualSize = uint32(len(s.data))
		h.VirtualAddress = uint32(0x1000 * (i + 1))
		h.SizeOfRawData = uint32(len(s.data))
		h.PointerToRawData = off + uint32(len(body))
		hdrs = append(hdrs, h)
		body = append(body, s.data...)
	}
	symtab := off + uint32(len(body))
	binary.LittleEndian.PutUint32(strtab, uint32(len(strtab)))
	body = append(body, strtab...)
	for (int(off)+len(body))%8 != 0 {
		body = append(body, 0)
	}
	var opt pe.OptionalHeader64
	opt.Magic = 0x20b
	opt.NumberOfRvaAndSizes = peDirs
	opt.SizeOfHeaders = off
	if len(certs) > 0 {
		opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY] = pe.DataDirectory{
			VirtualAddress: off + uint32(len(body)),
			Size:           uint32(len(certs)),
		}
	}
	var buf bytes.Buffer
	dos := make([]byte, 64)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 64)
	buf.Write(dos)
	buf.WriteString("PE\x00\x00")
	w := func(v any) {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	w(pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, PointerToSymbolTable: symtab, NumberOfSections: uint16(len(sections)), SizeOfOptionalHeader: uint16(optSize), Characteristics: 0x22})
	var ob bytes.Buffer
	if err := binary.Write(&ob, binary.LittleEndian, opt); err != nil {
		t.Fatal(err)
	}
	buf.Write(ob.Bytes()[:112])
	for i := range peDirs {
		var d pe.DataDirectory
		if i < 16 {
			d = opt.DataDirectory[i]
		}
		w(d)
	}
	if peReverse {
		slices.Reverse(hdrs)
	}
	for _, h := range hdrs {
		w(h)
	}
	buf.Write(body)
	buf.Write(certs)
	return buf.Bytes()
}

// signed is a PE signed by k, carrying k's chain up to (not including) the
// last certificate given.
func signed(t *testing.T, k *key, chain ...*x509.Certificate) []byte {
	t.Helper()
	return buildPE(t, winCerts(pkcs7(t, k.cert, append([]*x509.Certificate{k.cert}, chain...)...)), section{".text", []byte("code")})
}

// vendorSection is shim's .vendor_cert: four sizes and offsets, then the
// authorized certificate and the deauthorized list.
func vendorSection(auth, deauth []byte) section {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(len(auth)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(deauth)))
	b = binary.LittleEndian.AppendUint32(b, 16)
	b = binary.LittleEndian.AppendUint32(b, uint32(16+len(auth)))
	b = append(b, auth...)
	b = append(b, deauth...)
	return section{".vendor_cert", b}
}

// esl encodes one EFI_SIGNATURE_LIST of X.509 certificates.
func esl(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, sigList(certX509, c.Raw)...)
	}
	return out
}

func sigList(typ [16]byte, data ...[]byte) []byte {
	size := 16 + len(data[0])
	b := append([]byte{}, typ[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(28+size*len(data)))
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, uint32(size))
	for _, d := range data {
		b = append(b, make([]byte, 16)...)
		b = append(b, d...)
	}
	return b
}
