package secureboot

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/cockroachdb/errors"
)

// peImage is a PE file with the offsets the Authenticode hash skips.
type peImage struct {
	data []byte
	file *pe.File
	// checksum and certDir are the file offsets of the CheckSum field and
	// of the certificate table's data directory entry.
	checksum, certDir, headers uint64
	// certs is the certificate table: a file offset and a size.
	certs pe.DataDirectory
}

func parsePE(data []byte) (*peImage, error) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, errors.Wrap(err, "not a PE image")
	}
	// pe.NewFile has read the DOS header and found the optional header.
	opt := uint64(binary.LittleEndian.Uint32(data[0x3c:])) + 4 + 20
	p := &peImage{data: data, file: f, checksum: opt + 64}
	var dirs []pe.DataDirectory
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		p.certDir, p.headers = opt+112, uint64(h.SizeOfHeaders)
		// pe.NewFile keeps NumberOfRvaAndSizes as the file says, which may
		// exceed the 16 entries it reads.
		dirs = h.DataDirectory[:min(h.NumberOfRvaAndSizes, uint32(len(h.DataDirectory)))]
	case *pe.OptionalHeader32:
		p.certDir, p.headers = opt+96, uint64(h.SizeOfHeaders)
		dirs = h.DataDirectory[:min(h.NumberOfRvaAndSizes, uint32(len(h.DataDirectory)))]
	default:
		return nil, errors.New("PE image without an optional header")
	}
	p.certDir += 8 * pe.IMAGE_DIRECTORY_ENTRY_SECURITY
	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
		p.certs = dirs[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	}
	if end := uint64(p.certs.VirtualAddress) + uint64(p.certs.Size); end > uint64(len(data)) {
		return nil, errors.Newf("certificate table ends at %d, past the image's %d bytes", end, len(data))
	}
	if p.certDir+8 > p.headers || p.headers > uint64(len(data)) {
		return nil, errors.Newf("headers of %d bytes in an image of %d", p.headers, len(data))
	}
	return p, nil
}

// hash is the SHA-256 Authenticode hash, as db and dbx list binaries by it
// (Windows Authenticode PE Signature Format, "Calculating the PE Image
// Hash"): the headers without CheckSum and the certificate table entry,
// the sections in file order, then what follows them but the certificate
// table.
func (p *peImage) hash() ([sha256.Size]byte, error) {
	h := sha256.New()
	d := p.data
	h.Write(d[:p.checksum])
	h.Write(d[p.checksum+4 : p.certDir])
	h.Write(d[p.certDir+8 : p.headers])
	secs := slices.Clone(p.file.Sections)
	slices.SortFunc(secs, func(a, b *pe.Section) int { return cmp.Compare(a.Offset, b.Offset) })
	sum := p.headers
	for _, s := range secs {
		if s.Size == 0 {
			continue
		}
		end := uint64(s.Offset) + uint64(s.Size)
		if end > uint64(len(d)) {
			return [sha256.Size]byte{}, errors.Newf("section %s ends at %d, past the image's %d bytes", s.Name, end, len(d))
		}
		h.Write(d[s.Offset:end])
		sum += uint64(s.Size)
	}
	end := uint64(len(d))
	if p.certs.Size > 0 {
		end = uint64(p.certs.VirtualAddress)
	}
	if end > sum {
		h.Write(d[sum:end])
	}
	return [sha256.Size]byte(h.Sum(nil)), nil
}

// signatures returns, for each Authenticode signature of the image, its
// signer followed by the certificates the signature embeds above it.
func (p *peImage) signatures() ([][]*x509.Certificate, error) {
	// The security directory holds a file offset, not an RVA.
	t := p.data[p.certs.VirtualAddress : uint64(p.certs.VirtualAddress)+uint64(p.certs.Size)]
	var sigs [][]*x509.Certificate
	for len(t) >= 8 {
		n := uint64(binary.LittleEndian.Uint32(t))
		if n < 8 || n > uint64(len(t)) {
			return nil, errors.Newf("WIN_CERTIFICATE of %d bytes in %d", n, len(t))
		}
		// WIN_CERT_TYPE_PKCS_SIGNED_DATA
		if binary.LittleEndian.Uint16(t[6:]) == 2 {
			path, err := signerPath(t[8:n])
			if err != nil {
				return nil, err
			}
			sigs = append(sigs, path)
		}
		t = t[min((n+7)&^7, uint64(len(t))):]
	}
	return sigs, nil
}

// signerPath parses PKCS#7 SignedData (RFC 2315, 9.1): the signer, then each
// embedded certificate that signed the one before it.
func signerPath(der []byte) ([]*x509.Certificate, error) {
	var ci struct {
		Type asn1.ObjectIdentifier
		// [0] EXPLICIT, which a RawValue keeps: the SignedData is inside.
		Content asn1.RawValue
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, errors.Wrap(err, "PKCS#7 content info")
	}
	if !ci.Type.Equal(oidSignedData) || ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 {
		return nil, errors.Newf("PKCS#7 content type %v", ci.Type)
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		CRLs             asn1.RawValue `asn1:"optional,tag:1"`
		SignerInfos      []struct {
			Version int
			IAS     struct {
				Issuer asn1.RawValue
				Serial *big.Int
			}
		} `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, errors.Wrap(err, "PKCS#7 signed data")
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "PKCS#7 certificates")
	}
	if len(sd.SignerInfos) != 1 {
		return nil, errors.Newf("%d signer infos, Authenticode has one", len(sd.SignerInfos))
	}
	ias := sd.SignerInfos[0].IAS
	var path []*x509.Certificate
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			path = append(path, c)
			break
		}
	}
	if path == nil {
		return nil, errors.New("PKCS#7 signer certificate is not embedded")
	}
	for len(path) <= len(certs) {
		last := path[len(path)-1]
		var next *x509.Certificate
		for _, c := range certs {
			if !bytes.Equal(c.Raw, last.Raw) && signs(c, last) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		path = append(path, next)
	}
	return path, nil
}

// vendorCerts reads shim's .vendor_cert section: what shim trusts besides db
// and MOK, as one DER certificate or a signature list, and the list it
// revokes. isShim is false without the section.
func (p *peImage) vendorCerts() (vendor, deauth Sigs, isShim bool, err error) {
	s := p.file.Section(".vendor_cert")
	if s == nil {
		return Sigs{}, Sigs{}, false, nil
	}
	b, err := s.Data()
	if err != nil {
		return Sigs{}, Sigs{}, true, errors.Wrap(err, "read .vendor_cert")
	}
	if len(b) < 16 {
		return Sigs{}, Sigs{}, true, errors.Newf(".vendor_cert of %d bytes", len(b))
	}
	part := func(size, off uint32) ([]byte, error) {
		if uint64(off)+uint64(size) > uint64(len(b)) {
			return nil, errors.Newf(".vendor_cert entry at %d of %d bytes, in %d", off, size, len(b))
		}
		return b[off : off+size], nil
	}
	le := binary.LittleEndian
	auth, err := part(le.Uint32(b), le.Uint32(b[8:]))
	if err != nil {
		return Sigs{}, Sigs{}, true, err
	}
	de, err := part(le.Uint32(b[4:]), le.Uint32(b[12:]))
	if err != nil {
		return Sigs{}, Sigs{}, true, err
	}
	if len(auth) > 0 {
		if c, cerr := x509.ParseCertificate(auth); cerr == nil {
			vendor.Certs = []*x509.Certificate{c}
		} else if vendor, _, err = parseESL(auth, false); err != nil {
			return Sigs{}, Sigs{}, true, errors.Wrap(err, "shim vendor certificate")
		}
	}
	if deauth, _, err = parseESL(de, true); err != nil {
		return Sigs{}, Sigs{}, true, errors.Wrap(err, "shim deauthorized list")
	}
	return vendor, deauth, true, nil
}
