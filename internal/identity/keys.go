package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/url"
	"strings"

	"github.com/cockroachdb/errors"
)

// acceptedTypes are the key types the sshd of Kairos v4.3 accepts in
// authorized_keys: OpenSSH 10 with its default PubkeyAcceptedAlgorithms,
// under which an RSA key signs with rsa-sha2. DSA is gone from OpenSSH 10.
var acceptedTypes = map[string]bool{ //nolint:gochecknoglobals // fixed table
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

type keyLine struct {
	line, typ, blob string
	// command is set when the line forces a command, which makes it no
	// way to log in.
	command bool
}

// parseKeyLine reads one authorized_keys line: options, key type, base64
// blob and comment, as sshd(8) describes them.
func parseKeyLine(s string) (keyLine, error) {
	s = strings.TrimSpace(s)
	if err := literal(s); err != nil {
		return keyLine{}, err
	}
	// yip fetches a key that parses as a URL instead of writing it.
	if u, err := url.Parse(s); err == nil && u.Scheme != "" {
		return keyLine{}, errors.New("it reads as a URL, which Kairos would fetch")
	}
	k := keyLine{line: s}
	rest := s
	if f := strings.Fields(s); len(f) > 0 && !looksLikeType(f[0]) {
		opts, after, ok := splitOptions(s)
		if !ok {
			return keyLine{}, errors.New("not a key: unterminated quote in its options")
		}
		for _, o := range opts {
			if strings.HasPrefix(strings.ToLower(o), "command=") {
				k.command = true
			}
		}
		rest = after
	}
	f := strings.Fields(rest)
	if len(f) < 2 {
		return keyLine{}, errors.New("not a key: no key after the type")
	}
	k.typ, k.blob = f[0], f[1]
	if !blobOfType(k.blob, k.typ) {
		return keyLine{}, errors.Newf("not a key: the %s blob does not decode as one", k.typ)
	}
	if !acceptedTypes[k.typ] {
		return keyLine{}, errors.Newf("Kairos's sshd does not accept %s keys", k.typ)
	}
	return k, nil
}

// literal refuses what yip would render as a Go template.
func literal(s string) error {
	if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
		return errors.New("it contains {{ or }}, which yip renders as a template in files, commands and conditions")
	}
	return nil
}

func looksLikeType(s string) bool {
	return acceptedTypes[s] || strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
}

// splitOptions splits the comma-separated options at the start of s from
// the rest of the line. Commas and blanks inside double quotes, where \"
// escapes a quote, belong to the option.
func splitOptions(s string) (opts []string, rest string, ok bool) {
	quoted, start := false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quoted && c == '\\' && i+1 < len(s):
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && c == ',':
			opts = append(opts, s[start:i])
			start = i + 1
		case !quoted && (c == ' ' || c == '\t'):
			return append(opts, s[start:i]), s[i:], true
		}
	}
	return nil, "", false
}

// blobOfType checks that b is base64 of a key blob that names typ first.
func blobOfType(b, typ string) bool {
	raw, err := base64.StdEncoding.DecodeString(b)
	if err != nil || len(raw) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(raw)
	return uint64(n) == uint64(len(typ)) && len(raw) >= 4+len(typ) && string(raw[4:4+len(typ)]) == typ
}

// fingerprint is what ssh-keygen -l prints for the base64 blob b.
func fingerprint(b string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return "", errors.Wrap(err, "decode key")
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}
