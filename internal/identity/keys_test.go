package identity

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// blob is a well-formed public key blob of type typ.
func blob(typ string) string {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(typ)))
	b = append(b, typ...)
	b = append(b, "key material of "+typ...)
	return base64.StdEncoding.EncodeToString(b)
}

func line(typ, comment string) string { return typ + " " + blob(typ) + " " + comment }

func TestParseKeyLine(t *testing.T) {
	ed := line("ssh-ed25519", "me@example.com")
	for _, tc := range []struct {
		in      string
		typ     string
		command bool
	}{
		{ed, "ssh-ed25519", false},
		{line("ssh-rsa", ""), "ssh-rsa", false},
		{line("ecdsa-sha2-nistp384", "x"), "ecdsa-sha2-nistp384", false},
		{line("sk-ssh-ed25519@openssh.com", "yubikey"), "sk-ssh-ed25519@openssh.com", false},
		{`from="192.0.2.0/24",no-pty ` + ed, "ssh-ed25519", false},
		{`command="echo 'a b, c' ; exit 142",no-port-forwarding ` + ed, "ssh-ed25519", true},
		{`no-pty,COMMAND="/bin/backup" ` + ed, "ssh-ed25519", true},
		{`environment="X=a\" b" ` + ed, "ssh-ed25519", false},
		{`cert-authority,principals="a,b" ` + ed, "ssh-ed25519", false},
		{`from="192.0.2.1,command=x" ` + ed, "ssh-ed25519", false},
		{"\t" + ed + "  ", "ssh-ed25519", false},
	} {
		k, err := parseKeyLine(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if k.typ != tc.typ || k.command != tc.command {
			t.Errorf("%q: type %q command %v, want %q %v", tc.in, k.typ, k.command, tc.typ, tc.command)
		}
		if k.line != strings.TrimSpace(tc.in) {
			t.Errorf("%q: line = %q, want it verbatim", tc.in, k.line)
		}
	}
}

func TestParseKeyLineRefuses(t *testing.T) {
	ed := line("ssh-ed25519", "")
	for in, why := range map[string]string{
		line("ssh-dss", "old"):                          "ssh-dss",
		line("ssh-foo", ""):                             "ssh-foo",
		"ssh-ed25519 !!!notbase64":                      "not a key",
		"ssh-ed25519 " + blob("ssh-rsa"):                "not a key",
		"ssh-ed25519":                                   "not a key",
		`command="unterminated ` + ed:                   "unterminated quote",
		"ssh-ed25519 " + blob("ssh-ed25518"):            "not a key",
		"https://example.com/keys":                      "URL",
		"github:someone":                                "URL",
		`command="{{ .Values.x }}" ` + ed:               "template",
		line("ssh-ed25519", "}} braces"):                "template",
		`from="x" ssh-ed25519 ` + blob("ssh-ed25519"):   "",
		"ssh-ed25519 " + blob("ssh-ed25519") + " a b c": "",
	} {
		_, err := parseKeyLine(in)
		if why == "" {
			if err != nil {
				t.Errorf("%q: %v", in, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: error %v, want one naming %q", in, err, why)
		}
	}
}

func TestFingerprint(t *testing.T) {
	// ssh-keygen -l prints this for the blob below.
	b := "AAAAC3NzaC1lZDI1NTE5AAAAIJqBf/kk9HU/3TTpEf+1g2pfWs/ebgaHHdytZjPg102p"
	got, err := fingerprint(b)
	if err != nil || got != "SHA256:RNbX1SWLLtVp36zvLrV5U+HLXRs0F2ZukYzF5/QY60o" {
		t.Errorf("fingerprint = %q, %v", got, err)
	}
}
