//go:build linux

package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/identity"
)

const (
	hostPub     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqBf/kk9HU/3TTpEf+1g2pfWs/ebgaHHdytZjPg102p"
	hostFP      = "SHA256:RNbX1SWLLtVp36zvLrV5U+HLXRs0F2ZukYzF5/QY60o"
	hostPrivate = "-----BEGIN OPENSSH PRIVATE KEY-----\nTHE-HOST-PRIVATE-KEY\n-----END OPENSSH PRIVATE KEY-----\n"
	forcedKey   = `command="echo 'Please login as the user \"ubuntu\"';exit 142" ` + hostPub
)

func identityHost(users ...identity.User) func(context.Context) (*identity.Host, error) {
	return func(context.Context) (*identity.Host, error) {
		return &identity.Host{
			Hostname: "web-1",
			Users:    users,
			HostKeys: []identity.HostKey{{Path: "/etc/ssh/ssh_host_ed25519_key", Private: []byte(hostPrivate), Public: []byte(hostPub + " root@web-1\n")}},
		}, nil
	}
}

var ubuntuUser = identity.User{Name: "ubuntu", UID: 1000, Shell: "/bin/bash", Admin: true, Lines: []string{hostPub + " lex@laptop"}}

// captureLog collects what is logged until the test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	w := log.Writer()
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(w) })
	return &b
}

func TestDryRunPrintsTheCarriedIdentity(t *testing.T) {
	stubMachine(t)
	captureIdentity = identityHost(ubuntuUser, identity.User{Name: "root", Shell: "/bin/bash", Lines: []string{forcedKey}})
	logged := captureLog(t)
	var out bytes.Buffer
	o := Options{Disk: "/dev/vda", DryRun: true, KeepIdentity: true}
	if err := proceed(context.Background(), o, []byte("#cloud-config\n"), &Plan{}, strings.NewReader(""), &out, new(bool)); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	for _, want := range []string{"THE-HOST-PRIVATE-KEY", "lex@laptop", "web-1", "lock_passwd: true"} {
		if !strings.Contains(string(builtConfig), want) {
			t.Errorf("the build got no %q:\n%s", want, builtConfig)
		}
	}
	for _, re := range []string{
		`(?m)^  hostname: +web-1$`,
		`(?m)^  SSH host keys: +ed25519 ` + regexp.QuoteMeta(hostFP) + `$`,
		`(?m)^  SSH users: +ubuntu \(admin, 1 key\)$`,
		`(?m)^  identity not carried: +root: Kairos refuses root logins, and an admin user above logs in$`,
	} {
		if !regexp.MustCompile(re).MatchString(out.String()) {
			t.Errorf("summary does not match %s:\n%s", re, out.String())
		}
	}
	var rep bytes.Buffer
	o.Output = OutputJSON
	plan := &Plan{}
	err := proceed(context.Background(), o, []byte("#cloud-config\n"), plan, strings.NewReader(""), io.Discard, new(bool))
	report(&rep, o, plan, err, false)
	if !strings.Contains(rep.String(), `{"name":"SSH host keys","values":["ed25519 `+hostFP+`"]}`) {
		t.Errorf("report = %s", rep.String())
	}
	for what, s := range map[string]string{"plan": out.String(), "report": rep.String(), "log": logged.String()} {
		if strings.Contains(s, "THE-HOST-PRIVATE-KEY") {
			t.Errorf("the %s carries the host's private key:\n%s", what, s)
		}
	}
}

func TestDryRunCarriesRootsKeysOntoKairos(t *testing.T) {
	stubMachine(t)
	captureIdentity = identityHost(identity.User{Name: "root", Shell: "/bin/bash", Lines: []string{hostPub}})
	var out bytes.Buffer
	o := Options{Disk: "/dev/vda", DryRun: true, KeepIdentity: true}
	if err := proceed(context.Background(), o, []byte("#cloud-config\n"), &Plan{}, strings.NewReader(""), &out, new(bool)); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	if re := `(?m)^  root's SSH keys: +carried to kairos, as Kairos refuses root logins$`; !regexp.MustCompile(re).MatchString(out.String()) {
		t.Errorf("summary does not match %s:\n%s", re, out.String())
	}
}

func TestDryRunSaysWhenNoHostKeyIsCarried(t *testing.T) {
	stubMachine(t)
	captureIdentity = func(context.Context) (*identity.Host, error) {
		return &identity.Host{Users: []identity.User{ubuntuUser}}, nil
	}
	var out bytes.Buffer
	o := Options{Disk: "/dev/vda", DryRun: true, KeepIdentity: true}
	if err := proceed(context.Background(), o, []byte("#cloud-config\n"), &Plan{}, strings.NewReader(""), &out, new(bool)); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	for _, re := range []string{`(?m)^  SSH host keys: +not carried: this system has none Kairos can use$`, `(?m)^  hostname: +not carried: this system has none$`} {
		if !regexp.MustCompile(re).MatchString(out.String()) {
			t.Errorf("summary does not match %s:\n%s", re, out.String())
		}
	}
}

func TestNoCloudConfigNeedsACarriedLogin(t *testing.T) {
	for name, tc := range map[string]struct {
		users  []identity.User
		config string
		want   error
	}{
		"only root's forced command": {[]identity.User{{Name: "root", Shell: "/bin/bash", Lines: []string{forcedKey}}}, "", identity.ErrNoLogin},
		"a user without admin":       {[]identity.User{{Name: "alice", UID: 1001, Shell: "/bin/bash", Lines: []string{hostPub}}}, "", identity.ErrNoLogin},
		"ubuntu":                     {[]identity.User{ubuntuUser}, "", nil},
		"a cloud-config of its own":  {nil, "cfg.yaml", nil},
	} {
		t.Run(name, func(t *testing.T) {
			calls := stubMachine(t)
			captureIdentity = identityHost(tc.users...)
			o := Options{Disk: "/dev/vda", DryRun: true, KeepIdentity: true, ConfigPath: tc.config}
			err := proceed(context.Background(), o, []byte("#cloud-config\n"), &Plan{}, strings.NewReader(""), io.Discard, new(bool))
			if !errors.Is(err, tc.want) {
				t.Fatalf("proceed = %v, want %v", err, tc.want)
			}
			if tc.want != nil && (slices.Contains(*calls, "build") || errorClass(err) != "no-login" || !strings.Contains(err.Error(), "--cloud-config")) {
				t.Errorf("proceed = %v (class %s) after %v, want the refusal before the build", err, errorClass(err), *calls)
			}
		})
	}
}

func TestDryRunSaysWhenTheIdentityIsNotCarried(t *testing.T) {
	calls := stubMachine(t)
	var out bytes.Buffer
	o := Options{Disk: "/dev/vda", DryRun: true, ConfigPath: "cfg.yaml"}
	if err := proceed(context.Background(), o, []byte(plainConfig), &Plan{}, strings.NewReader(""), &out, new(bool)); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	if re := `(?m)^  identity: +not carried \(--keep-identity=false\)$`; !regexp.MustCompile(re).MatchString(out.String()) {
		t.Errorf("summary does not match %s:\n%s", re, out.String())
	}
	if slices.Contains(*calls, "capture identity") || strings.Contains(string(builtConfig), "carried over from the replaced system") {
		t.Errorf("calls %v, config %q: nothing may be carried", *calls, builtConfig)
	}
}

func TestIdentityCaptureFailureStopsTheRun(t *testing.T) {
	calls := stubMachine(t)
	captureIdentity = func(context.Context) (*identity.Host, error) { return nil, unix.EPERM }
	o := Options{Disk: "/dev/vda", Yes: true, KeepIdentity: true}
	err := proceed(context.Background(), o, []byte(plainConfig), &Plan{}, strings.NewReader(""), io.Discard, new(bool))
	if err == nil || !strings.Contains(err.Error(), "--keep-identity=false") || slices.Contains(*calls, "build") {
		t.Fatalf("proceed = %v after %v", err, *calls)
	}
}
