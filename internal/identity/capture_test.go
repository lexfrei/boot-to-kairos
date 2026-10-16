//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "etc/passwd", `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
alice:x:1001:1001::/home/alice:/bin/zsh
bob:x:1002:10::/home/bob:/bin/sh
broken line
`)
	write(t, root, "etc/group", "root:x:0:\nwheel:x:10:\nsudo:x:27:ubuntu,carol\nalice:x:1001:\nubuntu:x:1000:\n")
	write(t, root, "proc/sys/kernel/hostname", "web-1\n")
	write(t, root, "root/.ssh/authorized_keys", "# comment\n\n"+rootKey+"\n")
	write(t, root, "home/ubuntu/.ssh/authorized_keys", ubuntuKey+"\n")
	write(t, root, "home/ubuntu/.ssh/authorized_keys2", forced+"\n")
	write(t, root, "home/alice/.ssh/authorized_keys", ubuntuKey)
	write(t, root, "home/bob/.ssh/authorized_keys", rootKey+"\n")
	write(t, root, "etc/ssh/ssh_host_ed25519_key", string(private("ssh-ed25519")))
	write(t, root, "etc/ssh/ssh_host_ed25519_key.pub", line("ssh-ed25519", "root@web-1"))
	write(t, root, "etc/ssh/ssh_host_rsa_key", string(private("ssh-rsa")))
	return root
}

func noSudo(string) bool { return false }

func user(h *Host, name string) *User {
	for i := range h.Users {
		if h.Users[i].Name == name {
			return &h.Users[i]
		}
	}
	return nil
}

func TestCaptureDefaults(t *testing.T) {
	root := fakeRoot(t)
	h, err := Capture(root, func() ([]byte, error) { return nil, errBoom }, func(name string) bool { return name == "alice" })
	if err != nil {
		t.Fatal(err)
	}
	if h.Hostname != "web-1" {
		t.Errorf("hostname = %q", h.Hostname)
	}
	for name, want := range map[string][]string{"root": {rootKey}, "ubuntu": {ubuntuKey, forced}, "alice": {ubuntuKey}, "bob": {rootKey}} {
		u := user(h, name)
		if u == nil || !slices.Equal(u.Lines, want) {
			t.Errorf("%s = %+v, want lines %v", name, u, want)
		}
	}
	if u := user(h, "daemon"); u != nil {
		t.Errorf("daemon = %+v: no keys, nothing to carry", u)
	}
	for name, admin := range map[string]bool{"root": false, "ubuntu": true, "alice": true, "bob": true} {
		if u := user(h, name); u != nil && u.Admin != admin {
			t.Errorf("%s admin = %v, want %v", name, u.Admin, admin)
		}
	}
	if u := user(h, "ubuntu"); u.UID != 1000 || u.Shell != "/bin/bash" {
		t.Errorf("ubuntu = %+v", u)
	}
	if len(h.HostKeys) != 2 || h.HostKeys[0].Path != "/etc/ssh/ssh_host_rsa_key" || h.HostKeys[0].Public != nil ||
		h.HostKeys[1].Path != "/etc/ssh/ssh_host_ed25519_key" || h.HostKeys[1].Public == nil {
		t.Errorf("host keys = %+v", h.HostKeys)
	}
	if !slices.ContainsFunc(h.Notes, func(n string) bool { return strings.Contains(n, "sshd -T") }) {
		t.Errorf("notes = %v, want the fallback named", h.Notes)
	}
}

func TestCaptureFollowsTheHostsSSHD(t *testing.T) {
	root := fakeRoot(t)
	write(t, root, "etc/ssh/keys/alice", rootKey)
	write(t, root, "etc/ssh/keys/1000%x", ubuntuKey)
	write(t, root, "srv/hk", string(private("ssh-ed25519")))
	write(t, root, "srv/hk.pub", line("ssh-ed25519", ""))
	write(t, root, "home/bob/extra/keys", ubuntuKey)
	sshd := "port 22\nauthorizedkeysfile /etc/ssh/keys/%u /etc/ssh/keys/%U%%x .ssh/authorized_keys2 /x/%Z %h/extra/keys\n" +
		"authorizedkeyscommand /usr/bin/fetch %u\nhostkey /srv/hk\n"
	h, err := Capture(root, func() ([]byte, error) { return []byte(sshd), nil }, noSudo)
	if err != nil {
		t.Fatal(err)
	}
	if u := user(h, "alice"); u == nil || !slices.Equal(u.Lines, []string{rootKey}) {
		t.Errorf("alice = %+v", u)
	}
	if u := user(h, "ubuntu"); u == nil || !slices.Equal(u.Lines, []string{ubuntuKey, forced}) {
		t.Errorf("ubuntu = %+v", u)
	}
	if u := user(h, "bob"); u == nil || !slices.Equal(u.Lines, []string{ubuntuKey}) {
		t.Errorf("bob = %+v", u)
	}
	if user(h, "root") != nil {
		t.Errorf("root carried from a file sshd does not read")
	}
	if h.KeysCommand != "/usr/bin/fetch %u" {
		t.Errorf("keys command = %q", h.KeysCommand)
	}
	if len(h.HostKeys) != 1 || h.HostKeys[0].Path != "/srv/hk" {
		t.Errorf("host keys = %+v", h.HostKeys)
	}
	if !slices.ContainsFunc(h.Notes, func(n string) bool { return strings.Contains(n, "%Z") }) {
		t.Errorf("notes = %v, want the unknown token named", h.Notes)
	}
}

func TestCaptureNoneCommand(t *testing.T) {
	h, err := Capture(fakeRoot(t), func() ([]byte, error) { return []byte("authorizedkeyscommand none\n"), nil }, noSudo)
	if err != nil || h.KeysCommand != "" {
		t.Errorf("keys command = %q, %v", h.KeysCommand, err)
	}
}

func TestCaptureNeedsPasswd(t *testing.T) {
	if _, err := Capture(t.TempDir(), func() ([]byte, error) { return nil, errBoom }, noSudo); err == nil {
		t.Error("no error without /etc/passwd")
	}
}

func TestClashes(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/group", "root:x:0:\ndocker:x:999:\nkairos:x:1000:\n")
	write(t, root, "etc/passwd", "root:x:0:0::/root:/bin/sh\nlxd:x:998:998::/:/bin/false\nkairos:x:1000:1000::/home/kairos:/bin/bash\n")
	h := &Host{Users: []User{
		{Name: "kairos", UID: 1003, Shell: "/bin/bash", Admin: true, Lines: []string{ubuntuKey}},
		{Name: "docker", UID: 1000, Shell: "/bin/bash", Admin: true, Lines: []string{ubuntuKey}},
		{Name: "lxd", UID: 1001, Shell: "/bin/bash", Lines: []string{ubuntuKey}},
		{Name: "ubuntu", UID: 1002, Shell: "/bin/bash", Lines: []string{ubuntuKey}},
	}}
	out, _, err := Carry([]byte("#cloud-config\nstages:\n  initramfs:\n    - name: mine\n      users:\n        root: {}\n"), func() (*Host, error) { return h, nil }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Clashes(out, root)
	if err != nil || !slices.Equal(got, []string{"docker", "lxd"}) {
		t.Errorf("clashes = %v, %v: the cloud-config's own root is not ours to refuse, and yip only adds keys to an existing kairos", got, err)
	}
	// A group named kairos without the user is written over by the new
	// user's primary group.
	write(t, root, "etc/passwd", "root:x:0:0::/root:/bin/sh\n")
	if got, err := Clashes(out, root); err != nil || !slices.Equal(got, []string{"docker", "kairos"}) {
		t.Errorf("clashes = %v, %v with a kairos group alone", got, err)
	}
	if got, err := Clashes([]byte("#cloud-config\n"), root); err != nil || len(got) != 0 {
		t.Errorf("clashes without a carried user = %v, %v", got, err)
	}
}
