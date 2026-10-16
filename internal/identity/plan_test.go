//go:build linux

package identity

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/lexfrei/boot-to-kairos/internal/kairos"
)

var errBoom = errors.New("boom")

const secret = "PRIVATE-KEY-BYTES-THAT-MUST-NOT-LEAK"

func private(typ string) []byte {
	return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" + secret + typ + "\n-----END OPENSSH PRIVATE KEY-----\n")
}

func hostKey(typ, path string) HostKey {
	return HostKey{Path: path, Private: private(typ), Public: []byte(line(typ, "root@old-host") + "\n")}
}

var (
	ubuntuKey = line("ssh-ed25519", "lex@laptop")
	rootKey   = line("ssh-ed25519", "root@admin")
	forced    = `no-port-forwarding,command="echo 'Please login as the user \"ubuntu\" rather than the user \"root\".';echo;sleep 10;exit 142" ` + ubuntuKey
)

func ubuntuHost() *Host {
	return &Host{
		Hostname: "web-1",
		Users: []User{
			{Name: "root", UID: 0, Shell: "/bin/bash", Lines: []string{forced}},
			{Name: "ubuntu", UID: 1000, Shell: "/bin/bash", Admin: true, Lines: []string{ubuntuKey}},
		},
		HostKeys: []HostKey{
			hostKey("ssh-rsa", "/etc/ssh/ssh_host_rsa_key"),
			hostKey("ecdsa-sha2-nistp256", "/etc/ssh/ssh_host_ecdsa_key"),
			hostKey("ssh-ed25519", "/etc/ssh/ssh_host_ed25519_key"),
		},
	}
}

// yipStage is what the injected stages hold, as yip reads them.
type yipStage struct {
	Name  string `yaml:"name"`
	If    string `yaml:"if"`
	Files []struct {
		Path        string `yaml:"path"`
		Permissions uint32 `yaml:"permissions"`
		Owner       int    `yaml:"owner"`
		Group       int    `yaml:"group"`
		Content     string `yaml:"content"`
	} `yaml:"files"`
	Hostname string `yaml:"hostname"`
	Users    map[string]struct {
		Groups     []string `yaml:"groups"`
		LockPasswd bool     `yaml:"lock_passwd"` //nolint:tagliatelle // yip's key
		Shell      string   `yaml:"shell"`
		Passwd     *string  `yaml:"passwd"`
	} `yaml:"users"`
	AuthorizedKeys map[string][]string `yaml:"authorized_keys"` //nolint:tagliatelle // yip's key
}

type yipConfig struct {
	Stages map[string][]yipStage `yaml:"stages"`
}

func carry(t *testing.T, cfg string, h *Host) ([]byte, Carried, yipConfig, string) {
	t.Helper()
	var log strings.Builder
	out, c, err := Carry([]byte(cfg), func() (*Host, error) { return h, nil }, func(f string, a ...any) { fmt.Fprintf(&log, f+"\n", a...) })
	if err != nil {
		t.Fatal(err)
	}
	if err := kairos.CheckConfig(out); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	var y yipConfig
	if err := yaml.Unmarshal(out, &y); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	if strings.Contains(fmt.Sprint(c), secret) || strings.Contains(log.String(), secret) {
		t.Errorf("a private key reached the plan or the log:\n%+v\n%s", c, log.String())
	}
	return out, c, y, log.String()
}

func carried(t *testing.T, cfg string, h *Host) Carried {
	t.Helper()
	_, c, _, _ := carry(t, cfg, h) //nolint:dogsled // the plan alone
	return c
}

func dropped(c Carried, sub string) bool {
	return slices.ContainsFunc(c.Dropped, func(s string) bool { return strings.Contains(s, sub) })
}

func TestCarryUbuntuCloudImage(t *testing.T) {
	_, c, y, log := carry(t, "#cloud-config\n", ubuntuHost())
	if !c.Login || c.RootTo != "" {
		t.Errorf("login %v, root to %q: ubuntu logs in as admin, root's keys stay", c.Login, c.RootTo)
	}
	if !slices.Equal(c.Users, []string{"ubuntu (admin, 1 key)"}) {
		t.Errorf("users = %v", c.Users)
	}
	if !dropped(c, "root: Kairos refuses root logins") {
		t.Errorf("dropped = %v", c.Dropped)
	}
	if c.Hostname != "web-1" {
		t.Errorf("hostname = %q (%s)", c.Hostname, c.HostnameReason)
	}
	if len(c.HostKeys) != 3 || !strings.HasPrefix(c.HostKeys[0], "rsa SHA256:") || !strings.Contains(c.HostKeys[1], "ecdsa SHA256:") ||
		!strings.Contains(c.HostKeys[1], "not offered") || !strings.HasPrefix(c.HostKeys[2], "ed25519 SHA256:") {
		t.Errorf("host keys = %v", c.HostKeys)
	}
	if !strings.Contains(log, "ECDSA") {
		t.Errorf("log does not warn about ECDSA:\n%s", log)
	}

	before := y.Stages["initramfs.before"]
	if len(before) != 3 {
		t.Fatalf("initramfs.before = %+v", before)
	}
	for i, typ := range []string{"rsa", "ecdsa", "ed25519"} {
		s := before[i]
		key := "/etc/ssh/ssh_host_" + typ + "_key"
		if s.If != "[ ! -e "+key+" ]" {
			t.Errorf("%s: if = %q; a key Kairos already has must not be overwritten", typ, s.If)
		}
		if len(s.Files) != 2 || s.Files[0].Path != key || s.Files[0].Permissions != 0o600 || s.Files[0].Owner != 0 || s.Files[0].Group != 0 ||
			!strings.Contains(s.Files[0].Content, secret) || s.Files[1].Path != key+".pub" || s.Files[1].Permissions != 0o644 ||
			strings.Contains(s.Files[1].Content, "root@old-host") || !strings.HasSuffix(s.Files[1].Content, "\n") {
			t.Errorf("%s: files = %+v", typ, s.Files)
		}
	}
	main := y.Stages["initramfs"]
	if len(main) != 1 || main[0].Hostname != "web-1" {
		t.Fatalf("initramfs = %+v", main)
	}
	u := main[0].Users["ubuntu"]
	if len(main[0].Users) != 1 || !slices.Equal(u.Groups, []string{"admin"}) || !u.LockPasswd || u.Passwd != nil || u.Shell != "/bin/bash" {
		t.Errorf("users = %+v: a user without lock_passwd gets an empty password", main[0].Users)
	}
	if k := main[0].AuthorizedKeys; len(k) != 1 || !slices.Equal(k["ubuntu"], []string{ubuntuKey}) {
		t.Errorf("authorized_keys = %v", k)
	}
}

func TestCarryRootOnlyHostOntoKairos(t *testing.T) {
	h := &Host{Users: []User{{Name: "root", Shell: "/bin/bash", Lines: []string{rootKey, forced}}}}
	_, c, y, _ := carry(t, "", h)
	if !c.Login || !strings.Contains(c.RootTo, "kairos") {
		t.Errorf("login %v, root to %q", c.Login, c.RootTo)
	}
	main := y.Stages["initramfs"][0]
	if !slices.Equal(main.AuthorizedKeys["kairos"], []string{rootKey}) || !slices.Equal(main.Users["kairos"].Groups, []string{"admin"}) ||
		!main.Users["kairos"].LockPasswd || len(main.Users) != 1 || main.AuthorizedKeys["root"] != nil {
		t.Errorf("stage = %+v: root's plain key only, onto kairos", main)
	}
	if !dropped(c, "forced") {
		t.Errorf("dropped = %v, want the forced-command line named", c.Dropped)
	}
}

func TestCarryRootWhenNoAdminCanLogIn(t *testing.T) {
	for name, users := range map[string][]User{
		"admin with forced keys only": {{Name: "ops", UID: 1000, Shell: "/bin/sh", Admin: true, Lines: []string{forced}}},
		"no admin":                    {{Name: "alice", UID: 1001, Shell: "/bin/zsh", Lines: []string{ubuntuKey}}},
		"admin without a login shell": {{Name: "svc", UID: 1002, Shell: "/usr/sbin/nologin", Admin: true, Lines: []string{ubuntuKey}}},
	} {
		h := &Host{Users: append([]User{{Name: "root", Shell: "/bin/bash", Lines: []string{rootKey}}}, users...)}
		_, c, y, _ := carry(t, "", h)
		if !c.Login || c.RootTo == "" || !slices.Contains(y.Stages["initramfs"][0].AuthorizedKeys["kairos"], rootKey) {
			t.Errorf("%s: login %v, root to %q", name, c.Login, c.RootTo)
		}
	}
}

func TestCarryRootMergesIntoAHostKairosUser(t *testing.T) {
	h := &Host{Users: []User{
		{Name: "root", Shell: "/bin/bash", Lines: []string{rootKey}},
		{Name: "kairos", UID: 1000, Shell: "/bin/bash", Admin: true, Lines: []string{forced, rootKey}},
	}}
	_, c, y, _ := carry(t, "", h)
	s := y.Stages["initramfs"][0]
	if !slices.Equal(s.AuthorizedKeys["kairos"], []string{forced, rootKey}) || !slices.Equal(s.Users["kairos"].Groups, []string{"admin"}) {
		t.Errorf("stage = %+v", s)
	}
	if !slices.Equal(c.Users, []string{"kairos (admin, 2 keys)"}) || !c.Login {
		t.Errorf("users = %v, login %v", c.Users, c.Login)
	}
}

// The image's kairos is in admin before the carried stage runs, and yip
// leaves the groups of a user that exists alone: whatever lands on kairos
// gets sudo.
func TestCarryAHostKairosOnlyWithSudo(t *testing.T) {
	h := &Host{Users: []User{{Name: "kairos", UID: 1000, Shell: "/bin/bash", Lines: []string{ubuntuKey}}}}
	c := carried(t, "#cloud-config\n", h)
	if len(c.Users) != 0 || c.Login || !dropped(c, "kairos: ") {
		t.Errorf("carried %+v: a host kairos without sudo would get it", c)
	}
}

// yip gives a new user a primary group of its own name and writes its gid
// over a group of that name, admin's included.
func TestCarrySkipsTheImagesNames(t *testing.T) {
	var users []User
	for i, name := range []string{"admin", "wheel", "users", "kvm", "disk", "nogroup", "systemd-journal", "nobody"} {
		users = append(users, User{Name: name, UID: 1000 + i, Shell: "/bin/bash", Admin: true, Lines: []string{ubuntuKey}})
	}
	c := carried(t, "#cloud-config\n", &Host{Users: users})
	if len(c.Users) != 0 || c.Login {
		t.Errorf("users = %v", c.Users)
	}
	for _, u := range users {
		if !dropped(c, u.Name+": ") {
			t.Errorf("dropped = %v, want %s named", c.Dropped, u.Name)
		}
	}
}

func TestCarryOnlyFullShells(t *testing.T) {
	var users []User
	for i, sh := range []string{"/usr/bin/git-shell", "/bin/rbash", "/usr/bin/scponly", "/usr/bin/rssh", "/bin/bash", "/usr/bin/zsh", "/bin/sh", ""} {
		users = append(users, User{Name: fmt.Sprintf("u%d", i), UID: 1000 + i, Shell: sh, Lines: []string{ubuntuKey}})
	}
	c := carried(t, "", &Host{Users: users})
	if !slices.Equal(c.Users, []string{"u4 (1 key)", "u5 (1 key)", "u6 (1 key)", "u7 (1 key)"}) {
		t.Errorf("users = %v: a restricted shell must not become bash", c.Users)
	}
	if !dropped(c, "u0: ") || !dropped(c, "u1: ") {
		t.Errorf("dropped = %v", c.Dropped)
	}
}

// kairos-agent prints the whole configuration when debug is set, in the
// cloud-config or on the installed system's kernel command line, and
// immucore prints every stage under its own debug there.
func TestCarryNoHostKeysUnderDebug(t *testing.T) {
	for cfg, h := range map[string]*Host{
		"#cloud-config\ndebug: true\n": ubuntuHost(),
		"#cloud-config\ninstall:\n  grub_options:\n    extra_cmdline: console=ttyS0 rd.immucore.debug\n": ubuntuHost(),
		"#cloud-config\ninstall:\n  grub_options:\n    extra_active_cmdline: rd.kairos.debug\n":          ubuntuHost(),
	} {
		_, c, y, _ := carry(t, cfg, h)
		if len(c.HostKeys) != 0 || !strings.Contains(c.HostKeysReason, "debug") || len(y.Stages["initramfs.before"]) != 0 {
			t.Errorf("%q: carried %+v", cfg, c)
		}
	}
}

func TestCarryNoWayIn(t *testing.T) {
	h := &Host{Users: []User{
		{Name: "root", Shell: "/bin/bash", Lines: []string{forced}},
		{Name: "alice", UID: 1001, Shell: "/bin/bash", Lines: []string{ubuntuKey}},
	}}
	_, c, y, _ := carry(t, "", h)
	if c.Login {
		t.Errorf("login = true for %+v", c)
	}
	if !slices.Equal(c.Users, []string{"alice (1 key)"}) {
		t.Errorf("users = %v", c.Users)
	}
	if g := y.Stages["initramfs"][0].Users["alice"].Groups; len(g) != 0 {
		t.Errorf("alice's groups = %v: she had no sudo", g)
	}
}

func TestCarrySkipsUsers(t *testing.T) {
	h := &Host{Users: []User{
		{Name: "ubuntu", UID: 1000, Shell: "/bin/bash", Admin: true, Lines: []string{ubuntuKey}},
		{Name: "svc", UID: 999, Shell: "/usr/sbin/nologin", Lines: []string{ubuntuKey}},
		{Name: "off", UID: 998, Shell: "/bin/false", Lines: []string{ubuntuKey}},
		{Name: "Bad.Name", UID: 1001, Shell: "/bin/bash", Lines: []string{ubuntuKey}},
		{Name: "messagebus", UID: 1002, Shell: "/bin/bash", Lines: []string{ubuntuKey}},
		{Name: "systemd-network", UID: 1003, Shell: "/bin/bash", Lines: []string{ubuntuKey}},
		{Name: "nokeys", UID: 1004, Shell: "/bin/bash"},
		{Name: "old", UID: 1005, Shell: "/bin/bash", Lines: []string{line("ssh-dss", ""), ubuntuKey, ubuntuKey}},
		{Name: "shell", UID: 1006, Shell: "", Lines: []string{ubuntuKey}},
	}}
	_, c, y, _ := carry(t, "", h)
	if !slices.Equal(c.Users, []string{"ubuntu (admin, 1 key)", "old (1 key)", "shell (1 key)"}) {
		t.Errorf("users = %v", c.Users)
	}
	for _, want := range []string{"svc: no login shell", "off: no login shell", "Bad.Name: ", "messagebus: ", "systemd-network: ", "old: Kairos's sshd does not accept ssh-dss"} {
		if !dropped(c, want) {
			t.Errorf("dropped = %v, want %q", c.Dropped, want)
		}
	}
	if dropped(c, "nokeys") {
		t.Errorf("dropped = %v: a user without keys is not news", c.Dropped)
	}
	if k := y.Stages["initramfs"][0].AuthorizedKeys["old"]; len(k) != 1 {
		t.Errorf("old's keys = %v, want the duplicate once", k)
	}
}

func TestCarryCloudConfigWins(t *testing.T) {
	for cfg, check := range map[string]func(Carried) bool{
		"#cloud-config\nusers:\n  - name: ubuntu\n    passwd: x\n": func(c Carried) bool {
			return len(c.Users) == 0 && dropped(c, "ubuntu: the cloud-config configures it")
		},
		"#cloud-config\nusers:\n  - default\n  - name: other\n": func(c Carried) bool { return len(c.Users) == 1 },
		"#cloud-config\nstages:\n  boot:\n    - users:\n        ubuntu: {}\n": func(c Carried) bool {
			return len(c.Users) == 0
		},
		"#cloud-config\nstages:\n  network:\n    - authorized_keys:\n        ubuntu: [github:me]\n": func(c Carried) bool {
			return len(c.Users) == 0
		},
		"#cloud-config\nhostname: mine\n": func(c Carried) bool {
			return c.Hostname == "" && strings.Contains(c.HostnameReason, "cloud-config")
		},
		"#cloud-config\nstages:\n  initramfs:\n    - hostname: mine\n": func(c Carried) bool { return c.Hostname == "" },
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc/hostname\n": func(c Carried) bool {
			return c.Hostname == ""
		},
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc/ssh/ssh_host_ed25519_key\n": func(c Carried) bool {
			return len(c.HostKeys) == 0 && strings.Contains(c.HostKeysReason, "/etc/ssh/ssh_host_ed25519_key")
		},
		"#cloud-config\nstages:\n  boot:\n    - downloads:\n        - path: /usr/local/.state/etc-ssh.bind/ssh_host_rsa_key\n": func(c Carried) bool {
			return len(c.HostKeys) == 0
		},
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc/ssh/sshd_config.d/10-me.conf\n": func(c Carried) bool {
			return len(c.HostKeys) == 3 && c.Hostname == "web-1" && len(c.Users) == 1
		},
	} {
		c := carried(t, cfg, ubuntuHost())
		if !check(c) {
			t.Errorf("%q: carried %+v", cfg, c)
		}
	}
}

func TestCarryRootNotOntoAConfiguredKairos(t *testing.T) {
	h := &Host{Users: []User{{Name: "root", Shell: "/bin/bash", Lines: []string{rootKey}}}}
	c := carried(t, "#cloud-config\nusers:\n  - name: kairos\n    groups: [admin]\n", h)
	if c.RootTo != "" || c.Login || !dropped(c, "root: ") {
		t.Errorf("carried %+v: the cloud-config's kairos wins", c)
	}
}

func TestCarryHostKeysItCannotUse(t *testing.T) {
	h := ubuntuHost()
	h.HostKeys = []HostKey{
		{Path: "/etc/ssh/ssh_host_ed25519_key", Private: private("x")},
		hostKey("ssh-dss", "/etc/ssh/ssh_host_dsa_key"),
		{Path: "/etc/ssh/ssh_host_rsa_key", Private: private("ssh-rsa"), Public: []byte("ssh-rsa garbage\n")},
		{Path: "/etc/ssh/other_ecdsa", Private: []byte("{{ .Values }}"), Public: []byte(line("ecdsa-sha2-nistp256", ""))},
		hostKey("ssh-ed25519", "/etc/ssh/a_ed25519"),
		hostKey("ssh-ed25519", "/etc/ssh/b_ed25519"),
	}
	_, c, y, _ := carry(t, "", h)
	if len(c.HostKeys) != 1 || len(y.Stages["initramfs.before"]) != 1 {
		t.Errorf("host keys = %v", c.HostKeys)
	}
	for _, want := range []string{"/etc/ssh/ssh_host_ed25519_key: no", "/etc/ssh/ssh_host_dsa_key: ", "/etc/ssh/ssh_host_rsa_key: ", "/etc/ssh/other_ecdsa: ", "/etc/ssh/b_ed25519: "} {
		if !dropped(c, want) {
			t.Errorf("dropped = %v, want %q", c.Dropped, want)
		}
	}
	for _, d := range c.Dropped {
		if strings.Contains(d, ".Values") {
			t.Errorf("dropped %q repeats the content", d)
		}
	}
}

func TestCarryHostname(t *testing.T) {
	for name, want := range map[string]string{
		"web-1.example.com":     "web-1.example.com",
		"":                      "",
		"localhost":             "",
		"(none)":                "",
		"bad_name":              "",
		"a-.b":                  "",
		"a..b":                  "",
		"a.-b":                  "",
		"a.b-":                  "",
		"a.b.":                  "",
		"-x":                    "",
		strings.Repeat("a", 65): "",
	} {
		h := ubuntuHost()
		h.Hostname = name
		_, c, y, _ := carry(t, "", h)
		if c.Hostname != want || (want == "" && c.HostnameReason == "") || y.Stages["initramfs"][0].Hostname != want {
			t.Errorf("%q: carried %q (%s)", name, c.Hostname, c.HostnameReason)
		}
	}
}

func TestCarryNamesTheKeysCommand(t *testing.T) {
	h := ubuntuHost()
	h.KeysCommand = "/usr/share/ec2-instance-connect/eic_run_authorized_keys %u %f"
	c := carried(t, "", h)
	if !dropped(c, "AuthorizedKeysCommand") {
		t.Errorf("dropped = %v", c.Dropped)
	}
}

func TestCarryTheHostnameAlone(t *testing.T) {
	_, c, y, _ := carry(t, "", &Host{Hostname: "web-1"})
	if s := y.Stages["initramfs"]; c.Hostname != "web-1" || len(s) != 1 || s[0].Hostname != "web-1" || len(s[0].Users) != 0 {
		t.Errorf("carried %+v, initramfs %+v", c, s)
	}
}

func TestCarryEndsAPrivateKeyWithANewline(t *testing.T) {
	h := &Host{HostKeys: []HostKey{{Path: "/etc/ssh/ssh_host_ed25519_key", Private: []byte("-----BEGIN-----\nx\n-----END-----"), Public: []byte(line("ssh-ed25519", ""))}}}
	_, _, y, _ := carry(t, "", h) //nolint:dogsled // the stages alone
	if f := y.Stages["initramfs.before"][0].Files[0]; f.Content != "-----BEGIN-----\nx\n-----END-----\n" {
		t.Errorf("content = %q: ssh-keygen and sshd reject a key without its final newline", f.Content)
	}
}

func TestCarryNothing(t *testing.T) {
	cfg := "#cloud-config\n# mine\nhostname: x\n"
	out, c, _, _ := carry(t, cfg, &Host{Hostname: "x"})
	if string(out) != cfg || c.Login || len(c.Users) != 0 || len(c.HostKeys) != 0 || c.HostKeysReason == "" {
		t.Errorf("out = %q, carried %+v", out, c)
	}
}

func TestCarryKeepsTheUsersConfig(t *testing.T) {
	out, _, y, _ := carry(t, "#cloud-config\nstages:\n  initramfs:\n    - name: mine\n", ubuntuHost())
	if s := y.Stages["initramfs"]; len(s) != 2 || s[0].Name != "mine" {
		t.Errorf("initramfs = %+v", s)
	}
	if _, _, err := kairos.Targets(out); err != nil {
		t.Error(err)
	}
}

func TestCarryFailsWithTheOptOut(t *testing.T) {
	_, _, err := Carry([]byte("#cloud-config\n"), func() (*Host, error) { return nil, errBoom }, t.Logf)
	if err == nil || !strings.Contains(err.Error(), "--keep-identity=false") {
		t.Errorf("err = %v", err)
	}
	_, _, err = Carry([]byte("#cloud-config\nstages: none\n"), func() (*Host, error) { return ubuntuHost(), nil }, t.Logf)
	if err == nil {
		t.Error("no error for a cloud-config it cannot extend")
	}
}
