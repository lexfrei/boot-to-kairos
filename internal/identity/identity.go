// Package identity carries the host's SSH logins, SSH host keys and
// hostname into the installed Kairos system, so that the machine comes
// back as itself for whoever connects to it.
//
// Like the network configuration, they are yip stages added to the
// cloud-config, which kairos-agent stores on the OEM partition: Kairos
// rebuilds /etc/passwd from the image on every boot and generates SSH host
// keys on the first one.
package identity

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"

	"github.com/lexfrei/boot-to-kairos/internal/cloudconfig"
	"github.com/lexfrei/boot-to-kairos/internal/kairos"
)

// Host is what is carried over, or examined to refuse.
type Host struct {
	// Hostname is the kernel's.
	Hostname string
	Users    []User
	HostKeys []HostKey
	// KeysCommand is the AuthorizedKeysCommand of the host's sshd, "" if
	// none.
	KeysCommand string
	// Notes are what the capture could not read.
	Notes []string
}

// User is a passwd entry and the lines of its authorized keys files.
type User struct {
	Name  string
	UID   int
	Shell string
	// Admin is set for a member of sudo, admin or wheel, or a user sudoers
	// lets run a shell as root.
	Admin bool
	Lines []string
}

// HostKey is a host private key and the public key beside it, nil if
// there is none.
type HostKey struct {
	Path            string
	Private, Public []byte
}

// Carried is what Carry carried over, for the plan. It holds fingerprints,
// never key material.
type Carried struct {
	// Hostname is "" when HostnameReason says why it was not carried.
	Hostname, HostnameReason string
	// HostKeys are "<type> <fingerprint>"; HostKeysReason says why there
	// are none.
	HostKeys       []string
	HostKeysReason string
	// Users are "<name> (admin, <n> keys)".
	Users []string
	// RootTo says where root's keys went, "" if they did not.
	RootTo string
	// Dropped are what was found and not carried, each with why.
	Dropped []string
	// Login is set when a carried admin user has a key that logs in.
	Login bool
}

// ErrNoLogin refuses an install that would leave nobody a way in.
var ErrNoLogin = errors.New("no way to log in to the installed system")

const optOut = "; to install without carrying it over, pass --keep-identity=false"

// Carry returns cfg with the host's identity added to it, or as it is when
// there is nothing to add.
func Carry(cfg []byte, capture func() (*Host, error), logf func(string, ...any)) ([]byte, Carried, error) {
	set, err := configured(cfg)
	if err != nil {
		return nil, Carried{}, err
	}
	h, err := capture()
	if err != nil {
		return nil, Carried{}, errors.Wrap(err, "read this system's SSH logins, host keys and hostname"+optOut)
	}
	for _, n := range h.Notes {
		logf("identity: %s", n)
	}
	p := plan(h, set)
	for _, d := range p.Dropped {
		logf("identity: not carried: %s", d)
	}
	for _, n := range p.notes {
		logf("identity: %s", n)
	}
	if len(p.keys) == 0 && len(p.users) == 0 && p.Hostname == "" {
		return cfg, p.Carried, nil
	}
	out, err := p.inject(cfg)
	if err != nil {
		return nil, Carried{}, err
	}
	return out, p.Carried, nil
}

// settings are what the user's cloud-config sets itself; each wins over
// what would be carried.
type settings struct {
	users    map[string]bool
	hostname string
	hostKeys string
	debug    bool
	// grubDebug names the install.grub_options key that turns debug on
	// at every boot of the installed system.
	grubDebug string
}

type pathed struct{ Path string }

type stageEntry struct {
	Hostname       string               `yaml:"hostname"`
	Users          map[string]yaml.Node `yaml:"users"`
	AuthorizedKeys map[string]yaml.Node `yaml:"authorized_keys"` //nolint:tagliatelle // yip's key
	Files          []pathed             `yaml:"files"`
	Downloads      []pathed             `yaml:"downloads"`
}

func configured(cfg []byte) (settings, error) {
	var c struct {
		Hostname string `yaml:"hostname"`
		Debug    bool   `yaml:"debug"`
		Install  struct {
			GrubOptions map[string]any `yaml:"grub_options"` //nolint:tagliatelle // Kairos's key
		} `yaml:"install"`
		Users  []yaml.Node             `yaml:"users"`
		Stages map[string][]stageEntry `yaml:"stages"`
	}
	if err := yaml.Unmarshal(cfg, &c); err != nil {
		return settings{}, errors.Wrap(err, "parse the cloud-config to carry the identity over")
	}
	s := settings{users: map[string]bool{}, debug: c.Debug}
	for key, v := range c.Install.GrubOptions {
		// immucore, which runs only on the installed system, logs each
		// stage it runs under rd.immucore.debug, matched as a prefix.
		if v := fmt.Sprint(v); kairos.AgentDebug(v) || strings.Contains(v, "rd.immucore.debug") {
			s.grubDebug = key
		}
	}
	if c.Hostname != "" {
		s.hostname = "it sets hostname"
	}
	for i := range c.Users {
		var named struct{ Name string }
		if c.Users[i].Decode(&named) == nil && named.Name != "" {
			s.users[named.Name] = true
		}
	}
	for name, entries := range c.Stages {
		for i := range entries {
			s.stage(name, &entries[i])
		}
	}
	return s, nil
}

func (s *settings) stage(name string, e *stageEntry) {
	if e.Hostname != "" {
		s.hostname = fmt.Sprintf("its %s stage sets hostname", name)
	}
	for u := range e.Users {
		s.users[u] = true
	}
	for u := range e.AuthorizedKeys {
		s.users[u] = true
	}
	for _, f := range append(e.Files, e.Downloads...) {
		p := path.Clean(f.Path)
		if p == "/etc/hostname" || p == "/usr/local/etc/hostname" {
			s.hostname = fmt.Sprintf("its %s stage writes %s", name, f.Path)
		}
		if strings.HasPrefix(p, "/etc/ssh/ssh_host_") || strings.HasPrefix(p, "/usr/local/.state/etc-ssh.bind/ssh_host_") {
			s.hostKeys = fmt.Sprintf("its %s stage writes %s", name, f.Path)
		}
	}
}

type carriedKey struct {
	typ, private, public string
}

type carriedUser struct {
	admin bool
	keys  []string
}

type planned struct {
	Carried

	keys  []carriedKey
	users map[string]*carriedUser
	order []string
	notes []string
}

// kairosUser is the image's own admin user, which root's keys move to:
// Kairos's sshd refuses root logins (PermitRootLogin no in kairos-init's
// 05-kairos-hardening.conf, the first value sshd reads).
const kairosUser = "kairos"

func plan(h *Host, set settings) *planned {
	p := &planned{users: map[string]*carriedUser{}}
	p.planHostname(h.Hostname, set.hostname)
	p.planHostKeys(h.HostKeys, set)
	p.planUsers(h, set.users)
	return p
}

// hostnameRe takes dot-separated RFC 1123 labels; HOST_NAME_MAX is 64.
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

func (p *planned) planHostname(name, set string) {
	switch {
	case set != "":
		p.HostnameReason = "the cloud-config sets it: " + set
	case name == "" || name == "(none)" || name == "localhost" || name == "localhost.localdomain":
		p.HostnameReason = "this system has none"
	case len(name) > 64 || !hostnameRe.MatchString(name):
		p.HostnameReason = fmt.Sprintf("%q is not a hostname Kairos can set", name)
	default:
		p.Hostname = name
	}
}

// hostKeyTypes maps the public key type to the name of Kairos's key file.
var hostKeyTypes = map[string]string{ //nolint:gochecknoglobals // fixed table
	"ssh-ed25519":         "ed25519",
	"ssh-rsa":             "rsa",
	"ecdsa-sha2-nistp256": "ecdsa",
	"ecdsa-sha2-nistp384": "ecdsa",
	"ecdsa-sha2-nistp521": "ecdsa",
}

func (p *planned) planHostKeys(keys []HostKey, set settings) {
	switch {
	case set.hostKeys != "":
		p.HostKeysReason = "the cloud-config writes them: " + set.hostKeys
		return
	case set.debug:
		p.HostKeysReason = "the cloud-config sets debug, under which kairos-agent prints the whole configuration, private keys included"
		return
	case set.grubDebug != "":
		p.HostKeysReason = "the cloud-config's install.grub_options." + set.grubDebug + " turns debug on at every boot, and the installed system then logs the configuration, private keys included"
		return
	}
	for _, k := range keys {
		pub, err := p.hostKey(k)
		if err != nil {
			p.Dropped = append(p.Dropped, fmt.Sprintf("%s: %v", k.Path, err))
			continue
		}
		fp, _ := fingerprint(pub.blob)
		v := pub.typ + " " + fp
		if pub.typ == "ecdsa" {
			v += " (not offered by Kairos's sshd)"
			p.notes = append(p.notes, fmt.Sprintf("the ECDSA host key %s is carried, but Kairos's sshd offers only ed25519 and RSA host keys: "+
				"a client that knows this host by its ECDSA key alone will refuse the new system", fp))
		}
		p.HostKeys = append(p.HostKeys, v)
	}
	if len(p.HostKeys) == 0 {
		p.HostKeysReason = "this system has none Kairos can use"
	}
}

type pubKey struct{ typ, blob string }

func (p *planned) hostKey(k HostKey) (pubKey, error) {
	if k.Public == nil {
		return pubKey{}, errors.Newf("no %s.pub beside it to tell its type", path.Base(k.Path))
	}
	f := strings.Fields(string(k.Public))
	if len(f) < 2 || !blobOfType(f[1], f[0]) {
		return pubKey{}, errors.Newf("%s.pub is not a public key", path.Base(k.Path))
	}
	typ, ok := hostKeyTypes[f[0]]
	if !ok {
		return pubKey{}, errors.Newf("Kairos's sshd does not use %s host keys", f[0])
	}
	if literal(string(k.Private)) != nil {
		return pubKey{}, errors.New("it contains {{ or }}, which Kairos would render as a template")
	}
	if slices.ContainsFunc(p.keys, func(c carriedKey) bool { return c.typ == typ }) {
		return pubKey{}, errors.Newf("a second %s host key; the first one is carried", typ)
	}
	priv := string(k.Private)
	if !strings.HasSuffix(priv, "\n") {
		priv += "\n"
	}
	p.keys = append(p.keys, carriedKey{typ: typ, private: priv, public: f[0] + " " + f[1] + "\n"})
	return pubKey{typ: typ, blob: f[1]}, nil
}

var (
	nameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// imageNames are the users and groups of Kairos v4.3's image, and the
	// admin group its initramfs stage adds. yip gives a new user a primary
	// group of its own name and writes its gid over a group of that name,
	// keeping the members: a user named admin would renumber Kairos's sudo
	// group and join it. Images with other names are caught after the
	// build has the image's /etc, by Clashes.
	imageNames = regexp.MustCompile(`^(root|nobody|nogroup|messagebus|systemd-.*|admin|adm|wheel|empower|utmp|audio|cdrom|clock|` +
		`dialout|disk|input|kmem|kvm|lp|render|sgx|tape|tty|video|users)$`)
	// fullShells are the shells whose users get bash on Kairos; a
	// restricted one such as git-shell or rbash must not become a full one.
	fullShells = []string{"sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh"} //nolint:gochecknoglobals // fixed list
)

func loginShell(shell string) bool {
	b := path.Base(shell)
	return b != "nologin" && b != "false"
}

func (p *planned) planUsers(h *Host, set map[string]bool) {
	var root []string
	for _, u := range h.Users {
		if len(u.Lines) == 0 {
			continue
		}
		switch {
		case !loginShell(u.Shell):
			p.Dropped = append(p.Dropped, fmt.Sprintf("%s: no login shell (%s)", u.Name, u.Shell))
		case u.UID == 0:
			root = append(root, p.accept(u.Name, u.Lines)...)
		case !slices.Contains(fullShells, path.Base(u.Shell)) && u.Shell != "":
			p.Dropped = append(p.Dropped, fmt.Sprintf("%s: its shell %s restricts it, and Kairos would give it bash", u.Name, u.Shell))
		case !nameRe.MatchString(u.Name) || imageNames.MatchString(u.Name):
			p.Dropped = append(p.Dropped, fmt.Sprintf("%s: not a name Kairos takes for a user", u.Name))
		case u.Name == kairosUser && !u.Admin:
			p.Dropped = append(p.Dropped, kairosUser+": the image's own admin user, so a "+kairosUser+" without sudo here would get it there")
		case set[u.Name]:
			p.Dropped = append(p.Dropped, fmt.Sprintf("%s: the cloud-config configures it", u.Name))
		default:
			if keys := p.accept(u.Name, u.Lines); len(keys) > 0 {
				p.add(u.Name, u.Admin, keys)
			}
		}
	}
	p.planRoot(root, set)
	if h.KeysCommand != "" {
		p.Dropped = append(p.Dropped, fmt.Sprintf("keys from the AuthorizedKeysCommand %s", h.KeysCommand))
	}
	for _, name := range p.order {
		u := p.users[name]
		v := fmt.Sprintf("%d key", len(u.keys))
		if len(u.keys) != 1 {
			v += "s"
		}
		if u.admin {
			v = "admin, " + v
		}
		p.Users = append(p.Users, fmt.Sprintf("%s (%s)", name, v))
	}
}

func (p *planned) planRoot(keys []string, set map[string]bool) {
	if len(keys) == 0 {
		return
	}
	const refuses = "root: Kairos refuses root logins"
	switch {
	case p.Login:
		p.Dropped = append(p.Dropped, refuses+", and an admin user above logs in")
		return
	case set[kairosUser]:
		p.Dropped = append(p.Dropped, refuses+", and the cloud-config configures "+kairosUser)
		return
	}
	var plain []string
	for _, k := range keys {
		if kl, _ := parseKeyLine(k); kl.command {
			p.Dropped = append(p.Dropped, "root: a key with a forced command is not moved to "+kairosUser)
			continue
		}
		plain = append(plain, k)
	}
	if len(plain) == 0 {
		p.Dropped = append(p.Dropped, refuses)
		return
	}
	p.add(kairosUser, true, plain)
	p.RootTo = fmt.Sprintf("carried to %s, as Kairos refuses root logins", kairosUser)
}

// accept returns the lines of name's keys that Kairos can use.
func (p *planned) accept(name string, lines []string) []string {
	var out []string
	for _, l := range lines {
		k, err := parseKeyLine(l)
		if err != nil {
			p.Dropped = append(p.Dropped, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		out = append(out, k.line)
	}
	return out
}

func (p *planned) add(name string, admin bool, keys []string) {
	u, ok := p.users[name]
	if !ok {
		u = &carriedUser{}
		p.users[name] = u
		p.order = append(p.order, name)
	}
	u.admin = u.admin || admin
	for _, k := range keys {
		if !slices.Contains(u.keys, k) {
			u.keys = append(u.keys, k)
		}
		if kl, _ := parseKeyLine(k); u.admin && !kl.command {
			p.Login = true
		}
	}
}

type yipFile struct {
	Path string `yaml:"path"`
	// Decimal: it reads the same under every YAML version.
	Permissions uint32 `yaml:"permissions"`
	Owner       int    `yaml:"owner"`
	Group       int    `yaml:"group"`
	Content     string `yaml:"content"`
}

type keyStage struct {
	Name  string    `yaml:"name"`
	If    string    `yaml:"if"`
	Files []yipFile `yaml:"files"`
}

type yipUser struct {
	Groups []string `yaml:"groups,omitempty"`
	// Without it yip gives the user an empty password.
	LockPasswd bool   `yaml:"lock_passwd"` //nolint:tagliatelle // yip's key
	Shell      string `yaml:"shell"`
}

type userStage struct {
	Name           string              `yaml:"name"`
	Hostname       string              `yaml:"hostname,omitempty"`
	Users          map[string]yipUser  `yaml:"users,omitempty"`
	AuthorizedKeys map[string][]string `yaml:"authorized_keys,omitempty"` //nolint:tagliatelle // yip's key
}

const stageName = "boot-to-kairos: %s carried over from the replaced system"

// inject writes the host keys in initramfs.before, chrooted into the
// installed system after /etc/ssh is bound to the persistent partition and
// before the image's own initramfs stage generates keys that are missing.
// Users, their keys and the hostname go in initramfs, which runs every
// boot before sshd starts.
func (p *planned) inject(cfg []byte) ([]byte, error) {
	doc, err := cloudconfig.Parse(cfg)
	if err != nil {
		return nil, err
	}
	for _, k := range p.keys {
		file := "/etc/ssh/ssh_host_" + k.typ + "_key"
		if err := doc.Append("initramfs.before", keyStage{
			Name:  fmt.Sprintf(stageName, "SSH "+k.typ+" host key"),
			If:    "[ ! -e " + file + " ]",
			Files: []yipFile{{Path: file, Permissions: 0o600, Content: k.private}, {Path: file + ".pub", Permissions: 0o644, Content: k.public}},
		}); err != nil {
			return nil, err
		}
	}
	if len(p.users) == 0 && p.Hostname == "" {
		return doc.Bytes()
	}
	s := userStage{Name: fmt.Sprintf(stageName, "SSH logins and hostname"), Hostname: p.Hostname}
	if len(p.users) > 0 {
		s.Users, s.AuthorizedKeys = map[string]yipUser{}, map[string][]string{}
	}
	for name, u := range p.users {
		y := yipUser{LockPasswd: true, Shell: "/bin/bash"}
		if u.admin {
			y.Groups = []string{"admin"}
		}
		s.Users[name], s.AuthorizedKeys[name] = y, u.keys
	}
	if err := doc.Append("initramfs", s); err != nil {
		return nil, err
	}
	return doc.Bytes()
}
