package identity

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
)

// sshdConfig is what Capture takes from the host's sshd -T.
type sshdConfig struct {
	keysFiles   []string
	keysCommand string
	hostKeys    []string
}

// sshdDefaults are OpenSSH's own defaults, for a host whose sshd -T
// cannot be read.
func sshdDefaults() sshdConfig {
	return sshdConfig{
		keysFiles: []string{".ssh/authorized_keys", ".ssh/authorized_keys2"},
		hostKeys:  []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"},
	}
}

func parseSSHD(out []byte) sshdConfig {
	c := sshdDefaults()
	var hostKeys []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, value, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		switch key {
		case "authorizedkeysfile":
			c.keysFiles = strings.Fields(value)
		case "authorizedkeyscommand":
			if value != "none" {
				c.keysCommand = value
			}
		case "hostkey":
			hostKeys = append(hostKeys, value)
		}
	}
	if hostKeys != nil {
		c.hostKeys = hostKeys
	}
	return c
}

// adminGroups are the groups whose members get sudo on the usual
// distributions, as admin does on Kairos.
var adminGroups = []string{"sudo", "admin", "wheel"} //nolint:gochecknoglobals // fixed list

// Capture reads the identity of the system whose root directory is root.
// sshdT returns the output of the host's sshd -T, whose AuthorizedKeysFile
// and HostKey it follows; Match blocks are not evaluated. canSudo tells
// whether a user may run a shell as root through sudoers alone, as the
// user cloud-init creates may.
func Capture(root string, sshdT func() ([]byte, error), canSudo func(string) bool) (*Host, error) {
	h := &Host{}
	c := sshdDefaults()
	if out, err := sshdT(); err != nil {
		h.Notes = append(h.Notes, fmt.Sprintf("sshd -T: %v; reading the default authorized_keys files and host keys", err))
	} else {
		c = parseSSHD(out)
	}
	h.KeysCommand = c.keysCommand
	if b, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/hostname")); err == nil {
		h.Hostname = strings.TrimSpace(string(b))
	}
	admins, err := adminGIDs(root)
	if err != nil {
		return nil, err
	}
	passwd, err := os.ReadFile(filepath.Join(root, "etc/passwd"))
	if err != nil {
		return nil, errors.Wrap(err, "read /etc/passwd")
	}
	for l := range strings.Lines(string(passwd)) {
		f := strings.Split(strings.TrimRight(l, "\n"), ":")
		if len(f) != 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		u := User{Name: f[0], UID: uid, Shell: f[6]}
		if u.Lines = h.keyLines(root, c.keysFiles, u, f[5]); len(u.Lines) == 0 {
			continue
		}
		u.Admin = admins.has(f[0], gid) || canSudo(f[0])
		h.Users = append(h.Users, u)
	}
	for _, p := range c.hostKeys {
		h.hostKey(root, p)
	}
	return h, nil
}

type admins struct {
	gids    []int
	members []string
}

func (a admins) has(name string, gid int) bool {
	return slices.Contains(a.gids, gid) || slices.Contains(a.members, name)
}

func adminGIDs(root string) (admins, error) {
	b, err := os.ReadFile(filepath.Join(root, "etc/group"))
	if err != nil {
		return admins{}, errors.Wrap(err, "read /etc/group")
	}
	var a admins
	for l := range strings.Lines(string(b)) {
		f := strings.Split(strings.TrimRight(l, "\n"), ":")
		if len(f) != 4 || !slices.Contains(adminGroups, f[0]) {
			continue
		}
		if gid, err := strconv.Atoi(f[2]); err == nil {
			a.gids = append(a.gids, gid)
		}
		if f[3] != "" {
			a.members = append(a.members, strings.Split(f[3], ",")...)
		}
	}
	return a, nil
}

// keyLines reads u's authorized keys files, which sshd names relative to
// the home directory unless absolute.
func (h *Host) keyLines(root string, files []string, u User, home string) []string {
	var out []string
	for _, f := range files {
		p, ok := expand(f, u, home)
		if !ok {
			h.Notes = append(h.Notes, fmt.Sprintf("AuthorizedKeysFile %s: a token this cannot expand; that file is not read", f))
			continue
		}
		if !path.IsAbs(p) {
			p = path.Join(home, p)
		}
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
				h.Notes = append(h.Notes, fmt.Sprintf("%s: %v", p, err))
			}
			continue
		}
		for l := range strings.Lines(string(b)) {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, l)
			}
		}
	}
	return out
}

// expand expands the tokens sshd_config(5) allows in AuthorizedKeysFile.
func expand(f string, u User, home string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(f); i++ {
		if f[i] != '%' {
			b.WriteByte(f[i])
			continue
		}
		i++
		if i == len(f) {
			return "", false
		}
		switch f[i] {
		case '%':
			b.WriteByte('%')
		case 'h':
			b.WriteString(home)
		case 'u':
			b.WriteString(u.Name)
		case 'U':
			b.WriteString(strconv.Itoa(u.UID))
		default:
			return "", false
		}
	}
	return b.String(), true
}

func (h *Host) hostKey(root, p string) {
	priv, err := os.ReadFile(filepath.Join(root, p))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			h.Notes = append(h.Notes, fmt.Sprintf("host key %s: %v", p, err))
		}
		return
	}
	k := HostKey{Path: p, Private: priv}
	if pub, err := os.ReadFile(filepath.Join(root, p+".pub")); err == nil {
		k.Public = pub
	}
	h.HostKeys = append(h.HostKeys, k)
}

// CaptureHost reads the running system's identity.
func CaptureHost(ctx context.Context) (*Host, error) {
	return Capture("/", func() ([]byte, error) { return sshdT(ctx) }, func(name string) bool {
		// -l with a command exits 0 only if sudoers lets name run it.
		return exec.CommandContext(ctx, "sudo", "-n", "-l", "-U", name, "/bin/sh").Run() == nil
	})
}

func sshdT(ctx context.Context) ([]byte, error) {
	bin, err := exec.LookPath("sshd")
	if err != nil {
		for _, p := range []string{"/usr/sbin/sshd", "/sbin/sshd"} {
			if _, serr := os.Stat(p); serr == nil {
				bin, err = p, nil
				break
			}
		}
	}
	if err != nil {
		return nil, errors.Wrap(err, "find sshd")
	}
	out, err := exec.CommandContext(ctx, bin, "-T").Output()
	return out, errors.Wrap(err, "sshd -T")
}
