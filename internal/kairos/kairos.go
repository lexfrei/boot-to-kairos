//go:build linux

// Package kairos runs the image's own kairos-agent to install onto a device.
package kairos

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
	"github.com/google/shlex"
	"go.yaml.in/yaml/v3"

	"github.com/lexfrei/boot-to-kairos/internal/sandbox"
)

// ConfigName is the cloud-config file inside the sandbox root, on its private
// /run, so the agent does not copy it into the installed system.
const ConfigName = "run/btk-config.yaml"

// ErrNotCloudConfig rejects a config Kairos would silently ignore, which would
// leave a machine nobody can log in to.
var ErrNotCloudConfig = errors.New("config does not start with #cloud-config")

// Command returns kairos-agent manual-install for device, run from the image
// chrooted at root. The absolute path is resolved after the chroot, so it is
// the image's agent, never one from the host.
func Command(ctx context.Context, root, device string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/kairos-agent",
		"manual-install", "--device", device,
		"--source", "dir:/"+sandbox.SourceDir, "/"+ConfigName)
	cmd.Args[0] = "kairos-agent"
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	inGroup(cmd)
	cmd.Env = []string{
		"PATH=/" + StubDir + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		// udevadm skips trigger and settle in a chroot, and kairos-agent then
		// looks up /dev/disk/by-partlabel before udev has created it. The
		// second name is the deprecated spelling older systemd reads.
		"SYSTEMD_IN_CHROOT=0",
		"SYSTEMD_IGNORE_CHROOT=1",
	}
	// Not the files themselves: in its own process group the agent would be
	// stopped writing to a terminal that has tostop set. A plain writer
	// makes exec copy the output through a pipe.
	cmd.Stdout = struct{ io.Writer }{os.Stdout}
	cmd.Stderr = struct{ io.Writer }{os.Stderr}
	return cmd
}

// CheckConfig rejects a config Kairos would not read as cloud-config.
func CheckConfig(cfg []byte) error {
	if !bytes.HasPrefix(bytes.TrimLeft(cfg, " \t\r\n"), []byte("#cloud-config")) {
		return ErrNotCloudConfig
	}
	return nil
}

// WriteConfig stores the user's cloud-config inside root for the agent.
func WriteConfig(root string, cfg []byte) error {
	if err := CheckConfig(cfg); err != nil {
		return err
	}
	p := filepath.Join(root, ConfigName)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return errors.Wrap(err, "create config dir")
	}
	return errors.Wrap(os.WriteFile(p, cfg, 0o600), "write cloud-config")
}

// Install runs kairos-agent and kills whatever it left running, so nothing
// keeps the loop device or the binds busy afterwards.
func Install(ctx context.Context, root, device string) error {
	if err := WriteStubs(root); err != nil {
		return err
	}
	return run(Command(ctx, root, device))
}

func run(cmd *exec.Cmd) error {
	err := cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// The agent succeeded; only a child of it kept the output open.
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	return err
}

// outputGrace is how long the output of an exited agent is still drained.
const outputGrace = 5 * time.Second

// inGroup starts cmd in a process group of its own and makes cancelling it
// kill the whole group: killing only the agent leaves its formatters and
// copies running.
func inGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	// Output goes through pipes, and Wait would also wait for every child
	// holding them, past the agent's exit and past any cancel.
	cmd.WaitDelay = outputGrace
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// StubDir holds commands the agent must not run against the host. It is on
// the chroot's private /run, so the stubs never reach the installed system,
// and first in the agent's PATH, which is how the agent finds them.
const StubDir = "run/btk-bin"

// stubbed are host-wide in effect although run from the chroot:
// blkdeactivate --dmoptions force replaces the device-mapper tables of the
// host, which look unused from inside; reboot and poweroff, which a config's
// install section can ask for, reach the host's init.
var stubbed = []string{"blkdeactivate", "reboot", "poweroff", "shutdown", "halt"} //nolint:gochecknoglobals // fixed list

// WriteStubs writes a do-nothing command for each of them into root.
func WriteStubs(root string) error {
	dir := filepath.Join(root, StubDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.Wrap(err, "create stub dir")
	}
	for _, name := range stubbed {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			return errors.Wrapf(err, "write %s stub", name)
		}
	}
	return nil
}

// LabelClashes returns the names already present in dir.
func LabelClashes(dir string, names []string) []string {
	var out []string
	for _, name := range names {
		if _, err := os.Lstat(filepath.Join(dir, udevEscape(name))); err == nil {
			out = append(out, name)
		}
	}
	return out
}

// The agent finds the partitions it formats by GPT name, through
// /dev/disk/by-partlabel, and those it mounts by filesystem label, through
// /dev/disk/by-label, rather than on the device it was given; a host
// partition carrying one of them is taken instead. These are the defaults
// of kairos-agent v4; legacy boot's bios partition is left out, as legacy
// boot is refused.
var (
	defaultNames  = []string{"efi", "oem", "recovery", "state", "persistent"}                                                             //nolint:gochecknoglobals // fixed list
	defaultLabels = []string{"COS_GRUB", "COS_OEM", "COS_OEM_LUKS", "COS_RECOVERY", "COS_STATE", "COS_PERSISTENT", "COS_PERSISTENT_LUKS"} //nolint:gochecknoglobals // fixed list
)

type partition struct {
	Name  string `yaml:"name"`
	Label string `yaml:"label"`
	FS    string `yaml:"fs"`
}

// Targets returns the partition names and filesystem labels the agent
// looks up on the host for cfg and the host's kernel command line: the
// defaults, the ones they rename them to, and the config's extra
// partitions, except those left unformatted.
func Targets(cfg, cmdline []byte) (names, labels []string, err error) {
	var c struct {
		ConfigURL string `yaml:"config_url"` //nolint:tagliatelle // Kairos's key
		Install   struct {
			Partitions map[string]partition `yaml:"partitions"`
			Extra      []partition          `yaml:"extra-partitions"` //nolint:tagliatelle // Kairos's key
		} `yaml:"install"`
	}
	if err := yaml.Unmarshal(cfg, &c); err != nil {
		return nil, nil, errors.Wrap(err, "parse cloud-config")
	}
	if c.ConfigURL != "" {
		return nil, nil, errors.New("the cloud-config sets config_url, which the agent fetches and merges unchecked; inline that configuration")
	}
	names = slices.Clone(defaultNames)
	labels = slices.Clone(defaultLabels)
	parts := slices.Collect(maps.Values(c.Install.Partitions))
	for _, p := range append(parts, c.Install.Extra...) {
		switch p.FS {
		case "-", "none", "noformat":
			continue
		}
		if p.Name != "" {
			names = append(names, p.Name)
		}
		if p.Label != "" {
			labels = append(labels, p.Label)
		}
	}
	// The agent also merges install.* keys from the kernel command line,
	// dotted paths into the same tree.
	for _, tok := range cmdlineTokens(string(cmdline)) {
		key, value, _ := strings.Cut(tok, "=")
		switch {
		case fetched[key]:
			return nil, nil, errors.Newf("the kernel command line sets %s, which the agent fetches and merges unchecked; remove it", key)
		case strings.HasPrefix(key, "install.extra-partitions"):
			return nil, nil, errors.Newf("the kernel command line declares %s, which cannot be checked; remove it", key)
		case strings.HasPrefix(key, "install.partitions.") && strings.HasSuffix(key, ".name"):
			names = append(names, value)
		case strings.HasPrefix(key, "install.partitions.") && strings.HasSuffix(key, ".label"):
			labels = append(labels, value)
		}
	}
	return names, labels, nil
}

// fetched are the keys through which the agent pulls in more configuration
// at run time.
var fetched = map[string]bool{"config_url": true, "kairos.config": true, "kairos.config_url": true, "cos.setup": true} //nolint:gochecknoglobals // fixed set

// cmdlineTokens splits a kernel command line the way the agent does, with
// shlex and its error ignored, which drops what follows an unbalanced
// quote.
func cmdlineTokens(cmdline string) []string {
	tokens, _ := shlex.Split(cmdline)
	return tokens
}

// udevEscape spells name the way udev names its by-label and by-partlabel
// links: characters outside [A-Za-z0-9#+-.:=@_] and valid UTF-8 become
// \xNN, a slash included, so the name never leaves the directory.
func udevEscape(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		switch {
		case r >= utf8.RuneSelf && r != utf8.RuneError:
			b.WriteString(name[i : i+size])
		case r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("#+-.:=@_", r)):
			b.WriteRune(r)
		default:
			for _, c := range []byte(name[i : i+size]) {
				fmt.Fprintf(&b, "\\x%02x", c)
			}
		}
		i += size
	}
	return b.String()
}
