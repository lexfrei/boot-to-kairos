//go:build linux

// Package kairos runs the image's own kairos-agent to install onto a device.
package kairos

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	"go.yaml.in/yaml/v3"

	"github.com/lexfrei/boot-to-kairos/internal/sandbox"
)

// ConfigName is the cloud-config file inside the sandbox root, on its private
// /run, so the agent does not copy it into the installed system.
const ConfigName = "run/btk-config.yaml"

// ErrNotCloudConfig rejects a config Kairos would silently ignore, which would
// leave a machine nobody can log in to.
var ErrNotCloudConfig = errors.New("config does not start with #cloud-config")

// ErrUncheckable marks configuration that cannot be checked here: what the
// agent would fetch or merge from elsewhere, and keys spelled so that it
// reads them otherwise than written.
var ErrUncheckable = errors.New("configuration from elsewhere cannot be checked")

type uncheckable struct{ error }

func (uncheckable) Is(target error) bool { return target == ErrUncheckable }

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
	// makes exec copy the output through a pipe. Its stdout goes to stderr
	// too, as stdout may carry a JSON report.
	cmd.Stdout = struct{ io.Writer }{os.Stderr}
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
// of kairos-agent v4. Legacy boot's bios partition is left out: the agent
// skips it when formatting, and grub-install finds it on the device it is
// given by its type GUID, never by name.
var (
	defaultNames  = []string{"efi", "oem", "recovery", "state", "persistent"}                                                             //nolint:gochecknoglobals // fixed list
	defaultLabels = []string{"COS_GRUB", "COS_OEM", "COS_OEM_LUKS", "COS_RECOVERY", "COS_STATE", "COS_PERSISTENT", "COS_PERSISTENT_LUKS"} //nolint:gochecknoglobals // fixed list
)

type partition struct {
	Name  string `yaml:"name"`
	Label string `yaml:"label"`
	FS    string `yaml:"fs"`
}

// Targets returns the partition names and filesystem labels the agent may
// look up on the host for cfg: the defaults, those the config gives the
// agent's own partitions, and those of its extra partitions. kairos-agent
// v4.3.0 lays its own partitions out from the defaults, keeping only their
// sizes, but an image may ship an agent that honours them. The agent never
// reads the host's kernel command line, which the sandbox hides.
func Targets(cfg []byte) (names, labels []string, err error) {
	top, install, err := parseConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	// The collector fetches config_url spelled exactly so, and only a string.
	if u, ok := top["config_url"].(string); ok && u != "" {
		return nil, nil, uncheckable{errors.New("the cloud-config sets config_url, which the agent fetches and merges unchecked; inline that configuration")}
	}
	var c struct {
		Partitions map[string]partition `yaml:"partitions"`
		Extra      []partition          `yaml:"extra-partitions"` //nolint:tagliatelle // Kairos's key
	}
	if err := redecode(install, &c); err != nil {
		return nil, nil, err
	}
	names = slices.Clone(defaultNames)
	labels = slices.Clone(defaultLabels)
	// The agent formats by name only a partition with a filesystem, but
	// mounts its own partitions by label whatever fs says; extra
	// partitions are never mounted.
	add := func(p partition, mounted bool) {
		if p.Name != "" && !unformatted(p.FS) {
			names = append(names, p.Name)
		}
		if p.Label != "" && (mounted || !unformatted(p.FS)) {
			labels = append(labels, p.Label)
		}
	}
	for _, p := range c.Partitions {
		add(p, true)
	}
	for _, p := range c.Extra {
		add(p, false)
	}
	return names, labels, nil
}

func unformatted(fs string) bool {
	return fs == "-" || fs == "none" || fs == "noformat"
}

// parseConfig returns the top level of cfg and its install section, after
// refusing every spelling the agent would read otherwise than written. It
// merges an install section of its own, spelled install, and reads the
// result through viper, which lowercases every key, keeps one of two that
// differ only in case, whichever map iteration reaches last, and nests a
// dotted key inside the section. With install spelled so and every key
// under it lowercase and free of dots, both read the same.
func parseConfig(cfg []byte) (top, install map[string]any, err error) {
	dec := yaml.NewDecoder(bytes.NewReader(cfg))
	var doc, more any
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, errors.Mark(errors.Wrap(err, "parse cloud-config"), ErrBadConfig)
	}
	// The agent reads the first document only and drops the rest unseen.
	for {
		err := dec.Decode(&more)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || more != nil {
			return nil, nil, errors.Mark(errors.New("the cloud-config holds more than one YAML document, and the agent reads only the first; put it all in one"), ErrBadConfig)
		}
	}
	install = map[string]any{}
	if doc == nil {
		return map[string]any{}, install, nil
	}
	top, ok := stringMap(doc)
	if !ok {
		return nil, nil, errors.Mark(errors.New("the cloud-config is not a mapping"), ErrBadConfig)
	}
	for k := range top {
		lower := strings.ToLower(k)
		if (lower == "install" && k != "install") || strings.HasPrefix(lower, "install.") {
			return nil, nil, uncheckable{errors.Newf("the cloud-config sets %s, which the agent reads otherwise than written; spell it install, with the keys under it nested", k)}
		}
	}
	m, ok := stringMap(top["install"])
	if !ok {
		return top, install, nil
	}
	return top, m, plainKeys(m, "install")
}

// plainKeys refuses a key in v, under path, that is not lowercase or holds
// a dot.
func plainKeys(v any, path string) error {
	if m, ok := stringMap(v); ok {
		for k, e := range m {
			if k != strings.ToLower(k) || strings.Contains(k, ".") {
				return uncheckable{errors.Newf("the cloud-config sets %s.%s, which the agent reads otherwise than written; keys under install must be lowercase and hold no dot", path, k)}
			}
			if err := plainKeys(e, path+"."+k); err != nil {
				return err
			}
		}
		return nil
	}
	list, _ := v.([]any)
	for i, e := range list {
		if err := plainKeys(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// stringMap returns a YAML mapping keyed by strings; one with a key of
// another type, like 1 or true, decodes keyed by any.
func stringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, e := range m {
			out[fmt.Sprint(k)] = e
		}
		return out, true
	}
	return nil, false
}

// redecode decodes view, a parsed cloud-config section, into out.
func redecode(view map[string]any, out any) error {
	b, err := yaml.Marshal(view)
	if err != nil {
		return errors.Wrap(err, "re-encode cloud-config")
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return errors.Mark(errors.Wrap(err, "parse cloud-config"), ErrBadConfig)
	}
	return nil
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
