//go:build linux

package kairos

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestCommandRunsAgentInsideTheSandbox(t *testing.T) {
	cmd := Command(t.Context(), "/run/btk/root", "/dev/loop7")

	wantArgs := []string{"kairos-agent", "manual-install", "--device", "/dev/loop7", "--source", "dir:/run/btk-src", "/run/btk-config.yaml"}
	if !reflect.DeepEqual(cmd.Args, wantArgs) {
		t.Fatalf("args = %q, want %q", cmd.Args, wantArgs)
	}
	if cmd.Path != "/usr/bin/kairos-agent" {
		t.Fatalf("path = %q: it must be the image's agent, resolved after the chroot", cmd.Path)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Chroot != "/run/btk/root" {
		t.Fatalf("chroot = %+v", cmd.SysProcAttr)
	}
	if cmd.Dir != "/" {
		t.Fatalf("dir = %q", cmd.Dir)
	}
	for _, e := range []string{"SYSTEMD_IN_CHROOT=0", "SYSTEMD_IGNORE_CHROOT=1"} {
		if !slices.Contains(cmd.Env, e) {
			t.Fatalf("env %q missing: udevadm would skip settle in the chroot", e)
		}
	}
}

func TestWriteConfigPlacesItPrivately(t *testing.T) {
	root := t.TempDir()
	cfg := []byte("#cloud-config\nusers:\n- name: kairos\n  passwd: secret\n")
	if err := WriteConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, ConfigName)
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(cfg) {
		t.Fatalf("config = %q, %v", got, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600: the config can carry passwords", st.Mode().Perm())
	}
}

func TestWriteConfigRejectsMissingHeader(t *testing.T) {
	err := WriteConfig(t.TempDir(), []byte("users:\n- name: kairos\n"))
	if !errors.Is(err, ErrNotCloudConfig) {
		t.Fatalf("err = %v, want ErrNotCloudConfig", err)
	}
}

func TestCommandOutputGoesThroughAPipe(t *testing.T) {
	cmd := Command(t.Context(), "/run/btk/root", "/dev/loop7")
	// In a process group of its own, the agent writing to the terminal
	// directly is stopped by SIGTTOU when the terminal has tostop set.
	if _, ok := cmd.Stdout.(*os.File); ok {
		t.Fatal("Stdout is a file: the agent would write to the terminal itself")
	}
	if _, ok := cmd.Stderr.(*os.File); ok {
		t.Fatal("Stderr is a file: the agent would write to the terminal itself")
	}
	// stdout carries only what boot-to-kairos itself prints, a JSON report
	// among it.
	if w, ok := cmd.Stdout.(struct{ io.Writer }); !ok || w.Writer != os.Stderr {
		t.Fatalf("Stdout = %#v, want the agent's output on stderr", cmd.Stdout)
	}
}

func TestCommandFindsTheStubsFirst(t *testing.T) {
	cmd := Command(t.Context(), "/run/btk/root", "/dev/loop7")
	if !slices.Contains(cmd.Env, "PATH=/"+StubDir+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatalf("env = %q: the agent must find the stubs before the image's own commands", cmd.Env)
	}
}

func TestWriteStubsNeutralizesHostWideCommands(t *testing.T) {
	root := t.TempDir()
	if err := WriteStubs(root); err != nil {
		t.Fatal(err)
	}
	// blkdeactivate --dmoptions force would replace the host's own
	// device-mapper tables, which look unused from the chroot; reboot and
	// poweroff from a config's install section would reach the host's init.
	for _, name := range []string{"blkdeactivate", "reboot", "poweroff", "shutdown", "halt"} {
		p := filepath.Join(root, StubDir, name)
		if err := exec.CommandContext(t.Context(), p, "--any", "args").Run(); err != nil {
			t.Errorf("%s: %v, want a stub that does nothing and succeeds", name, err)
		}
	}
}

func TestLabelClashes(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"efi", "data", "persistent"} {
		if err := os.Symlink("../../sda1", filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	got := LabelClashes(dir, []string{"efi", "oem", "persistent"})
	slices.Sort(got)
	if want := []string{"efi", "persistent"}; !slices.Equal(got, want) {
		t.Fatalf("clashes = %v, want %v", got, want)
	}
}

func TestTargetsIncludeWhatTheConfigAdds(t *testing.T) {
	cfg := []byte(`#cloud-config
install:
  partitions:
    oem:
      name: myoem
      label: MY_OEM
  extra-partitions:
    - name: data
      label: DATA
      fs: ext4
    - name: raw
      fs: none
`)
	names, labels, err := Targets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The agent formats and mounts what the config declares the same way
	// as its own partitions: by name and by filesystem label.
	for _, want := range []string{"efi", "state", "persistent", "myoem", "data"} {
		if !slices.Contains(names, want) {
			t.Errorf("names = %v, missing %s", names, want)
		}
	}
	if slices.Contains(names, "raw") || slices.Contains(names, "bios") {
		t.Errorf("names = %v: a partition left unformatted, or legacy boot's, is never looked up", names)
	}
	for _, want := range []string{"COS_STATE", "COS_PERSISTENT", "COS_OEM", "MY_OEM", "DATA"} {
		if !slices.Contains(labels, want) {
			t.Errorf("labels = %v, missing %s", labels, want)
		}
	}
	if _, _, err := Targets([]byte("#cloud-config\ninstall: [")); err == nil {
		t.Error("a config that is not YAML must not pass as declaring nothing")
	}
}

func TestLabelClashesMatchUdevLinkNames(t *testing.T) {
	dir := t.TempDir()
	for _, link := range []string{`my\x20data`, `a\x2fb`} {
		if err := os.Symlink("../../sda1", filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	// udev escapes everything outside [A-Za-z0-9#+-.:=@_] and UTF-8 in the
	// link names, so a name with a space or a slash is looked up escaped;
	// unescaped, a slash would also lead out of dir.
	got := LabelClashes(dir, []string{"my data", "a/b", "../escape"})
	if want := []string{"my data", "a/b"}; !slices.Equal(got, want) {
		t.Fatalf("clashes = %q, want %q", got, want)
	}
}

// The agent merges an install section of its own, spelled install, and
// reads the result through viper, which lowercases every key, keeps one of
// two differing only in case at random, and nests a dotted key inside the
// section; any spelling that would read otherwise than written is refused.
func TestTargetsRefuseSpellingsTheAgentReadsOtherwise(t *testing.T) {
	for name, cfg := range map[string]string{
		"Install":                   "#cloud-config\nInstall: {partitions: {oem: {name: myoem}}}\n",
		"INSTALL beside install":    "#cloud-config\ninstall: {device: /dev/sda}\nINSTALL: {reboot: true}\n",
		"dotted at the top":         "#cloud-config\ninstall.partitions.oem.fs: none\n",
		"dotted Install at the top": "#cloud-config\nInstall.device: /dev/sda\n",
		"Device":                    "#cloud-config\ninstall: {Device: /dev/sda}\n",
		"deep":                      "#cloud-config\ninstall: {partitions: {oem: {Name: myoem}}}\n",
		"dotted in the section":     "#cloud-config\ninstall: {partitions.oem: {name: myoem}}\n",
		"in a list entry":           "#cloud-config\ninstall: {extra-partitions: [{name: a, Label: b}]}\n",
		"dotted in a list entry":    "#cloud-config\ninstall: {extra-partitions: [{name: a, name.x: b}]}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Targets([]byte(cfg)); !errors.Is(err, ErrUncheckable) {
				t.Fatalf("err = %v, want ErrUncheckable", err)
			}
		})
	}
	names, labels, err := Targets([]byte("#cloud-config\n1: x\ninstall:\n  device: /dev/sda\n  partitions: {oem: {name: myoem, label: MY_OEM}}\n  extra-partitions: [{name: data, label: DATA, fs: ext4}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "myoem") || !slices.Contains(names, "data") || !slices.Contains(labels, "MY_OEM") || !slices.Contains(labels, "DATA") {
		t.Fatalf("names = %v, labels = %v, want myoem, data, MY_OEM, DATA", names, labels)
	}
}

// The collector fetches config_url spelled exactly so.
func TestTargetsReadConfigURLAsTheCollectorDoes(t *testing.T) {
	if _, _, err := Targets([]byte("#cloud-config\nconfig_url: https://example.com/c.yaml\n")); !errors.Is(err, ErrUncheckable) {
		t.Errorf("config_url gave %v, want ErrUncheckable", err)
	}
	if _, _, err := Targets([]byte("#cloud-config\nConfig_URL: https://example.com/c.yaml\nconfig_url: [x]\n")); err != nil {
		t.Errorf("a key the collector does not fetch refused: %v", err)
	}
}

// Only the install section goes through viper; stages are run as written.
func TestTargetsLeaveTheRestOfTheConfigAlone(t *testing.T) {
	cfg := "#cloud-config\nstages:\n  boot:\n    - environment: {HTTP_PROXY: x, http_proxy: x}\nlabels: {app: a, app.kubernetes.io/name: b}\n"
	if _, _, err := Targets([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
}

// An agent that honours the config's own partitions formats one by name
// only when it has a filesystem, but mounts it by label whatever fs says;
// extra partitions are never mounted.
func TestTargetsCountMountedLabelsOfUnformattedPartitions(t *testing.T) {
	cfg := []byte("#cloud-config\ninstall:\n  partitions: {state: {name: hs, label: HOSTROOT, fs: none}}\n  extra-partitions: [{name: xs, label: XS, fs: none}]\n")
	names, labels, err := Targets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(labels, "HOSTROOT") || slices.Contains(labels, "XS") {
		t.Errorf("labels = %v, want HOSTROOT, not XS", labels)
	}
	if slices.Contains(names, "hs") || slices.Contains(names, "xs") {
		t.Errorf("names = %v: an unformatted partition is not looked up by name", names)
	}
}

// The agent creates its bios partition but never looks one up by name: it
// skips it when formatting, and grub-install finds it on the device it is
// given by its type GUID.
func TestHostBIOSPartitionDoesNotClash(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("../../sda14", filepath.Join(dir, "bios")); err != nil {
		t.Fatal(err)
	}
	names, _, err := Targets([]byte("#cloud-config\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := LabelClashes(dir, names); len(got) != 0 {
		t.Fatalf("clashes = %v", got)
	}
}
