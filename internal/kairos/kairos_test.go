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
	names, labels, err := Targets(cfg, nil)
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
	if _, _, err := Targets([]byte("#cloud-config\ninstall: ["), nil); err == nil {
		t.Error("a config that is not YAML must not pass as declaring nothing")
	}
}

func TestTargetsReadTheKernelCommandLine(t *testing.T) {
	// The agent merges install.* keys from the host's /proc/cmdline into
	// its config.
	cmdline := []byte("BOOT_IMAGE=/vmlinuz root=/dev/sda2 install.partitions.state.name=sys install.partitions.state.label=SYS quiet\n")
	names, labels, err := Targets([]byte("#cloud-config\n"), cmdline)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "sys") || !slices.Contains(labels, "SYS") {
		t.Fatalf("names = %v, labels = %v, want sys and SYS from the command line", names, labels)
	}
	if _, _, err := Targets([]byte("#cloud-config\n"), []byte("install.extra-partitions=x\n")); err == nil {
		t.Fatal("extra partitions on the command line cannot be read reliably and must be refused")
	}
}

func TestTargetsRefuseConfigFetchedElsewhere(t *testing.T) {
	// kairos-agent fetches and merges these, recursively, and what they
	// declare is formatted by name like the rest.
	for name, in := range map[string][2]string{
		"config_url in the file": {"#cloud-config\nconfig_url: https://example.com/c.yaml\n", ""},
		"kairos.config_url=":     {"#cloud-config\n", "quiet kairos.config_url=https://example.com/c.yaml"},
		"kairos.config=":         {"#cloud-config\n", `kairos.config="install: {}"`},
		"cos.setup=":             {"#cloud-config\n", "cos.setup=https://example.com/c.yaml"},
		"config_url= on cmdline": {"#cloud-config\n", "config_url=https://example.com/c.yaml"},
		"after an escaped quote": {"#cloud-config\n", `k="a\"b" config_url=https://example.com/c.yaml`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Targets([]byte(in[0]), []byte(in[1])); err == nil {
				t.Fatal("a configuration fetched or merged from elsewhere cannot be checked and must be refused")
			}
		})
	}
}

func TestTargetsReadQuotedCommandLineValues(t *testing.T) {
	cmdline := []byte(`quiet install.partitions.state.name="my state" install.partitions.state.label='my label'`)
	names, labels, err := Targets([]byte("#cloud-config\n"), cmdline)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "my state") || !slices.Contains(labels, "my label") {
		t.Fatalf("names = %q, labels = %q: a quoted value with spaces is one, in single quotes too as the agent reads them", names, labels)
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
