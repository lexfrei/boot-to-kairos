//go:build linux

package netcfg

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/lexfrei/boot-to-kairos/internal/kairos"
)

type yipConfig struct {
	Users  []map[string]any `yaml:"users"`
	Stages map[string][]struct {
		Name  string `yaml:"name"`
		Files []struct {
			Path        string `yaml:"path"`
			Content     string `yaml:"content"`
			Permissions uint32 `yaml:"permissions"`
			Owner       int    `yaml:"owner"`
			Group       int    `yaml:"group"`
		} `yaml:"files"`
		Directories []struct {
			Path        string `yaml:"path"`
			Permissions uint32 `yaml:"permissions"`
		} `yaml:"directories"`
		Commands []string `yaml:"commands"`
	} `yaml:"stages"`
}

var errBoom = errors.New("boom")

var carried = []File{
	{Path: "/etc/systemd/network/10-btk-x.network", Content: "[Match]\nName=x\n"},
	{Path: "/etc/systemd/resolved.conf.d/10-btk.conf", Content: "[Resolve]\nDNS=192.0.2.53\n"},
}

func inject(t *testing.T, cfg string) yipConfig {
	t.Helper()
	out, err := Inject([]byte(cfg), carried)
	if err != nil {
		t.Fatal(err)
	}
	if err := kairos.CheckConfig(out); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	if _, _, err := kairos.Targets(out, nil); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	var c yipConfig
	if err := yaml.Unmarshal(out, &c); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	return c
}

func TestInjectWithoutStages(t *testing.T) {
	c := inject(t, "#cloud-config\nusers:\n  - name: kairos # me\n")
	if len(c.Users) != 1 || c.Users[0]["name"] != "kairos" {
		t.Errorf("users = %v", c.Users)
	}
	for _, stage := range []string{"rootfs.before", "initramfs"} {
		s := c.Stages[stage]
		if len(s) != 1 || len(s[0].Files) != len(carried) {
			t.Fatalf("%s = %+v", stage, s)
		}
		for i, f := range s[0].Files {
			if f.Path != carried[i].Path || f.Content != carried[i].Content || f.Permissions != 0o644 || f.Owner != 0 || f.Group != 0 {
				t.Errorf("%s file = %+v", stage, f)
			}
		}
		// yip would create a missing parent as 0744, which systemd-resolved,
		// not running as root, cannot read.
		dirs := map[string]uint32{}
		for _, d := range s[0].Directories {
			dirs[d.Path] = d.Permissions
		}
		if dirs["/etc/systemd/resolved.conf.d"] != 0o755 || dirs["/etc/systemd/network"] != 0o755 || len(dirs) != 2 {
			t.Errorf("%s directories = %v, want each parent 0755", stage, dirs)
		}
	}
	if cmds := c.Stages["initramfs"][0].Commands; len(cmds) != 1 || cmds[0] != "networkctl reload" {
		t.Errorf("initramfs commands = %v: networkd must re-read the files it already started with", cmds)
	}
}

func TestInjectAppendsToUserStages(t *testing.T) {
	c := inject(t, `#cloud-config
stages:
  initramfs:
    - name: mine
      commands: [echo hi]
  boot:
    - name: later
`)
	if s := c.Stages["initramfs"]; len(s) != 2 || s[0].Name != "mine" || len(s[1].Files) != len(carried) {
		t.Errorf("initramfs = %+v, want the user's entry first", s)
	}
	if s := c.Stages["boot"]; len(s) != 1 || s[0].Name != "later" {
		t.Errorf("boot = %+v", s)
	}
}

func TestInjectIntoAnEmptyConfig(t *testing.T) {
	c := inject(t, "#cloud-config\n")
	if len(c.Stages["initramfs"]) != 1 {
		t.Errorf("stages = %+v", c.Stages)
	}
}

func TestInjectRefusesWhatItCannotExtend(t *testing.T) {
	for _, cfg := range []string{
		"#cloud-config\nstages: none\n",
		"#cloud-config\nstages:\n  initramfs: none\n",
		"#cloud-config\n- a list\n",
	} {
		if _, err := Inject([]byte(cfg), carried); err == nil {
			t.Errorf("%q: no error", cfg)
		}
	}
}

func TestUserConfigures(t *testing.T) {
	for cfg, want := range map[string]bool{
		"#cloud-config\nstages:\n  initramfs:\n    - files:\n        - path: /etc/systemd/network/01-static.network\n":      true,
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /run/systemd/network/x.network\n":                   true,
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc/systemd/resolved.conf\n":                       true,
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc/systemd/resolved.conf.d/dns.conf\n":            true,
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc/resolv.conf\n":                                 true,
		"#cloud-config\nstages:\n  boot:\n    - downloads:\n        - path: /etc/systemd/network/x.netdev\n":                true,
		"#cloud-config\nstages:\n  boot:\n    - dns:\n        nameservers: [192.0.2.53]\n":                                  true,
		"#cloud-config\ninstall:\n  grub_options:\n    extra_cmdline: console=tty1 ip=192.0.2.5::192.0.2.1:255.255.255.0\n": true,
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc/hosts\n":                                       false,
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /etc//systemd/./network/x.network\n":                true,
		"#cloud-config\ninstall:\n  grub_options:\n    extra_cmdline: noip=1\n":                                             false,
		"#cloud-config\nusers:\n  - name: kairos\n":                                                                         false,
	} {
		why, err := UserConfigures([]byte(cfg))
		if err != nil {
			t.Fatalf("%q: %v", cfg, err)
		}
		if (why != "") != want {
			t.Errorf("%q: reason %q, want configured = %v", cfg, why, want)
		}
	}
}

func TestCarry(t *testing.T) {
	static := &Host{
		Links:  []Link{nic(2, "lan0", "52:54:00:12:34:56", Addr{Prefix: netip.MustParsePrefix("10.0.2.50/24"), Global: true})},
		Routes: []Route{route("0.0.0.0/0", "10.0.2.2", 2), route("198.51.100.0/24", "", 2)},
	}
	team := nic(2, "eth0", "52:54:00:12:34:56")
	team.Master = 9
	refused := &Host{Links: []Link{team, {Index: 9, Name: "team0", Kind: "team"}}}
	dhcpOnly := &Host{Links: []Link{nic(2, "lan0", "52:54:00:12:34:56")}}
	user := "#cloud-config\nstages:\n  initramfs:\n    - files:\n        - path: /etc/systemd/network/01-static.network\n"
	plain := "#cloud-config\nusers:\n  - name: kairos\n"
	quiet := func(string, ...any) {}

	t.Run("user wins", func(t *testing.T) {
		out, got, err := Carry([]byte(user), func() (*Host, error) {
			t.Error("captured although the user configures the network")
			return nil, errBoom
		}, quiet)
		if err != nil || string(out) != user {
			t.Errorf("out %q, err %v", out, err)
		}
		if !strings.Contains(got.Reason, "the cloud-config configures it") || got.Files != nil {
			t.Errorf("carried = %+v, want the reason the user's configuration wins", got)
		}
	})
	t.Run("refused", func(t *testing.T) {
		_, _, err := Carry([]byte(plain), func() (*Host, error) { return refused, nil }, quiet)
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "--keep-network=false") {
			t.Errorf("err = %v, want ErrUnsupported naming the flag", err)
		}
	})
	t.Run("nothing to carry", func(t *testing.T) {
		out, got, err := Carry([]byte(plain), func() (*Host, error) { return dhcpOnly, nil }, quiet)
		if err != nil || string(out) != plain {
			t.Errorf("out %q, err %v", out, err)
		}
		if !strings.Contains(got.Reason, "DHCP") || got.Files != nil {
			t.Errorf("carried = %+v, want the reason nothing is carried", got)
		}
	})
	t.Run("carried", func(t *testing.T) {
		out, got, err := Carry([]byte(plain), func() (*Host, error) { return static, nil }, quiet)
		if err != nil || !strings.Contains(string(out), "10.0.2.50/24") || !strings.Contains(string(out), "name: kairos") {
			t.Errorf("out %q, err %v", out, err)
		}
		want := Carried{
			Files:     []string{"/etc/systemd/network/10-btk-525400123456.network"},
			Addresses: []string{"lan0 10.0.2.50/24"},
			Routes:    []string{"lan0 default via 10.0.2.2", "lan0 198.51.100.0/24"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("carried = %+v, want %+v", got, want)
		}
	})
	t.Run("capture fails", func(t *testing.T) {
		if _, _, err := Carry([]byte(plain), func() (*Host, error) { return nil, errBoom }, quiet); !errors.Is(err, errBoom) ||
			!strings.Contains(err.Error(), "--keep-network=false") {
			t.Errorf("err = %v", err)
		}
	})
}
