//go:build linux

package install

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestDatasourcesAreTurnedOff(t *testing.T) {
	out, why, err := blockDatasources([]byte("#cloud-config\nstages:\n  after-install-chroot:\n    - name: mine\n"))
	if err != nil || why != "" {
		t.Fatalf("blockDatasources = %q, %v", why, err)
	}
	var c struct {
		Stages map[string][]struct {
			Name        string `yaml:"name"`
			Directories []struct {
				Path        string `yaml:"path"`
				Permissions uint32 `yaml:"permissions"`
			} `yaml:"directories"`
		} `yaml:"stages"`
	}
	if err := yaml.Unmarshal(out, &c); err != nil {
		t.Fatal(err)
	}
	s := c.Stages["after-install-chroot"]
	if len(s) != 2 || s[0].Name != "mine" || len(s[1].Directories) != 1 || s[1].Directories[0].Path != "/oem/95_userdata" || s[1].Directories[0].Permissions != 0o700 {
		t.Errorf("after-install-chroot = %+v: Kairos pulls a datasource on every boot until /oem/95_userdata exists", s)
	}
}

func TestDatasourcesStayWhenTheCloudConfigAsks(t *testing.T) {
	for _, cfg := range []string{
		"#cloud-config\nstages:\n  rootfs.before:\n    - datasource:\n        providers: [hetzner]\n        path: /oem/95_userdata\n",
		"#cloud-config\nstages:\n  boot:\n    - files:\n        - path: /oem/95_userdata/x.yaml\n",
		"#cloud-config\nstages:\n  boot:\n    - directories:\n        - path: /oem/95_userdata\n",
		"#cloud-config\nstages:\n  boot:\n    - downloads:\n        - path: /oem/95_userdata/y.yaml\n",
	} {
		out, why, err := blockDatasources([]byte(cfg))
		if err != nil || why == "" || string(out) != cfg {
			t.Errorf("%q: why %q, err %v, out %q", cfg, why, err, out)
		}
	}
}

func TestDryRunSaysTheDatasourcesAreOff(t *testing.T) {
	for cfg, want := range map[string]string{
		plainConfig: `(?m)^  cloud datasources: +off: Kairos will not apply user-data from a NoCloud seed, a config drive or a cloud metadata service$`,
		"#cloud-config\nstages:\n  network:\n    - datasource:\n        providers: [aws]\n": `(?m)^  cloud datasources: +left on: its network stage pulls a datasource$`,
	} {
		stubMachine(t)
		var out bytes.Buffer
		o := Options{Disk: "/dev/vda", DryRun: true, ConfigPath: "cfg.yaml"}
		if err := proceed(context.Background(), o, []byte(cfg), &Plan{}, strings.NewReader(""), &out, new(bool)); err != nil {
			t.Fatalf("proceed = %v", err)
		}
		if !regexp.MustCompile(want).MatchString(out.String()) {
			t.Errorf("summary does not match %s:\n%s", want, out.String())
		}
		if blocked := strings.Contains(string(builtConfig), "/oem/95_userdata"); blocked != (cfg == plainConfig) {
			t.Errorf("%q: the build got %q", cfg, builtConfig)
		}
	}
}
