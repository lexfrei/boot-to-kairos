//go:build linux

package install

import (
	"fmt"
	"path"
	"strings"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"

	"github.com/lexfrei/boot-to-kairos/internal/cloudconfig"
)

// userdataDir is where the image's /system/oem/00_datasource.yaml stores
// the user-data it pulls from a NoCloud seed, a config drive or a cloud
// metadata service. It probes on every boot until the directory exists,
// then applies what it stored on every boot after. That user-data was
// written for the replaced system, and it creates users with empty
// passwords as readily as anything else.
const userdataDir = "/oem/95_userdata"

type dirEntry struct {
	Path        string `yaml:"path"`
	Permissions uint32 `yaml:"permissions"`
}

type datasourceStage struct {
	Name        string     `yaml:"name"`
	Directories []dirEntry `yaml:"directories"`
}

// blockDatasources returns cfg with a stage that creates userdataDir empty
// at install, so the image never pulls a datasource, or cfg as it is and
// why when the cloud-config uses a datasource itself. after-install-chroot
// is the last stage with the OEM partition at /oem; the first boot probes
// before any stage of the cloud-config runs.
func blockDatasources(cfg []byte) ([]byte, string, error) {
	why, err := usesDatasource(cfg)
	if err != nil || why != "" {
		return cfg, why, err
	}
	doc, err := cloudconfig.Parse(cfg)
	if err != nil {
		return nil, "", err
	}
	if err := doc.Append("after-install-chroot", datasourceStage{
		Name:        "boot-to-kairos: no user-data from the replaced system's datasources",
		Directories: []dirEntry{{Path: userdataDir, Permissions: 0o700}},
	}); err != nil {
		return nil, "", err
	}
	out, err := doc.Bytes()
	return out, "", err
}

func usesDatasource(cfg []byte) (string, error) {
	type pathed struct{ Path string }
	var c struct {
		Stages map[string][]struct {
			Datasource struct {
				Providers []string `yaml:"providers"`
			} `yaml:"datasource"`
			Files       []pathed `yaml:"files"`
			Downloads   []pathed `yaml:"downloads"`
			Directories []pathed `yaml:"directories"`
		} `yaml:"stages"`
	}
	if err := yaml.Unmarshal(cfg, &c); err != nil {
		return "", errors.Wrap(err, "parse the cloud-config for its datasources")
	}
	for name, entries := range c.Stages {
		for _, e := range entries {
			if len(e.Datasource.Providers) > 0 {
				return fmt.Sprintf("its %s stage pulls a datasource", name), nil
			}
			for _, f := range append(append(e.Files, e.Downloads...), e.Directories...) {
				if p := path.Clean(f.Path); p == userdataDir || strings.HasPrefix(p, userdataDir+"/") {
					return fmt.Sprintf("its %s stage writes %s", name, f.Path), nil
				}
			}
		}
	}
	return "", nil
}

func (p *Plan) addDatasources(why string) {
	if why != "" {
		p.Add("cloud datasources", "left on: "+why)
		return
	}
	p.Add("cloud datasources", "off: Kairos will not apply user-data from a NoCloud seed, a config drive or a cloud metadata service")
}
