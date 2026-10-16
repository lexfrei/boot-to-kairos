package netcfg

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"

	"github.com/lexfrei/boot-to-kairos/internal/cloudconfig"
	"github.com/lexfrei/boot-to-kairos/internal/kairos"
)

// stages are where the carried files are written, as Kairos writes its own
// default network configuration: rootfs.before runs in the initramfs, whose
// own networkd would otherwise bring the links up with DHCP; initramfs runs
// chrooted into the installed system before its networkd starts, and its
// networkctl reload makes the initramfs's networkd, already running, read
// the files rootfs.before wrote.
var stages = []string{"rootfs.before", "initramfs"} //nolint:gochecknoglobals // fixed list

const stageName = "boot-to-kairos: network carried over from the replaced system"

type yipFile struct {
	Path string `yaml:"path"`
	// 420 is 0644: decimal reads the same under every YAML version.
	Permissions uint32 `yaml:"permissions"`
	Owner       int    `yaml:"owner"`
	Group       int    `yaml:"group"`
	Content     string `yaml:"content"`
}

type yipDir struct {
	Path        string `yaml:"path"`
	Permissions uint32 `yaml:"permissions"`
	Owner       int    `yaml:"owner"`
	Group       int    `yaml:"group"`
}

type yipStage struct {
	Name string `yaml:"name"`
	// yip creates a missing parent of a file as 0744, which services not
	// running as root, systemd-resolved among them, cannot read; it creates
	// directories before it writes files.
	Directories []yipDir  `yaml:"directories"`
	Files       []yipFile `yaml:"files"`
	Commands    []string  `yaml:"commands,omitempty"`
}

// Inject appends a stage writing files to the cloud-config's rootfs.before
// and initramfs stages, after whatever the user put there.
func Inject(cfg []byte, files []File) ([]byte, error) {
	doc, err := cloudconfig.Parse(cfg)
	if err != nil {
		return nil, err
	}
	for _, name := range stages {
		entry := yipStage{Name: stageName}
		for _, f := range files {
			if dir := path.Dir(f.Path); !slices.ContainsFunc(entry.Directories, func(d yipDir) bool { return d.Path == dir }) {
				entry.Directories = append(entry.Directories, yipDir{Path: dir, Permissions: 0o755})
			}
			entry.Files = append(entry.Files, yipFile{Path: f.Path, Permissions: 0o644, Content: f.Content})
		}
		if name == "initramfs" {
			entry.Commands = []string{"networkctl reload"}
		}
		if err := doc.Append(name, entry); err != nil {
			return nil, err
		}
	}
	return doc.Bytes()
}

// networkPaths are where a cloud-config configures systemd-networkd or
// systemd-resolved.
var networkPaths = []string{ //nolint:gochecknoglobals // fixed list
	"/etc/systemd/network/", "/run/systemd/network/", "/etc/systemd/resolved.conf", "/etc/resolv.conf",
}

// UserConfigures returns why cfg configures the network itself, or "". The
// user's configuration then wins whole: networkd applies the first .network
// file matching a link, and whether the user's match covers a link the way
// a carried file would cannot be told from here.
func UserConfigures(cfg []byte) (string, error) {
	var c struct {
		Stages map[string][]struct {
			Files     []struct{ Path string } `yaml:"files"`
			Downloads []struct{ Path string } `yaml:"downloads"`
			DNS       yaml.Node               `yaml:"dns"`
		} `yaml:"stages"`
		Install struct {
			GrubOptions map[string]any `yaml:"grub_options"` //nolint:tagliatelle // Kairos's key
		} `yaml:"install"`
	}
	if err := yaml.Unmarshal(cfg, &c); err != nil {
		return "", errors.Mark(errors.Wrap(err, "parse cloud-config"), kairos.ErrBadConfig)
	}
	for name, entries := range c.Stages {
		for i := range entries {
			e := &entries[i]
			for _, f := range append(e.Files, e.Downloads...) {
				for _, p := range networkPaths {
					if strings.HasPrefix(path.Clean(f.Path), p) {
						return fmt.Sprintf("its %s stage writes %s", name, f.Path), nil
					}
				}
			}
			if e.DNS.Kind != 0 && e.DNS.Tag != "!!null" {
				return fmt.Sprintf("its %s stage sets dns", name), nil
			}
		}
	}
	for key, v := range c.Install.GrubOptions {
		for w := range strings.FieldsSeq(fmt.Sprint(v)) {
			if strings.HasPrefix(w, "ip=") {
				return fmt.Sprintf("install.grub_options.%s passes %s to the kernel", key, w), nil
			}
		}
	}
	return "", nil
}

const optOut = "; to install without carrying the network over, pass --keep-network=false"

// Carry returns cfg with the host's network configuration added to it. cfg
// comes back as it is when the user's configuration sets up the network
// itself, or when Kairos's default DHCP covers everything.
func Carry(cfg []byte, capture func() (*Host, error), logf func(string, ...any)) ([]byte, Carried, error) {
	why, err := UserConfigures(cfg)
	if err != nil {
		return nil, Carried{}, err
	}
	if why != "" {
		reason := "the cloud-config configures it: " + why
		logf("network: not carried over, as %s", reason)
		return cfg, Carried{Reason: reason}, nil
	}
	h, err := capture()
	if err != nil {
		return nil, Carried{}, errors.Wrap(err, "read the network configuration"+optOut)
	}
	files, p, err := plan(h)
	if err != nil {
		return nil, Carried{}, errors.Wrap(err, "carry the network configuration"+optOut)
	}
	for _, n := range p.notes {
		logf("network: %s", n)
	}
	if len(files) == 0 {
		reason := "nothing to carry over; Kairos brings its NICs up with DHCP"
		logf("network: %s", reason)
		return cfg, Carried{Reason: reason}, nil
	}
	c := Carried{Addresses: p.addrs, Routes: p.routeList}
	for _, f := range files {
		logf("network: carrying %s", f.Path)
		c.Files = append(c.Files, f.Path)
	}
	out, err := Inject(cfg, files)
	if err != nil {
		return nil, Carried{}, err
	}
	return out, c, nil
}

// Carried is what Carry carried over: the files it writes, and the static
// addresses and routes they set, each prefixed with its interface.
type Carried struct {
	// Reason is why nothing was carried, "" when something was.
	Reason                   string
	Files, Addresses, Routes []string
}
