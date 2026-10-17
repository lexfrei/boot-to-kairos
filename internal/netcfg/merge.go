package netcfg

import (
	"bytes"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"

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
// and initramfs stages, after whatever the user put there. kairos-agent
// re-encodes the whole configuration when it stores it, so re-encoding it
// here loses nothing the agent would keep.
func Inject(cfg []byte, files []File) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(cfg, &doc); err != nil {
		return nil, errors.Wrap(err, "parse cloud-config")
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root, err := resolve(doc.Content[0])
	if err != nil {
		return nil, err
	}
	if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
		root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	doc.Content[0] = root
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("the cloud-config is not a mapping")
	}
	st, err := child(root, "stages", yaml.MappingNode)
	if err != nil {
		return nil, err
	}
	for _, name := range stages {
		seq, err := child(st, name, yaml.SequenceNode)
		if err != nil {
			return nil, err
		}
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
		var n yaml.Node
		if err := n.Encode(entry); err != nil {
			return nil, errors.Wrap(err, "encode network stage")
		}
		seq.Content = append(seq.Content, &n)
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, errors.Wrap(err, "encode cloud-config")
	}
	out := b.Bytes()
	if !bytes.HasPrefix(out, []byte("#cloud-config")) {
		out = append([]byte("#cloud-config\n"), out...)
	}
	return out, nil
}

// resolve returns a copy of n with every alias replaced by a copy of the
// node it names and every merge key by the keys it merges, read as the
// YAML decoder reads them, so that extending one place in it extends no
// other, and a key the user merged in is extended rather than shadowed.
// The parse in kairos.Targets has refused excessive aliasing by the time
// this runs.
func resolve(n *yaml.Node) (*yaml.Node, error) {
	return resolver{}.resolve(n)
}

// resolver holds the anchors being expanded, as a node parse accepts one
// that contains itself.
type resolver map[*yaml.Node]bool

func (r resolver) resolve(n *yaml.Node) (*yaml.Node, error) {
	if n.Kind == yaml.AliasNode {
		if r[n.Alias] {
			return nil, errors.Newf("cloud-config anchor %s contains itself", n.Value)
		}
		r[n.Alias] = true
		defer delete(r, n.Alias)
		return r.resolve(n.Alias)
	}
	c := *n
	c.Anchor = ""
	c.Content = nil
	var merged []*yaml.Node
	for i := 0; i < len(n.Content); i++ {
		e, err := r.resolve(n.Content[i])
		if err != nil {
			return nil, err
		}
		if n.Kind != yaml.MappingNode || i%2 == 1 || !isMerge(n.Content[i]) {
			c.Content = append(c.Content, e)
			continue
		}
		i++
		v, err := r.resolve(n.Content[i])
		if err != nil {
			return nil, err
		}
		// Of keys merged from a list, the earlier mapping's win.
		from := []*yaml.Node{v}
		if v.Kind == yaml.SequenceNode {
			from = v.Content
		}
		for _, m := range from {
			if m.Kind != yaml.MappingNode {
				return nil, errors.Newf("cloud-config merges a %s, not a mapping, at line %d", m.ShortTag(), m.Line)
			}
			merged = append(merged, m.Content...)
		}
	}
	// A key written in the mapping wins over a merged one.
	for i := 0; i+1 < len(merged); i += 2 {
		if !hasKey(&c, merged[i]) {
			c.Content = append(c.Content, merged[i], merged[i+1])
		}
	}
	return &c, nil
}

// isMerge is the decoder's test: a key tagged !!merge, explicitly or not,
// is a merge only when spelled <<.
func isMerge(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == "<<" && k.ShortTag() == "!!merge"
}

// hasKey compares keys decoded, as a merge does, so 0x10 and 16 are one
// key. "1" and 1 are one too, though a merge keeps both: the decoder
// refuses them written side by side, which the result would be.
func hasKey(m, key *yaml.Node) bool {
	var want any
	wantErr := key.Decode(&want)
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key.Value {
			return true
		}
		var k any
		if wantErr == nil && m.Content[i].Decode(&k) == nil && reflect.DeepEqual(k, want) {
			return true
		}
	}
	return false
}

// child returns the value of key in m, added empty if missing.
func child(m *yaml.Node, key string, kind yaml.Kind) (*yaml.Node, error) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		v := m.Content[i+1]
		if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
			v.Kind, v.Tag, v.Value = kind, "", ""
		}
		if v.Kind != kind {
			return nil, errors.Newf("cloud-config key %s is not a %s", key, map[yaml.Kind]string{yaml.MappingNode: "mapping", yaml.SequenceNode: "list"}[kind])
		}
		return v, nil
	}
	v := &yaml.Node{Kind: kind}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, v)
	return v, nil
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
