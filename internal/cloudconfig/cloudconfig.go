// Package cloudconfig adds yip stage entries to a user's cloud-config.
// kairos-agent re-encodes the whole configuration when it stores it, so
// re-encoding it here loses nothing the agent would keep.
package cloudconfig

import (
	"bytes"
	"reflect"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"
)

// Doc is a parsed cloud-config.
type Doc struct {
	doc  yaml.Node
	root *yaml.Node
}

// Parse parses cfg, which may be empty or null.
func Parse(cfg []byte) (*Doc, error) {
	d := &Doc{}
	if err := yaml.Unmarshal(cfg, &d.doc); err != nil {
		return nil, errors.Wrap(err, "parse cloud-config")
	}
	if len(d.doc.Content) == 0 {
		d.doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root, err := resolve(d.doc.Content[0])
	if err != nil {
		return nil, err
	}
	if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
		root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	d.doc.Content[0], d.root = root, root
	if d.root.Kind != yaml.MappingNode {
		return nil, errors.New("the cloud-config is not a mapping")
	}
	return d, nil
}

// Append adds entry at the end of stages.<stage>, after whatever the user
// put there.
func (d *Doc) Append(stage string, entry any) error {
	st, err := child(d.root, "stages", yaml.MappingNode)
	if err != nil {
		return err
	}
	seq, err := child(st, stage, yaml.SequenceNode)
	if err != nil {
		return err
	}
	var n yaml.Node
	if err := n.Encode(entry); err != nil {
		return errors.Wrapf(err, "encode %s stage", stage)
	}
	seq.Content = append(seq.Content, &n)
	return nil
}

// Bytes encodes the cloud-config, with the #cloud-config header Kairos
// needs to read it as one.
func (d *Doc) Bytes() ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&d.doc); err != nil {
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
	// The encoder writes an empty null as '', which reads back as a string.
	if c.ShortTag() == "!!null" {
		c.Value = "~"
	}
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
