package cloudconfig

import (
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type entry struct {
	Name string `yaml:"name"`
}

func appendAll(t *testing.T, cfg string, stages ...string) map[string]any {
	t.Helper()
	d, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stages {
		if err := d.Append(s, entry{Name: "added"}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "#cloud-config\n") {
		t.Errorf("no #cloud-config header:\n%s", out)
	}
	var m map[string]any
	if err := yaml.Unmarshal(out, &m); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	return m
}

func TestAppendCreatesStages(t *testing.T) {
	for _, cfg := range []string{
		"", "#cloud-config\n", "#cloud-config\nstages:\n", "#cloud-config\nstages:\n  boot:\n",
		// The agent reads a null document as an empty config.
		"#cloud-config\n---\n", "#cloud-config\n~\n", "#cloud-config\n--- !!null\n",
	} {
		m := appendAll(t, cfg, "boot", "initramfs.before")
		st, _ := m["stages"].(map[string]any)
		for _, s := range []string{"boot", "initramfs.before"} {
			seq, _ := st[s].([]any)
			if len(seq) != 1 || seq[0].(map[string]any)["name"] != "added" {
				t.Errorf("%q: %s = %v", cfg, s, st[s])
			}
		}
	}
}

func TestAppendKeepsWhatIsThere(t *testing.T) {
	m := appendAll(t, "#cloud-config\nhostname: x # mine\nstages:\n  boot:\n    - name: mine\n", "boot")
	if m["hostname"] != "x" {
		t.Errorf("hostname = %v", m["hostname"])
	}
	seq := m["stages"].(map[string]any)["boot"].([]any)
	if len(seq) != 2 || seq[0].(map[string]any)["name"] != "mine" || seq[1].(map[string]any)["name"] != "added" {
		t.Errorf("boot = %v, want the user's entry first", seq)
	}
}

// The user's stages are extended wherever YAML puts them, and a node
// several keys share through an alias is extended once per key.
func TestAppendFollowsAliasesAndMerges(t *testing.T) {
	for _, cfg := range []string{
		"#cloud-config\nx: &s {boot: [{name: mine}]}\nstages: *s\n",
		"#cloud-config\nl: &l [{name: mine}]\nstages: {boot: *l, initramfs: *l}\n",
		"#cloud-config\nbase: &b {stages: {boot: [{name: mine}]}}\n<<: *b\n",
		"#cloud-config\nbase: &b {boot: [{name: mine}]}\nstages: {<<: *b}\n",
	} {
		m := appendAll(t, cfg, "boot")
		seq, _ := m["stages"].(map[string]any)["boot"].([]any)
		if len(seq) != 2 || seq[0].(map[string]any)["name"] != "mine" || seq[1].(map[string]any)["name"] != "added" {
			t.Errorf("%q: boot = %v, want the user's entry and one added after it", cfg, seq)
		}
		if l, ok := m["l"].([]any); ok && len(l) != 1 {
			t.Errorf("%q: l = %v, want it left as written", cfg, l)
		}
		if init, ok := m["stages"].(map[string]any)["initramfs"].([]any); ok && len(init) != 1 {
			t.Errorf("%q: initramfs = %v, extended through the shared alias", cfg, init)
		}
	}
}

func TestResolveReadsAsTheDecoderDoes(t *testing.T) {
	for _, cfg := range []string{
		"a: &a {k: 1}\nx: {!!merge foo: *a, k: 2}\n",
		"a: &a {k: 1}\nx: {\"<<\": *a, k: 2}\n",
		"a: &a {0x10: m}\nx: {<<: *a, 16: w}\n",
		"a: &a {k: 1}\nb: &b {k: 2, j: 3}\nx: {<<: [*a, *b]}\n",
		"a: &a {k: 1}\nn: &n {<<: *a, j: 2}\nx: *n\ny: {<<: *n, k: 5}\n",
		"x: {a}\n",
		"x: {a: }\n",
		"x: [a, {b}]\n",
		"x: {a: ~}\n",
		"x: {a: ''}\n",
		"x: {a: \"\"}\n",
	} {
		var want, got any
		if err := yaml.Unmarshal([]byte(cfg), &want); err != nil {
			t.Fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(cfg), &doc); err != nil {
			t.Fatal(err)
		}
		r, err := resolve(doc.Content[0])
		if err != nil {
			t.Fatalf("%q: %v", cfg, err)
		}
		out, err := yaml.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(out, &got); err != nil {
			t.Fatalf("%q resolved to:\n%s%v", cfg, out, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q resolved reads %v, want %v", cfg, got, want)
		}
	}
}

func TestRefusesWhatItCannotExtend(t *testing.T) {
	for _, cfg := range []string{"#cloud-config\nstages: none\n", "#cloud-config\nstages:\n  boot: none\n"} {
		d, err := Parse([]byte(cfg))
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Append("boot", entry{}); err == nil {
			t.Errorf("%q: no error", cfg)
		}
	}
	for _, cfg := range []string{
		"#cloud-config\n- a list\n",
		"#cloud-config\na scalar\n",
		"#cloud-config\n<<: 5\n",
		"#cloud-config\na: &a [*a]\n",
		"#cloud-config\na: &a {<<: *a}\n",
	} {
		if _, err := Parse([]byte(cfg)); err == nil {
			t.Errorf("%q: no error", cfg)
		}
	}
}
