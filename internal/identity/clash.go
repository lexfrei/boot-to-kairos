package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"
)

// ErrAccountClash refuses a carried user that has the name of a user or
// group of the image, which yip would rewrite into that account.
var ErrAccountClash = errors.New("a carried user has the name of an account of the image")

// Clashes returns the users cfg carries over whose names the image unpacked
// at root already uses for a user or a group.
func Clashes(cfg []byte, root string) ([]string, error) {
	var c struct {
		Stages map[string][]struct {
			Name  string               `yaml:"name"`
			Users map[string]yaml.Node `yaml:"users"`
		} `yaml:"stages"`
	}
	if err := yaml.Unmarshal(cfg, &c); err != nil {
		return nil, errors.Wrap(err, "parse cloud-config")
	}
	var carried []string
	for _, e := range c.Stages["initramfs"] {
		if e.Name == fmt.Sprintf(stageName, "SSH logins and hostname") {
			for u := range e.Users {
				carried = append(carried, u)
			}
		}
	}
	if len(carried) == 0 {
		return nil, nil
	}
	var users, groups []string
	for f, names := range map[string]*[]string{"etc/passwd": &users, "etc/group": &groups} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return nil, errors.Wrapf(err, "read the image's /%s", f)
		}
		for l := range strings.Lines(string(b)) {
			if name, _, ok := strings.Cut(l, ":"); ok {
				*names = append(*names, name)
			}
		}
	}
	var out []string
	for _, u := range carried {
		// yip only adds keys to a user the image has already, which is
		// what carrying onto kairos means.
		if u == kairosUser && slices.Contains(users, u) {
			continue
		}
		if slices.Contains(users, u) || slices.Contains(groups, u) {
			out = append(out, u)
		}
	}
	slices.Sort(out)
	return out, nil
}
