//go:build linux

package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lexfrei/boot-to-kairos/internal/identity"
)

func TestBuildRefusesACarriedUserTheImageHas(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for f, c := range map[string]string{"etc/passwd": "root:x:0:0::/root:/bin/sh\n", "etc/group": "root:x:0:\nubuntu:x:999:\n"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	host := identityHost(ubuntuUser)
	cfg, _, err := identity.Carry([]byte("#cloud-config\n"), func() (*identity.Host, error) { return host(context.Background()) }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	err = checkClashes(cfg, root)
	if !errors.Is(err, identity.ErrAccountClash) || errorClass(err) != "account-clash" || !strings.Contains(err.Error(), "ubuntu") {
		t.Fatalf("checkClashes = %v (class %s)", err, errorClass(err))
	}
	if err := checkClashes([]byte(plainConfig), root); err != nil {
		t.Errorf("checkClashes without carried users = %v", err)
	}
}
