//go:build linux

package mountns

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testDirEnv = "BOOT_TO_KAIROS_NS_TEST_DIR"

// TestMain doubles as the child: re-run in its own namespace, it mounts a
// tmpfs on the directory it is given and exits.
func TestMain(m *testing.M) {
	if Inside() {
		if err := Isolate(); err != nil {
			os.Exit(2)
		}
		if err := unix.Mount("tmpfs", os.Getenv(testDirEnv), "tmpfs", 0, "size=1m"); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestChildMountsStayInsideItsNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a mount namespace")
	}
	dir := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Only if the namespace leaked: never delete through a mount.
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })

	cmd := Command(t.Context(), os.Args[0], []string{"-test.run=^$"})
	cmd.Env = append(cmd.Env, testDirEnv+"="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v: %s", err, out)
	}
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for l := range strings.SplitSeq(string(mi), "\n") {
		if f := strings.Fields(l); len(f) > 4 && f[4] == dir {
			t.Fatalf("the child's tmpfs on %s outlived it here: its mounts would pin memory in other namespaces", dir)
		}
	}
}

func TestIsolateRefusesTheParentsNamespace(t *testing.T) {
	// Not re-run: the parent's namespace is ours, and making its / a slave
	// would change the host until reboot. The check comes before any mount.
	if err := Isolate(); !errors.Is(err, ErrNotIsolated) {
		t.Fatalf("err = %v, want ErrNotIsolated", err)
	}
}

func TestExitCode(t *testing.T) {
	for script, want := range map[string]int{"exit 0": 0, "exit 3": 3, "kill -TERM $$": 128 + 15} {
		err := exec.CommandContext(t.Context(), "sh", "-c", script).Run()
		if got := ExitCode(err); got != want {
			t.Errorf("%s: ExitCode = %d, want %d, as a shell reports it", script, got, want)
		}
	}
}

func TestRunForwardsSignalsToTheChild(t *testing.T) {
	// kill -TERM aimed at the parent's pid must reach the installer.
	cmd := exec.CommandContext(t.Context(), "sh", "-c", `trap "exit 7" TERM; echo ready; while :; do sleep 0.1; done`)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- Run(cmd, sigs) }()
	if _, err := bufio.NewReader(out).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGTERM
	select {
	case err := <-done:
		if got := ExitCode(err); got != 7 {
			t.Fatalf("exit = %d (%v), want 7 from the child's TERM trap", got, err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the signal never reached the child")
	}
}

func TestIsolatedNeedsANamespaceOfItsOwn(t *testing.T) {
	for _, tc := range []struct {
		own, parent, init string
		want              bool
	}{
		{"mnt:[2]", "mnt:[1]", "mnt:[1]", true},
		{"mnt:[1]", "mnt:[1]", "mnt:[1]", false}, // marker set by hand, no re-run
		{"mnt:[2]", "mnt:[3]", "mnt:[2]", false}, // the host's own, under a parent elsewhere
		{"mnt:[2]", "", "mnt:[1]", false},        // parent unreadable
	} {
		if got := isolated(tc.own, tc.parent, tc.init); got != tc.want {
			t.Errorf("isolated(%q, %q, %q) = %v, want %v", tc.own, tc.parent, tc.init, got, tc.want)
		}
	}
}

func TestAbsorbLeavesChildrenTheirDefaults(t *testing.T) {
	Absorb(syscall.SIGPIPE)
	// An ignored signal stays ignored across exec, and no child can undo
	// that; kairos-agent and dmsetup must die of SIGPIPE like anything else.
	err := exec.CommandContext(t.Context(), "sh", "-c", "kill -PIPE $$; exit 0").Run()
	if got := ExitCode(err); got != 128+int(syscall.SIGPIPE) {
		t.Fatalf("child exit = %d (%v), want death by SIGPIPE: it inherited the signal ignored", got, err)
	}
}
