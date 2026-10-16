//go:build linux

// Package mountns runs the installer in a mount namespace of its own. Its
// work mounts then never reach another namespace, where a copy would keep
// the image's memory after the installer let go of it, and they all vanish
// with the process, however it dies. A Go process cannot unshare its own
// mount namespace, since its threads share filesystem state, so the
// program runs itself again in a new one.
package mountns

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

const marker = "BOOT_TO_KAIROS_IN_NS"

// Inside reports whether this process is the re-run one.
func Inside() bool { return os.Getenv(marker) != "" }

// Command re-runs name with args in a new mount namespace.
func Command(ctx context.Context, name string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), marker+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	return cmd
}

// Isolate is called first thing in the re-run process: mounts made on the
// host still show up here, and none made here propagate back.
func Isolate() error {
	// The marker can also come from the environment the user started the
	// program in, without the re-run.
	own, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return errors.Wrap(err, "read own mount namespace")
	}
	parent, _ := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/mnt")
	init, _ := os.Readlink("/proc/1/ns/mnt")
	if !isolated(own, parent, init) {
		return errors.Wrapf(ErrNotIsolated, "%s is shared with the parent or the host", own)
	}
	return errors.Wrap(unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""), "make / a slave mount")
}

// ErrNotIsolated means Isolate runs in the namespace it was started from.
var ErrNotIsolated = errors.New("not in a mount namespace of its own")

// ExitCode turns the result of running the child into this process's exit
// status.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return 1
	}
	// Killed by a signal: report it the way a shell does.
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return exit.ExitCode()
}

// Run starts cmd, passes it every signal received on sigs and waits for it.
// A signal sent to this process by pid, unlike one from the terminal,
// reaches only this process.
func Run(cmd *exec.Cmd, sigs <-chan os.Signal) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	return err
}

// isolated reports whether own is a namespace of its own: not the one of
// the process that started it, and not the host's, which init is in.
func isolated(own, parent, init string) bool {
	return own != "" && parent != "" && own != parent && own != init
}

// Absorb keeps sigs from stopping this process. They are caught and
// dropped rather than ignored: an ignored signal stays ignored across exec,
// where no child can undo it, while a caught one is reset to its default.
func Absorb(sigs ...os.Signal) {
	signal.Notify(make(chan os.Signal, 1), sigs...)
}
