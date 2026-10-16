//go:build linux

package kairos

import (
	"bufio"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCancelKillsTheWholeProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Stands in for kairos-agent with a formatter still running under it.
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 30 & echo $!; wait")
	inGroup(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	child, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })

	cancelled := time.Now()
	cancel()
	_ = cmd.Wait()
	if waited := time.Since(cancelled); waited > 5*time.Second {
		t.Fatalf("Wait returned %v after cancel: the group was not killed", waited)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if err := syscall.Kill(child, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
	}
	t.Fatalf("child %d outlived the cancelled installer: it would keep the loop device busy", child)
}

func TestRunReturnsWhenTheAgentLeavesAChildBehind(t *testing.T) {
	// The agent exits but a child keeps its output pipe open.
	cmd := exec.CommandContext(t.Context(), "sh", "-c", "sleep 30 & echo $!; exit 0")
	var out strings.Builder
	cmd.Stdout = &out
	inGroup(cmd)
	start := time.Now()
	err := run(cmd)
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("run took %v: it waited for the child to close the pipe", took)
	}
	if err != nil {
		t.Fatalf("err = %v, want success: the agent itself exited 0", err)
	}
	child, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("child pid %q: %v", out.String(), err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if err := syscall.Kill(child, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
	}
	_ = syscall.Kill(child, syscall.SIGKILL)
	t.Fatalf("child %d outlived the agent", child)
}
