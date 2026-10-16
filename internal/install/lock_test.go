//go:build linux

package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// heldBySomeoneElse tries the lock the way a second instance would.
func heldBySomeoneElse(t *testing.T, lock string) bool {
	t.Helper()
	f, err := os.Open(lock)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return false
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal(err)
	}
	return true
}

func TestASecondRunRefusesWhileOneIsRunning(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "btk.lock")
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error)
	go func() {
		_, err := withWorkLock(lock, "", func(string, bool) {}, func(*bool) error {
			close(started)
			<-release
			return nil
		})
		done <- err
	}()
	<-started
	ran := false
	_, err := withWorkLock(lock, "", func(string, bool) {}, func(*bool) error { ran = true; return nil })
	if !errors.Is(err, ErrAlreadyRunning) || ran {
		t.Fatalf("second run = %v, ran %v, want ErrAlreadyRunning without running", err, ran)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first run = %v", err)
	}
	if _, err := withWorkLock(lock, "", func(string, bool) {}, func(*bool) error { return nil }); err != nil {
		t.Fatalf("a run after the first ended = %v, want it to get the lock", err)
	}
}

func TestTheWorkDirIsDroppedUnderTheLock(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "btk.lock")
	want := unix.EIO
	dropped := false
	frozen, err := withWorkLock(lock, "/run/work", func(dir string, frozen bool) {
		dropped = true
		if dir != "/run/work" || !frozen {
			t.Errorf("drop(%q, %v), want the work dir and what run said about the point of no return", dir, frozen)
		}
		if !heldBySomeoneElse(t, lock) {
			t.Error("the work dir is dropped after the lock is released: another run may have mounted it by then")
		}
	}, func(frozen *bool) error {
		*frozen = true
		return want
	})
	if !errors.Is(err, want) || !dropped || !frozen {
		t.Fatalf("withWorkLock = %v, %v, dropped %v, want the run's error and flag, and the work dir dropped", frozen, err, dropped)
	}
	if heldBySomeoneElse(t, lock) {
		t.Fatal("the lock is still held after the run")
	}
}

func TestTheWorkDirStaysOncePastThePointOfNoReturn(t *testing.T) {
	for frozen, want := range map[bool]bool{false: false, true: true} {
		dir := filepath.Join(t.TempDir(), "work")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		dropWork(dir, frozen)
		if _, err := os.Stat(dir); (err == nil) != want {
			t.Errorf("frozen %v: work dir still there = %v, want %v", frozen, err == nil, want)
		}
	}
}
