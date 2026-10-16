//go:build linux

package install

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/flash"
)

func TestWriteRetriesTheWholeImage(t *testing.T) {
	orig := writeImage
	t.Cleanup(func() { writeImage = orig })

	calls := 0
	writeImage = func(string, string, int) (flash.Stats, error) {
		calls++
		if calls < 3 {
			return flash.Stats{}, flash.ErrUnrepaired
		}
		return flash.Stats{Copied: 1}, nil
	}
	if st, err := write("/run/boot-to-kairos/image.raw", "/dev/vda"); err != nil || st.Copied != 1 || calls != 3 {
		t.Fatalf("write = %+v, %v after %d calls, want success on the third", st, err, calls)
	}

	calls = 0
	writeImage = func(string, string, int) (flash.Stats, error) {
		calls++
		return flash.Stats{}, flash.ErrUnrepaired
	}
	_, err := write("/run/boot-to-kairos/image.raw", "/dev/vda")
	if !errors.Is(err, flash.ErrUnrepaired) || calls != writeAttempts {
		t.Fatalf("err = %v after %d calls, want ErrUnrepaired after %d", err, calls, writeAttempts)
	}
	// The image goes with the installer's mount namespace, and nothing on
	// the overwritten disk could copy it anyway.
	if strings.Contains(err.Error(), "image.raw") || !strings.Contains(err.Error(), "rescue") {
		t.Fatalf("err = %v: it must send the user to rescue media, not to an image that is gone", err)
	}
}

func TestSafeLogNeverWritesToAFile(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "nohup.out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var kmsg bytes.Buffer
	log.New(safeLog(f, &kmsg), "", 0).Print("hello")
	if st, _ := f.Stat(); st.Size() != 0 {
		t.Fatalf("wrote %d bytes to a regular file: it may sit on the frozen disk, and the write would block", st.Size())
	}
	if !strings.Contains(kmsg.String(), "hello") {
		t.Fatalf("kmsg = %q, want the message", kmsg.String())
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	kmsg.Reset()
	log.New(safeLog(w, &kmsg), "", 0).Print("hello")
	w.Close()
	// safeLog writes through a descriptor of its own, still open, so the
	// pipe never reaches EOF: read just the message.
	got := make([]byte, len("hello\n"))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" || !strings.Contains(kmsg.String(), "hello") {
		t.Fatalf("pipe = %q, kmsg = %q, want the message on both", got, kmsg.String())
	}
}

func TestSafeLogReachesKmsgWhenStderrIsGone(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r.Close() // the SSH session that read stderr has died
	var kmsg bytes.Buffer
	log.New(safeLog(w, &kmsg), "", 0).Print("image is at /run/boot-to-kairos/image.raw")
	if got, want := kmsg.String(), "<2>boot-to-kairos: image is at /run/boot-to-kairos/image.raw\n"; got != want {
		t.Fatalf("kmsg = %q, want %q: level 2 reaches the console, and a dead stderr must not swallow it", got, want)
	}
}

func TestSafeLogDoesNotBlockOnAFullPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	// Fill the pipe: its reader is alive but stuck, say on the frozen disk.
	fill, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", w.Fd()), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 4096)
	for {
		if _, err := unix.Write(fill, chunk); err != nil {
			break
		}
	}
	unix.Close(fill)

	var kmsg bytes.Buffer
	done := make(chan struct{})
	go func() {
		log.New(safeLog(w, &kmsg), "", 0).Print("rebooting")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("logging blocked on a full pipe: the reboot after it would never come")
	}
	if !strings.Contains(kmsg.String(), "rebooting") {
		t.Fatalf("kmsg = %q", kmsg.String())
	}
}

func TestWriteGivesUpAtOnceWhenNothingWasWritten(t *testing.T) {
	orig := writeImage
	t.Cleanup(func() { writeImage = orig })
	calls := 0
	writeImage = func(string, string, int) (flash.Stats, error) {
		calls++
		return flash.Stats{}, errors.Join(flash.ErrNothingWritten, os.ErrPermission)
	}
	_, err := write("/run/boot-to-kairos/image.raw", "/dev/vda")
	if !errors.Is(err, flash.ErrNothingWritten) || calls != 1 {
		t.Fatalf("err = %v after %d calls, want ErrNothingWritten after one: the disk is intact, there is nothing to retry over", err, calls)
	}
	if strings.Contains(err.Error(), "rescue") {
		t.Fatalf("err = %v: the disk was never touched, it needs no rescue media", err)
	}
}

func TestWriteNeverCallsATouchedDiskIntact(t *testing.T) {
	orig := writeImage
	t.Cleanup(func() { writeImage = orig })
	calls := 0
	writeImage = func(string, string, int) (flash.Stats, error) {
		calls++
		if calls == 1 {
			return flash.Stats{}, flash.ErrUnrepaired // wrote, then failed to verify
		}
		return flash.Stats{}, errors.Join(flash.ErrNothingWritten, os.ErrPermission)
	}
	_, err := write("/run/boot-to-kairos/image.raw", "/dev/vda")
	if err == nil || errors.Is(err, flash.ErrNothingWritten) {
		t.Fatalf("err = %v: the first attempt already wrote, so a later one writing nothing does not make the disk intact", err)
	}
}

type countingCloser struct {
	*bytes.Buffer

	closed *int
}

func (c countingCloser) Close() error { *c.closed++; return nil }

func TestKmsgIsOpenedAnewForEveryLine(t *testing.T) {
	// /dev/kmsg rate-limits each open file on its own; a descriptor kept
	// open could have its budget spent when the final error comes.
	var buf bytes.Buffer
	opens, closes := 0, 0
	w := reopenWriter(func() (io.WriteCloser, error) {
		opens++
		return countingCloser{&buf, &closes}, nil
	})
	l := log.New(w, "", 0)
	l.Print("one")
	l.Print("two")
	if opens != 2 || closes != 2 || buf.String() != "one\ntwo\n" {
		t.Fatalf("opens = %d, closes = %d, out = %q, want each line through a descriptor of its own", opens, closes, buf.String())
	}
}
