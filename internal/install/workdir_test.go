//go:build linux

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	cerrors "github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/flash"
	"github.com/lexfrei/boot-to-kairos/internal/image"
	"github.com/lexfrei/boot-to-kairos/internal/quiesce"
)

func fitAnywhere(*os.File, string) (string, error) { return "", nil }

func TestOpenWorkDirRefuses(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stale := t.TempDir()
	if err := os.Mkdir(filepath.Join(stale, dataName), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		dir   string
		unfit func(*os.File, string) (string, error)
		want  error
		says  string
	}{
		"missing":       {filepath.Join(t.TempDir(), "gone"), fitAnywhere, ErrBadWorkDir, "gone"},
		"not a dir":     {file, fitAnywhere, ErrBadWorkDir, "not a directory"},
		"unfit":         {t.TempDir(), func(*os.File, string) (string, error) { return "it is on vda", nil }, ErrBadWorkDir, "it is on vda"},
		"unplaceable":   {t.TempDir(), func(*os.File, string) (string, error) { return "", quiesce.ErrUnplaceable }, quiesce.ErrUnplaceable, ""},
		"left by a run": {stale, fitAnywhere, ErrBadWorkDir, "remove it"},
	} {
		t.Run(name, func(t *testing.T) {
			w, err := openWorkDir(tc.dir, "/dev/vda", 1<<30, tc.unfit)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("openWorkDir = %v, %v; want %v saying %q", w, err, tc.want, tc.says)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(stale, dataName)); err != nil {
		t.Fatalf("the stale dir was touched: %v; it may hold anything", err)
	}
}

func TestOpenWorkDirHoldsAPrivateDirUntilRemoved(t *testing.T) {
	dir := t.TempDir()
	w, err := openWorkDir(dir, "/dev/vda", 1<<30, fitAnywhere)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, dataName))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("data dir = %v, %v, want a 0700 directory under the work dir", st, err)
	}
	if !strings.HasPrefix(w.path, "/proc/self/fd/") {
		t.Fatalf("path = %q, want it reached through the descriptor held on the work dir", w.path)
	}
	// Mounting over or renaming the work dir must not move the data dir.
	moved := dir + ".moved"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.WriteFile(filepath.Join(w.path, "image.raw"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, dataName, "image.raw")); err != nil {
		t.Fatalf("the file went elsewhere: %v", err)
	}
	w.remove()
	w.remove()
	if _, err := os.Stat(filepath.Join(moved, dataName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("data dir after remove: %v, want it gone", err)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatalf("the work dir itself was removed: %v; it is the user's", err)
	}
}

func TestOpenWorkDirRefusesAFilesystemWithoutHoles(t *testing.T) {
	keep := holesProbe
	t.Cleanup(func() { holesProbe = keep })
	holesProbe = func(string, int64) error { return fmt.Errorf("a 16 MiB truncate allocated 16384 KiB: %w", unix.EFBIG) }
	dir := t.TempDir()
	_, err := openWorkDir(dir, "/dev/vda", 1<<30, fitAnywhere)
	if !errors.Is(err, ErrBadWorkDir) || !strings.Contains(err.Error(), "16384 KiB") {
		t.Fatalf("openWorkDir = %v, want ErrBadWorkDir with the probe's reason", err)
	}
	if _, err := os.Stat(filepath.Join(dir, dataName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("data dir after a refusal: %v, want it removed so the next run is not refused as stale", err)
	}
}

func TestProbeHolesOnTheTestFilesystem(t *testing.T) {
	dir := t.TempDir()
	if err := probeHoles(dir, 1<<30); err != nil {
		t.Fatalf("probeHoles = %v; the test's temp dir keeps holes", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("the probe left %v behind", left)
	}
}

func TestHolesKept(t *testing.T) {
	if err := holesKept(0, unix.ENXIO); err != nil {
		t.Fatalf("holesKept = %v for an unallocated file with no data", err)
	}
	if err := holesKept(8, unix.ENXIO); err == nil || !strings.Contains(err.Error(), "allocated 4 KiB") {
		t.Fatalf("holesKept = %v, want a refusal naming what the truncate allocated", err)
	}
	if err := holesKept(0, nil); err == nil || !strings.Contains(err.Error(), "data") {
		t.Fatalf("holesKept = %v, want a refusal when a hole reads as data", err)
	}
}

func TestSpaceFor(t *testing.T) {
	dir := t.TempDir()
	if err := spaceFor(dir, 1, "a layer"); err != nil {
		t.Fatalf("spaceFor 1 byte = %v", err)
	}
	if err := spaceFor(dir, 1<<62, "a layer"); !errors.Is(err, ErrNotEnoughSpace) || !strings.Contains(err.Error(), "a layer") {
		t.Fatalf("spaceFor 4 EiB = %v, want ErrNotEnoughSpace naming what needs it", err)
	}
}

func TestImageEstimateFollowsTheAgentsSizing(t *testing.T) {
	// Active, passive and recovery, each the source plus 100 MiB, the
	// persistent partition's journal and the slack.
	for _, tc := range []struct {
		disk    int64
		journal uint64
	}{
		{4 << 30, 64 << 20},
		{20 << 30, 160 << 20},
		{1 << 40, 1 << 30},
	} {
		if got, want := imageEstimate(300<<20, tc.disk), uint64(3*(300+100)<<20)+tc.journal+imageSlack; got != want {
			t.Errorf("imageEstimate(300 MiB, %d GiB) = %d, want %d", tc.disk>>30, got, want)
		}
	}
}

func TestUnpackedFit(t *testing.T) {
	budget := int64(1 << 30)
	if err := unpackedFit(uint64(budget), []int64{budget - rootfsHeadroom - 1, 1}); err != nil {
		t.Fatalf("layers that just fit with the headroom: %v", err)
	}
	if err := unpackedFit(uint64(budget), []int64{budget - rootfsHeadroom, 1}); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory one byte over", err)
	}
	if err := unpackedFit(uint64(budget), []int64{-1}); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory for a negative size", err)
	}
}

func TestRootfsFits(t *testing.T) {
	budget := uint64(1 << 30)
	if got, err := rootfsFits(budget, budget-rootfsHeadroom); err != nil || got != budget {
		t.Fatalf("rootfsFits = %d, %v, want the whole budget: nothing else is in memory", got, err)
	}
	if _, err := rootfsFits(budget, budget-rootfsHeadroom+1); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("err = %v, want ErrNotEnoughMemory one byte over", err)
	}
}

func TestOutOfSpace(t *testing.T) {
	dir := t.TempDir()
	agent := fmt.Errorf("exit status 1: %w", unix.EIO)
	if err := outOfSpace(agent, dir, 1); !errors.Is(err, agent) || errors.Is(err, ErrNotEnoughSpace) {
		t.Fatalf("outOfSpace = %v, want the agent's error alone while there is room", err)
	}
	if err := outOfSpace(agent, dir, 1<<62); !errors.Is(err, agent) || !errors.Is(err, ErrNotEnoughSpace) {
		t.Fatalf("outOfSpace = %v, want the agent's error marked not enough space", err)
	}
	if err := outOfSpace(nil, dir, 1<<62); err != nil {
		t.Fatalf("outOfSpace = %v for a build that passed", err)
	}
}

func TestTheWorkDirIsEmptiedBeforeTheOtherDisksAreFlushed(t *testing.T) {
	calls := stubMachine(t)
	w, err := openWorkDir(t.TempDir(), "/dev/vda", 1<<30, fitAnywhere)
	if err != nil {
		t.Fatal(err)
	}
	syncOthers = func(string, time.Duration) {
		_, err := os.Stat(w.path)
		*calls = append(*calls, "sync, data dir there: "+strconv.FormatBool(err == nil))
	}
	o := Options{Disk: "/dev/vda", Yes: true, work: w}
	if err := proceed(context.Background(), o, nil, &Plan{}, strings.NewReader(""), &bytes.Buffer{}, new(bool)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(*calls, "sync, data dir there: false") {
		t.Fatalf("calls = %v: the disk image must be gone before the flush, or it stays on the other disk", *calls)
	}
}

func TestPlanNamesTheWorkDir(t *testing.T) {
	var p Plan
	addWorkDir(&p, nil)
	var out bytes.Buffer
	p.Print(&out)
	if want := "  work dir: /run/boot-to-kairos, a tmpfs\n"; out.String() != want {
		t.Fatalf("plan = %q, want %q", out.String(), want)
	}
	w, err := openWorkDir(t.TempDir(), "/dev/vda", 1<<30, fitAnywhere)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.remove)
	p, out = Plan{}, bytes.Buffer{}
	addWorkDir(&p, w)
	p.Print(&out)
	if !strings.Contains(out.String(), w.shown+" for the disk image and the staged layers") || !strings.Contains(out.String(), "/run/boot-to-kairos") {
		t.Fatalf("plan = %q, want the data dir and the tmpfs that keeps the unpacked image", out.String())
	}
}

func TestValidateMakesTheWorkDirAbsolute(t *testing.T) {
	t.Chdir(t.TempDir())
	o := Options{Image: "i", Disk: "/dev/vda", ConfigPath: config(t, "#cloud-config\nusers: []\n"), WorkDir: "work"}
	if _, err := Validate(&o, fakeSys(t, true), fakeDevOf); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(o.WorkDir) || filepath.Base(o.WorkDir) != "work" {
		t.Fatalf("WorkDir = %q, want it absolute", o.WorkDir)
	}
}

func TestOpenWorkDirMarksWhatItCannotPlaceAsTheWorkDirs(t *testing.T) {
	_, err := openWorkDir(t.TempDir(), "/dev/vda", 1<<30, func(*os.File, string) (string, error) { return "", quiesce.ErrUnplaceable })
	if c := errorClass(err); c != "bad-workdir" {
		t.Fatalf("class = %q, want bad-workdir: disk-in-use is about the target disk", c)
	}
}

func TestOpenWorkDirProbesWithTheDiskSize(t *testing.T) {
	keep := holesProbe
	t.Cleanup(func() { holesProbe = keep })
	var got int64
	holesProbe = func(_ string, size int64) error { got = size; return nil }
	w, err := openWorkDir(t.TempDir(), "/dev/vda", 20<<30, fitAnywhere)
	if err != nil {
		t.Fatal(err)
	}
	w.remove()
	if got != 20<<30 {
		t.Fatalf("probe size = %d, want the disk's: a file too large for the filesystem must be refused before the download", got)
	}
}

func TestInWorkDir(t *testing.T) {
	opened := false
	if err := inWorkDir(&Options{}, func() (*dataDir, error) { opened = true; return &dataDir{}, nil }, func() error { return nil }); err != nil || opened {
		t.Fatalf("inWorkDir without --workdir = %v, opened %v; want nothing opened", err, opened)
	}
	failure := fmt.Errorf("build: %w", unix.EIO)
	for keep, want := range map[bool]bool{false: false, true: true} {
		dir := t.TempDir()
		o := &Options{WorkDir: dir}
		err := inWorkDir(o, func() (*dataDir, error) { return openWorkDir(dir, "/dev/vda", 1<<30, fitAnywhere) }, func() error {
			if o.work == nil {
				t.Fatal("the data dir is not handed on")
			}
			o.work.keep = keep
			return failure
		})
		if !errors.Is(err, failure) {
			t.Fatalf("inWorkDir = %v, want the failure", err)
		}
		if _, err := os.Stat(filepath.Join(dir, dataName)); (err == nil) != want {
			t.Errorf("keep %v: data dir there = %v, want %v", keep, err == nil, want)
		}
	}
}

func TestTheDiskImageIsKeptWhenTheWriteFails(t *testing.T) {
	stubMachine(t)
	writeImage = func(string, string, int, flash.Progress) (flash.Stats, error) { return flash.Stats{}, unix.EIO }
	w, err := openWorkDir(t.TempDir(), "/dev/vda", 1<<30, fitAnywhere)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Disk: "/dev/vda", Yes: true, work: w}
	err = proceed(context.Background(), o, nil, &Plan{}, strings.NewReader(""), &bytes.Buffer{}, new(bool))
	if err == nil || !strings.Contains(err.Error(), filepath.Join(w.shown, "image.raw")) {
		t.Fatalf("proceed = %v, want it to say where the disk image is kept", err)
	}
	w.remove()
	if _, err := os.Stat(w.path); err != nil {
		t.Fatalf("data dir after a failed write: %v; it holds the only copy of the image off the disk", err)
	}
	t.Cleanup(func() { w.keep = false; w.remove() })
}

func TestRoomLeft(t *testing.T) {
	dir := t.TempDir()
	if err := roomLeft(dir, 1, true); err != nil {
		t.Fatalf("roomLeft = %v with room", err)
	}
	if err := roomLeft(dir, 1<<62, true); !errors.Is(err, ErrNotEnoughSpace) {
		t.Fatalf("roomLeft on disk = %v, want ErrNotEnoughSpace", err)
	}
	if err := roomLeft(dir, 1<<62, false); !errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("roomLeft in the tmpfs = %v, want ErrNotEnoughMemory", err)
	}
}

func TestStagingFull(t *testing.T) {
	staged := fmt.Errorf("layer 0: %w: write blob: %w", image.ErrStage, unix.ENOSPC)
	if err := stagingFull(staged); !errors.Is(err, ErrNotEnoughSpace) || errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("stagingFull = %v, want not enough space when staging filled --workdir", err)
	}
	applied := fmt.Errorf("layer 0: write usr/bin/x: %w", unix.ENOSPC)
	if err := stagingFull(applied); !errors.Is(err, ErrNotEnoughMemory) || errors.Is(err, ErrNotEnoughSpace) || strings.Contains(err.Error(), "staged layer") {
		t.Fatalf("stagingFull = %v, want not enough memory, without blaming a staged layer, when the rootfs filled up", err)
	}
	other := fmt.Errorf("layer 0: %w: %w", image.ErrStage, unix.EIO)
	if err := stagingFull(other); !errors.Is(err, unix.EIO) || errors.Is(err, ErrNotEnoughSpace) || errors.Is(err, ErrNotEnoughMemory) {
		t.Fatalf("stagingFull = %v, want another error left alone", err)
	}
}

func TestTheDiskImageGoesWhenNothingWasWritten(t *testing.T) {
	stubMachine(t)
	writeImage = func(string, string, int, flash.Progress) (flash.Stats, error) {
		return flash.Stats{}, cerrors.Mark(unix.EIO, flash.ErrNothingWritten)
	}
	w, err := openWorkDir(t.TempDir(), "/dev/vda", 1<<30, fitAnywhere)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Disk: "/dev/vda", Yes: true, work: w}
	if err := proceed(context.Background(), o, nil, &Plan{}, strings.NewReader(""), &bytes.Buffer{}, new(bool)); !cerrors.Is(err, flash.ErrNothingWritten) {
		t.Fatalf("proceed = %v, want the write's failure", err)
	}
	w.remove()
	if _, err := os.Stat(w.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("data dir after a write that wrote nothing: %v, want it removed: the disk still holds the old system", err)
	}
}
