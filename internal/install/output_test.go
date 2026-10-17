//go:build linux

package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	cerrors "github.com/cockroachdb/errors"

	"github.com/lexfrei/boot-to-kairos/internal/image"
	"github.com/lexfrei/boot-to-kairos/internal/kairos"
	"github.com/lexfrei/boot-to-kairos/internal/netcfg"
	"github.com/lexfrei/boot-to-kairos/internal/quiesce"
)

type reportJSON struct {
	DryRun bool `json:"dryRun"`
	Passed bool `json:"passed"`
	Plan   []struct {
		Name   string    `json:"name"`
		Value  *string   `json:"value"`
		Values *[]string `json:"values"`
	} `json:"plan"`
	Refusal *struct {
		Class   string `json:"class"`
		Message string `json:"message"`
	} `json:"refusal"`
}

// decodeOne fails unless out is exactly one JSON object.
func decodeOne(t *testing.T, out string) reportJSON {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var r reportJSON
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("stdout is not a JSON report: %v\n%s", err, out)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout holds more than one JSON object:\n%s", out)
	}
	return r
}

func TestDryRunPrintsOneJSONObject(t *testing.T) {
	stubMachine(t)
	plan := &Plan{}
	plan.Add("image", "quay.io/kairos/hadron:example")
	o := Options{Disk: "/dev/vda", DryRun: true, Output: OutputJSON}
	var out bytes.Buffer
	err := proceed(context.Background(), o, nil, plan, strings.NewReader(""), &out, new(bool))
	report(&out, o, plan, err, false)
	r := decodeOne(t, out.String())
	if !r.DryRun || !r.Passed || r.Refusal != nil {
		t.Fatalf("report = %+v, want a passed dry run", r)
	}
	var names []string
	for _, it := range r.Plan {
		names = append(names, it.Name)
	}
	if want := "image,network,image.raw,boot entry,swap to turn off,filesystems to stop"; strings.Join(names, ",") != want {
		t.Fatalf("plan items = %v, want %s in that order", names, want)
	}
	if it := r.Plan[0]; it.Value == nil || *it.Value != "quay.io/kairos/hadron:example" || it.Values != nil {
		t.Errorf("image item = %+v, want a single value", it)
	}
	if it := r.Plan[4]; it.Values == nil || len(*it.Values) != 1 || (*it.Values)[0] != "/swap.img" || it.Value != nil {
		t.Errorf("swap item = %+v, want a list", it)
	}
	if it := r.Plan[5]; it.Values == nil || strings.Join(*it.Values, "|") != "/|/boot/efi" {
		t.Errorf("filesystems item = %+v", it)
	}
}

func TestAnEmptyListIsAnEmptyJSONArray(t *testing.T) {
	p := &Plan{}
	p.AddList("swap to turn off", nil)
	var out bytes.Buffer
	report(&out, Options{DryRun: true, Output: OutputJSON}, p, nil, false)
	if !strings.Contains(out.String(), `"values":[]`) {
		t.Fatalf("report = %s, want an empty array, not null or nothing", out.String())
	}
}

func TestARefusalIsReportedWithItsClass(t *testing.T) {
	for _, tc := range []struct {
		err   error
		class string
	}{
		{cerrors.Wrapf(ErrNotWholeDisk, "/dev/vda1 is a partition"), "not-whole-disk"},
		{ErrMissingDisk, "usage"},
		{cerrors.Wrap(ErrBadOutput, "yaml"), "usage"},
		{cerrors.Wrap(ErrBadConfig, "no header"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\nconfig_url: https://example.com/c.yaml\n"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\ninstall: [\n"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\n- install\n"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\ninstall: {partitions: [oem]}\n"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\ninstall: {extra-partitions: {data: {}}}\n"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\nusers: []\n---\nstages: {}\n"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\na: 1\n---\n[\n"), "bad-config"},
		{targetsRefusal(t, "#cloud-config\na: 1\n---\n# empty\n---\nusers: [x]\n"), "bad-config"},
		{networkRefusal(t, "#cloud-config\nstages: [a]\n"), "bad-config"},
		{networkRefusal(t, "#cloud-config\ninstall: 5\n"), "bad-config"},
		{ErrBIOSUnsupported, "bios-unsupported"},
		{ErrLabelClash, "label-clash"},
		{ErrAborted, "aborted"},
		{cerrors.Wrap(ErrNotEnoughMemory, "100 MiB"), "not-enough-memory"},
		{cerrors.Wrap(ErrAlreadyRunning, "held"), "already-running"},
		{cerrors.Wrap(quiesce.ErrUnplaceable, "zfs"), "disk-in-use"},
		{cerrors.Wrap(netcfg.ErrUnsupported, "team0"), "network-unsupported"},
		{cerrors.Wrap(image.ErrPlatform, "resolve"), "bad-image"},
		{cerrors.Wrap(image.ErrMismatch, "layer 0"), "bad-image"},
		{cerrors.Wrap(image.ErrAmbiguous, "resolve"), "bad-image"},
		{cerrors.Wrap(image.ErrLegacyDockerArchive, "resolve"), "bad-image"},
		{cerrors.Wrap(image.ErrInsecureRegistry, "10.0.0.5:5000"), "bad-image"},
		{cerrors.Wrap(context.Canceled, "pull"), "interrupted"},
		{cerrors.Wrap(unix.EIO, "pull"), "error"},
	} {
		var out bytes.Buffer
		report(&out, Options{DryRun: true, Output: OutputJSON}, &Plan{}, tc.err, false)
		r := decodeOne(t, out.String())
		if r.Passed || r.Refusal == nil || r.Refusal.Class != tc.class || r.Refusal.Message != tc.err.Error() {
			t.Errorf("%v: report = %+v, want refusal class %q with the message", tc.err, r, tc.class)
		}
		if r.Plan == nil {
			t.Errorf("%v: plan is null, want an array", tc.err)
		}
	}
}

func TestTextOutputPrintsNoJSON(t *testing.T) {
	var out bytes.Buffer
	report(&out, Options{DryRun: true}, &Plan{}, ErrMissingDisk, false)
	if out.Len() != 0 {
		t.Fatalf("text mode wrote %q to stdout; the refusal goes to stderr", out.String())
	}
}

func TestRealRunPrintsThePlanBeforeThePointOfNoReturn(t *testing.T) {
	calls := stubMachine(t)
	var out bytes.Buffer
	var atNoReturn string
	enterPointOfNoReturn = func() error {
		*calls = append(*calls, "point of no return")
		atNoReturn = out.String()
		return unix.ENOMEM
	}
	o := Options{Disk: "/dev/vda", Yes: true, Output: OutputJSON}
	frozen := false
	err := proceed(context.Background(), o, nil, &Plan{}, strings.NewReader(""), &out, &frozen)
	if r := decodeOne(t, atNoReturn); r.DryRun || !r.Passed {
		t.Fatalf("report before the point of no return = %+v", r)
	}
	// Past that point stdout may sit on the frozen disk: nothing more.
	report(&out, o, &Plan{}, err, frozen)
	if out.String() != atNoReturn {
		t.Fatalf("stdout after the point of no return = %q, want nothing added", strings.TrimPrefix(out.String(), atNoReturn))
	}
}

func TestJSONRunAsksOnStderr(t *testing.T) {
	calls := stubMachine(t)
	var out, stderr bytes.Buffer
	var atNoReturn string
	enterPointOfNoReturn = func() error {
		*calls = append(*calls, "point of no return")
		atNoReturn = out.String()
		return unix.ENOMEM
	}
	orig := log.Writer()
	log.SetOutput(&stderr)
	t.Cleanup(func() { log.SetOutput(orig) })
	o := Options{Disk: "/dev/vda", Output: OutputJSON}
	_ = proceed(context.Background(), o, nil, &Plan{}, strings.NewReader("/dev/vda\n"), &out, new(bool))
	decodeOne(t, atNoReturn)
	if !strings.Contains(stderr.String(), "Type the disk path") {
		t.Fatalf("stderr = %q, want the prompt there, off the JSON on stdout", stderr.String())
	}
}

func TestAFailurePastThePointOfNoReturnIsNotReportedOnStdout(t *testing.T) {
	o := Options{Output: OutputJSON}
	for frozen, want := range map[bool]bool{false: true, true: false} {
		var out bytes.Buffer
		lock := filepath.Join(t.TempDir(), "btk.lock")
		err := lockedAndReported(&out, o, &Plan{}, lock, "", func(string, bool) {}, func(f *bool) error {
			*f = frozen
			return unix.EIO
		})
		if !errors.Is(err, unix.EIO) {
			t.Fatalf("err = %v, want the run's", err)
		}
		if got := out.Len() > 0; got != want {
			t.Errorf("frozen %v: reported on stdout = %v, want %v", frozen, got, want)
		}
	}
}

func TestARunThatCannotTakeTheLockIsReported(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "btk.lock")
	release, held := make(chan struct{}), make(chan struct{})
	go func() {
		_, _ = withWorkLock(lock, "", func(string, bool) {}, func(*bool) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	defer close(release)
	var out bytes.Buffer
	ran := false
	err := lockedAndReported(&out, Options{DryRun: true, Output: OutputJSON}, &Plan{}, lock, "", func(string, bool) {}, func(*bool) error {
		ran = true
		return nil
	})
	r := decodeOne(t, out.String())
	if !errors.Is(err, ErrAlreadyRunning) || ran || r.Refusal == nil || r.Refusal.Class != "already-running" {
		t.Fatalf("err = %v, ran %v, report %+v: want an already-running refusal on stdout", err, ran, r)
	}
}

// networkRefusal returns netcfg's refusal of a cfg that Targets accepts.
func networkRefusal(t *testing.T, cfg string) error {
	t.Helper()
	if _, _, err := kairos.Targets([]byte(cfg)); err != nil {
		t.Fatalf("Targets refused %q first: %v", cfg, err)
	}
	_, err := netcfg.UserConfigures([]byte(cfg))
	if err == nil {
		t.Fatalf("%q was not refused", cfg)
	}
	return err
}

func targetsRefusal(t *testing.T, cfg string) error {
	t.Helper()
	_, _, err := kairos.Targets([]byte(cfg))
	if err == nil {
		t.Fatalf("%q was not refused", cfg)
	}
	return err
}

func TestABuildCutShortByCtrlCIsInterrupted(t *testing.T) {
	stubMachine(t)
	ctx, cancel := context.WithCancel(context.Background())
	// The agent killed by the cancellation reports its own exit, not the
	// context's error.
	buildImage = func(context.Context, Options, []byte, *Plan) (string, error) {
		cancel()
		return "", cerrors.Wrap(unix.EINTR, "kairos-agent manual-install: signal: killed")
	}
	err := proceed(ctx, Options{Disk: "/dev/vda", DryRun: true}, nil, &Plan{}, strings.NewReader(""), io.Discard, new(bool))
	if errorClass(err) != "interrupted" || !strings.Contains(err.Error(), "signal: killed") {
		t.Fatalf("err = %v, class %q: want the build's error classed interrupted", err, errorClass(err))
	}
}
