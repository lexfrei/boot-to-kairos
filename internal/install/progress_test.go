//go:build linux

package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lexfrei/boot-to-kairos/internal/flash"
	"github.com/lexfrei/boot-to-kairos/internal/progress"
)

var errNoSuchHost = errors.New("no such host")

// receiver keeps the raw body of every report it gets.
type receiver struct {
	mu     sync.Mutex
	bodies []string
}

func (rc *receiver) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.bodies = append(rc.bodies, string(b))
}

type got struct {
	Seq   int    `json:"seq"`
	Phase string `json:"phase"`
	Bytes *struct {
		Done    int64 `json:"done"`
		Total   int64 `json:"total"`
		Attempt int   `json:"attempt"`
	} `json:"bytes"`
	Repairs *int              `json:"repairs"`
	Plan    []json.RawMessage `json:"plan"`
	Error   *struct {
		Class   string `json:"class"`
		Message string `json:"message"`
	} `json:"error"`
}

func (rc *receiver) reports(t *testing.T) []got {
	t.Helper()
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := make([]got, len(rc.bodies))
	for i, b := range rc.bodies {
		if err := json.Unmarshal([]byte(b), &out[i]); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// phases names each report, a pass over the image with its attempt and
// stage, and drops consecutive repeats of one.
func phases(rs []got) []string {
	var out []string
	for _, r := range rs {
		p := r.Phase
		if r.Bytes != nil && (p == "writing" || p == "verifying") {
			p = fmt.Sprintf("%s %d", p, r.Bytes.Attempt)
		}
		if len(out) == 0 || out[len(out)-1] != p {
			out = append(out, p)
		}
	}
	return out
}

// reporting returns options that report to a fresh receiver.
func reporting(t *testing.T, o Options) (Options, *receiver) {
	t.Helper()
	rc := &receiver{}
	srv := httptest.NewServer(rc)
	t.Cleanup(srv.Close)
	o.Report = &ReportOptions{URL: srv.URL + "/hook"}
	openReport(context.Background(), &o, &Plan{})
	t.Cleanup(func() { o.Report.sender.Close(0) })
	return o, rc
}

func TestRealRunReportsEveryPhaseBeforeTheReboot(t *testing.T) {
	calls := stubMachine(t)
	o, rc := reporting(t, Options{Disk: "/dev/vda", Yes: true})
	attempt := 0
	writeImage = func(_, _ string, _ int, p flash.Progress) (flash.Stats, error) {
		attempt++
		p(flash.StageCopy, 50, 100)
		p(flash.StageCopy, 100, 100)
		if attempt == 1 {
			return flash.Stats{}, flash.ErrUnrepaired
		}
		p(flash.StageVerify, 100, 100)
		return flash.Stats{Copied: 60, Zeroed: 40, Repairs: 2}, nil
	}
	var atReboot []string
	reboot = func() error {
		atReboot = phases(rc.reports(t))
		*calls = append(*calls, "reboot")
		return nil
	}
	const marker = "users: [{name: secret-marker}]"
	cfg := []byte("#cloud-config\n" + marker + "\n")
	if err := proceed(context.Background(), o, cfg, &Plan{}, strings.NewReader(""), io.Discard, new(bool)); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	want := []string{"started", "planned", "quiesced", "writing 1", "writing 2", "verifying 2", "verified", "synced", "rebooting"}
	if !slices.Equal(atReboot, want) {
		t.Fatalf("reports when reboot(2) came = %v, want %v: every one delivered before it", atReboot, want)
	}
	rs := rc.reports(t)
	for i, r := range rs {
		if r.Seq != i+1 {
			t.Fatalf("report %d has seq %d", i, r.Seq)
		}
	}
	if p := rs[1]; p.Phase != "planned" || !slices.ContainsFunc(p.Plan, func(m json.RawMessage) bool { return strings.Contains(string(m), "boot entry") }) {
		t.Fatalf("planned = %+v, want the plan in it", p)
	}
	v := rs[len(rs)-3]
	if v.Phase != "verified" || v.Repairs == nil || *v.Repairs != 2 || v.Bytes == nil || v.Bytes.Done != 100 || v.Bytes.Total != 100 || v.Bytes.Attempt != 2 {
		t.Fatalf("verified = %+v, want the bytes of the attempt that passed and its repairs", v)
	}
	for _, b := range rc.bodies {
		if strings.Contains(b, "secret-marker") {
			t.Fatalf("a report carries the cloud-config: %s", b)
		}
	}
}

func TestDryRunReportsTheWholePlan(t *testing.T) {
	stubMachine(t)
	o, rc := reporting(t, Options{Disk: "/dev/vda", DryRun: true})
	if err := proceed(context.Background(), o, nil, &Plan{}, strings.NewReader(""), io.Discard, new(bool)); err != nil {
		t.Fatalf("proceed = %v", err)
	}
	o.Report.sender.Close(reportBudget)
	rs := rc.reports(t)
	if want := []string{"started", "planned", "dry-run"}; !slices.Equal(phases(rs), want) {
		t.Fatalf("reports = %v, want %v", phases(rs), want)
	}
	if !slices.ContainsFunc(rs[2].Plan, func(m json.RawMessage) bool { return strings.Contains(string(m), "swap to turn off") }) {
		t.Fatalf("dry-run = %+v, want the plan with what the quiesce would stop", rs[2])
	}
}

func TestTheOutcomeIsReported(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		frozen bool
		phase  string
		class  string
	}{
		{"refused", ErrLabelClash, false, "refused", "label-clash"},
		{"interrupted", context.Canceled, false, "refused", "interrupted"},
		{"failed past the point of no return", flash.ErrUnrepaired, true, "failed", "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, rc := reporting(t, Options{Disk: "/dev/vda"})
			finishReport(&o, tc.err, tc.frozen)
			rs := rc.reports(t)
			last := rs[len(rs)-1]
			if last.Phase != tc.phase || last.Error == nil || last.Error.Class != tc.class || last.Error.Message != tc.err.Error() {
				t.Fatalf("last report = %+v, want %s with class %s and the message", last, tc.phase, tc.class)
			}
		})
	}
	o, rc := reporting(t, Options{Disk: "/dev/vda"})
	finishReport(&o, nil, false)
	if want := []string{"started"}; !slices.Equal(phases(rc.reports(t)), want) {
		t.Fatalf("a run that passed sent %v, want nothing after %v", phases(rc.reports(t)), want)
	}
}

func TestADeadEndpointDoesNotStopTheInstall(t *testing.T) {
	calls := stubMachine(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	o := Options{Disk: "/dev/vda", Yes: true, Report: &ReportOptions{URL: srv.URL}}
	plan := &Plan{}
	openReport(context.Background(), &o, plan)
	if err := proceed(context.Background(), o, nil, plan, strings.NewReader(""), io.Discard, new(bool)); err != nil || !slices.Contains(*calls, "reboot") {
		t.Fatalf("proceed = %v after %v, want the reboot", err, *calls)
	}
	var out strings.Builder
	plan.Print(&out)
	if !regexp.MustCompile(`(?m)^  progress report: +POST ` + regexp.QuoteMeta(srv.URL) + ` \(127\.0\.0\.1\)$`).MatchString(out.String()) {
		t.Fatalf("plan:\n%s\nwant where reports go", out.String())
	}
}

func TestAnUnresolvableEndpointIsAWarning(t *testing.T) {
	orig := openReporter
	t.Cleanup(func() { openReporter = orig })
	openReporter = func(context.Context, string, string, string) (*progress.Reporter, error) {
		return nil, errNoSuchHost
	}
	o := Options{Disk: "/dev/vda", Report: &ReportOptions{URL: "https://receiver.invalid/hook"}}
	plan := &Plan{}
	openReport(context.Background(), &o, plan)
	if o.reporter() != nil {
		t.Fatal("a reporter with nowhere to send")
	}
	var out strings.Builder
	plan.Print(&out)
	if !regexp.MustCompile(`(?m)^  progress report: +none: no such host$`).MatchString(out.String()) {
		t.Fatalf("plan:\n%s\nwant why nothing is reported", out.String())
	}
}

func TestBadReportFlagsAreAUsageError(t *testing.T) {
	good := config(t, "#cloud-config\nusers: []\n")
	for _, r := range []*ReportOptions{{URL: "ftp://receiver.example/"}, {CA: "/ca.pem"}, {URL: "http://receiver.example/", CA: "/ca.pem"}} {
		o := Options{Image: "quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0", Disk: "/dev/vda", ConfigPath: good, Report: r}
		_, err := Validate(&o, fakeSys(t, true), fakeDevOf)
		if !errors.Is(err, progress.ErrBadFlags) || errorClass(err) != "usage" {
			t.Errorf("Validate(%+v) = %v (class %s), want ErrBadFlags as usage", r, err, errorClass(err))
		}
	}
	o := Options{Image: "quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0", Disk: "/dev/vda", ConfigPath: good, Report: &ReportOptions{URL: "https://receiver.example/hook"}}
	if _, err := Validate(&o, fakeSys(t, true), fakeDevOf); err != nil {
		t.Fatalf("Validate = %v", err)
	}
}

func TestAWriteFailureIsReportedWithItsAttempts(t *testing.T) {
	stubMachine(t)
	o, rc := reporting(t, Options{Disk: "/dev/vda", Yes: true})
	writeImage = func(_, _ string, _ int, p flash.Progress) (flash.Stats, error) {
		p(flash.StageCopy, 1, 2)
		return flash.Stats{}, unix.EIO
	}
	err := proceed(context.Background(), o, nil, &Plan{}, strings.NewReader(""), io.Discard, new(bool))
	if err == nil {
		t.Fatal("proceed passed a failed write")
	}
	finishReport(&o, err, true)
	want := []string{"started", "planned", "quiesced", "writing 1", "writing 2", "writing 3", "failed"}
	if got := phases(rc.reports(t)); !slices.Equal(got, want) {
		t.Fatalf("reports = %v, want %v", got, want)
	}
}
