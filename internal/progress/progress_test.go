package progress

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// receiver records the reports it gets, in arrival order.
type receiver struct {
	mu   sync.Mutex
	got  []map[string]any
	host []string
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad report", http.StatusBadRequest)
		return
	}
	rc.mu.Lock()
	rc.got = append(rc.got, m)
	rc.host = append(rc.host, r.Host)
	rc.mu.Unlock()
}

func (rc *receiver) reports() []map[string]any {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return slices.Clone(rc.got)
}

func (rc *receiver) phases() []string {
	var out []string
	for _, m := range rc.reports() {
		out = append(out, fmt.Sprint(m["phase"]))
	}
	return out
}

// logs collects what the reporter logs.
type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

var (
	errNoSuchHost = errors.New("no such host")
	errRefused    = errors.New("connection refused")
)

// pinLookup makes every name resolve to 127.0.0.1 and counts the lookups.
func pinLookup(t *testing.T) *int {
	t.Helper()
	orig := lookup
	t.Cleanup(func() { lookup = orig })
	var mu sync.Mutex
	n := 0
	lookup = func(ctx context.Context, _, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		if d, ok := ctx.Deadline(); !ok || time.Until(d) > lookupTimeout {
			t.Errorf("lookup of %s without a deadline within %v", host, lookupTimeout)
		}
		switch {
		case strings.HasSuffix(host, ".invalid"):
			return nil, errNoSuchHost
		case strings.HasSuffix(host, ".empty"):
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return &n
}

func open(t *testing.T, rawURL, ca string) (*Reporter, *logs) {
	t.Helper()
	r, err := Open(context.Background(), rawURL, ca, "/dev/vda")
	if err != nil {
		t.Fatal(err)
	}
	l := &logs{}
	r.logf = l.printf
	return r, l
}

// at rewrites the server's URL to name host instead of its address.
func at(t *testing.T, srv *httptest.Server, scheme, host, path string) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return scheme + "://" + host + ":" + u.Port() + path
}

func TestReportsArriveInOrderWithTheirFields(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	r, l := open(t, srv.URL+"/hook", "")
	// The resolver answers an IPv4 literal as an IPv4-mapped IPv6 address.
	if s := r.String(); s != "POST "+srv.URL+"/hook (127.0.0.1)" {
		t.Fatalf("String = %q", s)
	}
	repairs := 1
	r.Send(Event{Phase: Started})
	r.Send(Event{Phase: Planned, Plan: []string{"image: example"}})
	r.Progress(Writing, 1, 10, 100)
	r.Send(Event{Phase: Verified, Bytes: &Bytes{Done: 100, Total: 100, Attempt: 1}, Repairs: &repairs})
	r.Send(Event{Phase: Failed, Error: &Failure{Class: "error", Message: "boom"}})
	r.Close(5 * time.Second)

	got := rc.reports()
	if want := []string{"started", "planned", "writing", "verified", "failed"}; !slices.Equal(rc.phases(), want) {
		t.Fatalf("phases = %v, want %v", rc.phases(), want)
	}
	host, _ := os.Hostname()
	for i, m := range got {
		if m["version"] != float64(1) || m["seq"] != float64(i+1) || m["run"] != got[0]["run"] || len(fmt.Sprint(m["run"])) != 32 ||
			m["hostname"] != host || m["disk"] != "/dev/vda" {
			t.Fatalf("report %d = %v: want version 1, seq %d, the run of the first report, this hostname and the disk", i, m, i+1)
		}
		if ts, err := time.Parse(time.RFC3339Nano, fmt.Sprint(m["time"])); err != nil || ts.Location() != time.UTC {
			t.Fatalf("report %d time = %v: want RFC 3339 in UTC", i, m["time"])
		}
	}
	if fmt.Sprint(got[1]["plan"]) != "[image: example]" || got[0]["plan"] != nil {
		t.Fatalf("plan = %v, %v: want it only on the report that carries it", got[1]["plan"], got[0]["plan"])
	}
	b, _ := got[2]["bytes"].(map[string]any)
	if b["done"] != float64(10) || b["total"] != float64(100) || b["attempt"] != float64(1) {
		t.Fatalf("progress bytes = %v", got[2]["bytes"])
	}
	if got[3]["repairs"] != float64(1) {
		t.Fatalf("repairs = %v", got[3]["repairs"])
	}
	e, _ := got[4]["error"].(map[string]any)
	if e["class"] != "error" || e["message"] != "boom" {
		t.Fatalf("error = %v", got[4]["error"])
	}
	if !strings.Contains(l.String(), "5 of 5 reports delivered") {
		t.Fatalf("log = %q, want the delivery count", l.String())
	}
}

func TestADeadEndpointHoldsNothingUp(t *testing.T) {
	before := runtime.NumGoroutine()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	r, l := open(t, srv.URL, "")
	r.timeout = 200 * time.Millisecond

	start := time.Now()
	for i := range 3 * queueLen {
		r.Progress(Writing, 1, int64(i+1), int64(3*queueLen))
		r.Send(Event{Phase: Quiesced})
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("sending to a hung endpoint took %v: the write loop would wait on it", d)
	}
	start = time.Now()
	budget := 500 * time.Millisecond
	r.Close(budget)
	if d := time.Since(start); d > budget+r.timeout {
		t.Fatalf("Close took %v, want at most the budget %v plus one timeout", d, budget)
	}
	if !strings.Contains(l.String(), "0 of ") {
		t.Fatalf("log = %q, want nothing delivered", l.String())
	}
	if !strings.Contains(l.String(), "no answer within 200ms") {
		t.Fatalf("log = %q, want the timeout named", l.String())
	}
	if n := strings.Count(l.String(), "the install goes on without it"); n != 1 {
		t.Fatalf("log = %q: want the failure logged once, not %d times", l.String(), n)
	}
	close(release)
	srv.Close()
	waitGoroutines(t, before)
}

// waitGoroutines fails unless the goroutine count drops back to n: the
// transport's connection goroutines end on their own just after Close.
func waitGoroutines(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > n {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("%d goroutines after Close, %d before:\n%s", runtime.NumGoroutine(), n, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAHungReportTimesOutAndTheNextGoesThrough(t *testing.T) {
	release := make(chan struct{})
	rc := &receiver{}
	var first sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hung := false
		first.Do(func() { hung = true })
		if hung {
			<-release
			return
		}
		rc.ServeHTTP(w, req)
	}))
	defer srv.Close()
	defer close(release)
	r, l := open(t, srv.URL, "")
	r.timeout = 100 * time.Millisecond
	r.Send(Event{Phase: Quiesced})
	r.Send(Event{Phase: Rebooting})
	start := time.Now()
	r.Close(5 * time.Second)
	if d := time.Since(start); d > time.Second || !slices.Equal(rc.phases(), []string{"rebooting"}) {
		t.Fatalf("Close took %v, phases %v, log %q: want the hung report cut off after its timeout and the next delivered", d, rc.phases(), l.String())
	}
}

func TestNothingIsLeftToReadPastThePointOfNoReturn(t *testing.T) {
	pinLookup(t)
	r, _ := open(t, "https://receiver.test/hook", "")
	defer r.Close(time.Second)
	tr, _ := r.client.Transport.(*http.Transport)
	// A proxy would need a lookup of its own, and the system roots are
	// otherwise read from disk at the first handshake.
	if tr == nil || tr.Proxy != nil || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("transport = %+v: want no proxy and the CA pool loaded at Open", tr)
	}
}

func TestQueueOverflowDropsWithAGapInSeq(t *testing.T) {
	release := make(chan struct{})
	rc := &receiver{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-release
		rc.ServeHTTP(w, req)
	}))
	defer srv.Close()
	r, l := open(t, srv.URL, "")
	for range queueLen + 10 {
		r.Send(Event{Phase: Quiesced})
	}
	close(release)
	r.Close(5 * time.Second)
	got := rc.reports()
	if len(got) == 0 || len(got) > queueLen+1 {
		t.Fatalf("%d reports arrived of %d sent, want the queue's worth and the one in flight", len(got), queueLen+10)
	}
	if last := got[len(got)-1]["seq"]; last == float64(queueLen+10) {
		t.Fatalf("the last report sent arrived: nothing was dropped")
	}
	if !strings.Contains(l.String(), fmt.Sprintf("%d of %d reports delivered", len(got), queueLen+10)) {
		t.Fatalf("log = %q", l.String())
	}
}

func TestProgressLeavesRoomForThePhases(t *testing.T) {
	release := make(chan struct{})
	rc := &receiver{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-release
		rc.ServeHTTP(w, req)
	}))
	defer srv.Close()
	r, _ := open(t, srv.URL, "")
	for i := range 2 * queueLen {
		r.Send(Event{Phase: Verifying, Bytes: &Bytes{Done: int64(i), Total: 2 * queueLen, Attempt: 1}})
	}
	r.Send(Event{Phase: Synced})
	r.Send(Event{Phase: Rebooting})
	close(release)
	r.Close(5 * time.Second)
	if ph := rc.phases(); len(ph) < 2 || !slices.Equal(ph[len(ph)-2:], []string{"synced", "rebooting"}) {
		t.Fatalf("phases = %v: a queue full of progress must still take the phases", ph)
	}
}

func TestADeadAddressLeavesTimeForTheNext(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	orig := lookup
	t.Cleanup(func() { lookup = orig })
	lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	r, _ := open(t, at(t, srv, "http", "receiver.test", "/hook"), "")
	r.timeout = time.Second
	dial := r.dial
	// 192.0.2.1 drops every packet, as an address with no route back does.
	r.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.0.2.1:") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return dial(ctx, network, addr)
	}
	r.Send(Event{Phase: Started})
	r.Close(5 * time.Second)
	if len(rc.reports()) != 1 {
		t.Fatalf("%d reports: the first address took the whole timeout", len(rc.reports()))
	}
}

func TestProgressIsThrottled(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	r, _ := open(t, srv.URL, "")
	now := time.Unix(0, 0)
	r.now = func() time.Time { return now }
	const total = 1000
	for done := int64(1); done <= total; done++ {
		r.Progress(Writing, 1, done, total)
	}
	// A pass that starts over, the next attempt and the read-back each
	// report from their start.
	r.Progress(Writing, 1, 1, total)
	r.Progress(Writing, 2, 1, total)
	r.Progress(Verifying, 2, 1, total)
	// Time alone makes a report due too.
	r.Progress(Verifying, 2, 2, total)
	now = now.Add(progressEvery)
	r.Progress(Verifying, 2, 3, total)
	r.Close(5 * time.Second)

	var seen []string
	for _, m := range rc.reports() {
		b, _ := m["bytes"].(map[string]any)
		seen = append(seen, fmt.Sprintf("%v/%v/%v", m["phase"], b["attempt"], b["done"]))
	}
	want := []string{"writing/1/1"}
	for d := 51; d <= total; d += 50 {
		want = append(want, fmt.Sprintf("writing/1/%d", d))
	}
	want = append(want, "writing/1/1000", "writing/1/1", "writing/2/1", "verifying/2/1", "verifying/2/3")
	if !slices.Equal(seen, want) {
		t.Fatalf("reports = %v\nwant %v: one per 5%%, the last, each new pass and one after progressEvery", seen, want)
	}
}

func TestNameIsResolvedOnceAndDialledByAddress(t *testing.T) {
	lookups := pinLookup(t)
	rc := &receiver{}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	u := at(t, srv, "http", "receiver.test", "/hook")
	r, _ := open(t, u, "")
	if *lookups != 1 {
		t.Fatalf("%d lookups at Open, want 1", *lookups)
	}
	r.Send(Event{Phase: Started})
	r.Send(Event{Phase: Rebooting})
	r.Close(5 * time.Second)
	if *lookups != 1 || len(rc.reports()) != 2 {
		t.Fatalf("%d lookups, %d reports, want 1 and 2: reports go to the address resolved at Open", *lookups, len(rc.reports()))
	}
	if rc.host[0] != strings.TrimPrefix(u[:len(u)-len("/hook")], "http://") {
		t.Fatalf("Host = %q, want the name from the URL", rc.host[0])
	}
	if s := r.String(); s != "POST "+u+" (127.0.0.1)" {
		t.Fatalf("String = %q", s)
	}
}

// A link-local receiver is reachable only through the interface its zone
// names; a report dialled without the zone fails with EINVAL.
func TestAZonedAddressIsDialledWithItsZone(t *testing.T) {
	lookups := pinLookup(t)
	r, _ := open(t, "http://[fe80::1%25eth9]:8080/hook", "")
	got := make(chan string, 4)
	r.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		got <- addr
		return nil, errRefused
	}
	r.Send(Event{Phase: Started})
	r.Close(5 * time.Second)
	if *lookups != 0 {
		t.Errorf("%d lookups of an address", *lookups)
	}
	select {
	case a := <-got:
		if a != "[fe80::1%eth9]:8080" {
			t.Fatalf("dialled %s, want the zone kept", a)
		}
	default:
		t.Fatal("nothing was dialled")
	}
}

func TestOpenFailsOnALookupThatFails(t *testing.T) {
	pinLookup(t)
	for _, u := range []string{"https://receiver.invalid/hook", "https://receiver.empty/hook"} {
		if _, err := Open(context.Background(), u, "", "/dev/vda"); err == nil || errors.Is(err, ErrBadFlags) {
			t.Fatalf("Open(%s) = %v, want a lookup error that is not a usage error", u, err)
		}
	}
}

func TestAnInterruptDoesNotCutOffItsReport(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	r, err := Open(ctx, srv.URL, "", "/dev/vda")
	if err != nil {
		t.Fatal(err)
	}
	r.logf = t.Logf
	cancel()
	r.Send(Event{Phase: Refused, Error: &Failure{Class: "interrupted", Message: "context canceled"}})
	r.Close(5 * time.Second)
	if want := []string{"refused"}; !slices.Equal(rc.phases(), want) {
		t.Fatalf("phases = %v, want %v", rc.phases(), want)
	}
}

func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHTTPSTrustsTheGivenCA(t *testing.T) {
	pinLookup(t)
	rc := &receiver{}
	srv := httptest.NewTLSServer(rc)
	defer srv.Close()
	// The test certificate names example.com.
	u := at(t, srv, "https", "example.com", "/hook")

	r, _ := open(t, u, writeCA(t, srv))
	r.Send(Event{Phase: Started})
	r.Close(5 * time.Second)
	if len(rc.reports()) != 1 {
		t.Fatalf("%d reports over https with the server's CA, want 1", len(rc.reports()))
	}

	r, l := open(t, u, "")
	r.Send(Event{Phase: Started})
	r.Close(5 * time.Second)
	if len(rc.reports()) != 1 || !strings.Contains(l.String(), "certificate") {
		t.Fatalf("%d reports, log %q: a certificate the system roots do not trust must be refused", len(rc.reports()), l.String())
	}
}

func TestFailuresAreNotDeliveries(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"server error": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		// Following it would deliver: /elsewhere answers 200.
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/elsewhere" {
				http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			r, l := open(t, srv.URL, "")
			r.Send(Event{Phase: Started})
			r.Send(Event{Phase: Rebooting})
			r.Close(5 * time.Second)
			if !strings.Contains(l.String(), "0 of 2 reports delivered") || strings.Count(l.String(), "goes on without it") != 1 {
				t.Fatalf("log = %q", l.String())
			}
		})
	}
}

func TestSecretsInTheURLStayOutOfLogsAndPlan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	u := strings.Replace(srv.URL, "http://", "http://user:hunter2@", 1) + "/hook?token=s3cret"
	r, l := open(t, u, "")
	r.Send(Event{Phase: Started})
	r.Close(5 * time.Second)
	refused := httptest.NewServer(http.NotFoundHandler())
	refused.Close()
	r2, l2 := open(t, strings.Replace(refused.URL, "http://", "http://user:hunter2@", 1)+"/hook?token=s3cret", "")
	r2.Send(Event{Phase: Started})
	r2.Close(5 * time.Second)
	bad := Check("https://user:hunter2@receiver.example:notaport/hook?token=s3cret", "")
	if bad == nil {
		t.Fatal("Check passed a URL with a bad port")
	}
	for _, s := range []string{l.String(), l2.String(), r.String(), r2.String(), bad.Error()} {
		if strings.Contains(s, "hunter2") || strings.Contains(s, "s3cret") || strings.Contains(s, "user") {
			t.Fatalf("%q carries the URL's credentials", s)
		}
	}
	if !strings.Contains(l2.String(), "refused") {
		t.Fatalf("log = %q, want the reason a report failed", l2.String())
	}
}

func TestUserInfoIsSentAsBasicAuth(t *testing.T) {
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { user, pass, _ = r.BasicAuth() }))
	defer srv.Close()
	r, _ := open(t, strings.Replace(srv.URL, "http://", "http://user:hunter2@", 1), "")
	r.Send(Event{Phase: Started})
	r.Close(5 * time.Second)
	if user != "user" || pass != "hunter2" {
		t.Fatalf("basic auth = %q:%q", user, pass)
	}
}

func TestNilReporterIsANoOp(t *testing.T) {
	var r *Reporter
	r.Send(Event{Phase: Started})
	r.Progress(Writing, 1, 1, 2)
	r.Close(time.Second)
}

func TestSendAfterCloseIsDropped(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	r, _ := open(t, srv.URL, "")
	r.Close(time.Second)
	r.Send(Event{Phase: Rebooting})
	r.Close(time.Second)
	if len(rc.reports()) != 0 {
		t.Fatalf("got %v after Close", rc.phases())
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ca := writeCA(t, srv)
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		url, ca string
		ok      bool
	}{
		{"https://receiver.example/hook", "", true},
		{"http://192.0.2.1:8080/", "", true},
		{"https://receiver.example/hook", ca, true},
		{"http://receiver.example/hook", ca, false},
		{"https://receiver.example/hook", junk, false},
		{"https://receiver.example/hook", filepath.Join(t.TempDir(), "missing.pem"), false},
		{"ftp://receiver.example/", "", false},
		{"receiver.example/hook", "", false},
		{"https:///hook", "", false},
		{"https://receiver.example:notaport/", "", false},
		{"", "", false},
	} {
		err := Check(c.url, c.ca)
		if c.ok != (err == nil) || (err != nil && !errors.Is(err, ErrBadFlags)) {
			t.Errorf("Check(%q, %q) = %v, want ok=%v and ErrBadFlags on failure", c.url, c.ca, err, c.ok)
		}
	}
	if err := Check("", ca); err == nil || !strings.Contains(err.Error(), "--report-ca needs --report-url") {
		t.Errorf("Check without a URL = %v, want it to name the missing flag", err)
	}
}

func TestEveryPhaseIsDistinct(t *testing.T) {
	seen := map[Phase]bool{}
	for _, p := range []Phase{Started, Planned, DryRun, Refused, Quiesced, Writing, Verifying, Verified, Synced, Rebooting, Failed} {
		if seen[p] || p == "" {
			t.Fatalf("phase %q repeats", p)
		}
		seen[p] = true
	}
}
