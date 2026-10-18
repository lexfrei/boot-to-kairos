// Package progress posts the installer's progress to an HTTP endpoint, for a
// machine whose console nobody can see. Reporting never holds the install
// up: reports queue without blocking, each gets one attempt with a timeout,
// and Close gives the queue a bounded time to drain.
package progress

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// ErrBadFlags means --report-url or --report-ca cannot be used.
var ErrBadFlags = errors.New("bad progress report flags")

// Phase is how far the install got.
type Phase string

const (
	Started   Phase = "started"
	Planned   Phase = "planned"
	DryRun    Phase = "dry-run"
	Refused   Phase = "refused"
	Quiesced  Phase = "quiesced"
	Writing   Phase = "writing"
	Verifying Phase = "verifying"
	Verified  Phase = "verified"
	Synced    Phase = "synced"
	Rebooting Phase = "rebooting"
	Failed    Phase = "failed"
)

const (
	wireVersion = 1
	queueLen    = 64
	phaseSlots  = 16
	// postTimeout bounds one report: dial, TLS handshake and response.
	postTimeout   = 3 * time.Second
	lookupTimeout = 5 * time.Second
	// A progress report is due every progressStep of the total, or after
	// progressEvery, whichever comes first.
	progressStep  = 20
	progressEvery = 10 * time.Second
)

var lookup = net.DefaultResolver.LookupNetIP //nolint:gochecknoglobals // test seam

// Bytes is how far a pass over the image got.
type Bytes struct {
	Done    int64 `json:"done"`
	Total   int64 `json:"total"`
	Attempt int   `json:"attempt"`
}

// Failure is why the install stopped.
type Failure struct {
	Class   string `json:"class"`
	Message string `json:"message"`
}

// Event is one report; the Reporter adds who sends it and when.
type Event struct {
	Phase   Phase
	Bytes   *Bytes
	Repairs *int
	Plan    any
	Error   *Failure
}

type wire struct {
	Version  int      `json:"version"`
	Run      string   `json:"run"`
	Seq      uint64   `json:"seq"`
	Time     string   `json:"time"`
	Hostname string   `json:"hostname"`
	Disk     string   `json:"disk"`
	Phase    Phase    `json:"phase"`
	Bytes    *Bytes   `json:"bytes,omitempty"`
	Repairs  *int     `json:"repairs,omitempty"`
	Plan     any      `json:"plan,omitempty"`
	Error    *Failure `json:"error,omitempty"`
}

// Reporter sends events to one endpoint. A nil Reporter sends nothing.
type Reporter struct {
	url     string
	shown   string
	addrs   []netip.Addr
	client  *http.Client
	timeout time.Duration
	run     string
	host    string
	disk    string
	now     func() time.Time
	logf    func(string, ...any)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)

	// cancel cuts off what is in flight at Close.
	cancel context.CancelFunc
	wg     sync.WaitGroup
	queue  chan []byte

	mu     sync.Mutex
	seq    uint64
	closed bool
	prog   progress

	// Written by the sender only, read after it is done.
	delivered int
	failed    bool
}

type progress struct {
	phase      Phase
	attempt    int
	done, next int64
	at         time.Time
}

type endpoint struct {
	u    *url.URL
	pool *x509.CertPool
}

// Check validates the flags without touching the network.
func Check(rawURL, caFile string) error {
	_, err := parse(rawURL, caFile)
	return err
}

func parse(rawURL, caFile string) (endpoint, error) {
	u, err := url.Parse(rawURL)
	switch {
	case rawURL == "":
		return endpoint{}, errors.Wrap(ErrBadFlags, "--report-ca needs --report-url")
	case err != nil:
		// A *url.Error quotes the URL, credentials and all.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return endpoint{}, errors.Wrapf(ErrBadFlags, "--report-url: %v", err)
	case u.Scheme != "http" && u.Scheme != "https":
		return endpoint{}, errors.Wrap(ErrBadFlags, "--report-url must be an http or https URL")
	case u.Hostname() == "":
		return endpoint{}, errors.Wrap(ErrBadFlags, "--report-url has no host")
	case caFile != "" && u.Scheme != "https":
		return endpoint{}, errors.Wrap(ErrBadFlags, "--report-ca needs an https --report-url")
	}
	e := endpoint{u: u}
	if caFile == "" {
		return e, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return endpoint{}, errors.Wrapf(ErrBadFlags, "--report-ca: %v", err)
	}
	e.pool = x509.NewCertPool()
	if !e.pool.AppendCertsFromPEM(pem) {
		return endpoint{}, errors.Wrapf(ErrBadFlags, "--report-ca: no PEM certificate in %s", caFile)
	}
	return e, nil
}

// Open resolves the endpoint and loads the certificates to trust now: past
// the point of no return nothing may be read from the disk being replaced,
// and the resolver and the system roots read their files lazily. Reports
// then go to the addresses resolved here, with no proxy.
func Open(ctx context.Context, rawURL, caFile, disk string) (*Reporter, error) {
	e, err := parse(rawURL, caFile)
	if err != nil {
		return nil, err
	}
	if e.u.Scheme == "https" && e.pool == nil {
		if e.pool, err = x509.SystemCertPool(); err != nil {
			return nil, errors.Wrap(err, "load the system's CA certificates")
		}
	}
	addrs, err := resolve(ctx, e.u.Hostname())
	if err != nil {
		return nil, err
	}
	port := e.u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[e.u.Scheme]
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	host, _ := os.Hostname()
	shown := *e.u
	shown.User, shown.RawQuery, shown.ForceQuery, shown.Fragment = nil, "", false, ""
	r := &Reporter{
		url:     e.u.String(),
		shown:   shown.String(),
		addrs:   addrs,
		timeout: postTimeout,
		run:     hex.EncodeToString(id),
		host:    host,
		disk:    disk,
		now:     time.Now,
		logf:    log.Printf,
		queue:   make(chan []byte, queueLen),
	}
	var d net.Dialer
	r.dial = d.DialContext
	r.client = &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: e.pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// The transport does not hand the request's deadline down to
				// the dial, so the dial gets one of its own.
				deadline := time.Now().Add(r.timeout)
				var errs []error
				for i, a := range addrs {
					// Each address gets its share of what is left, so that one
					// dropping packets leaves time for the next.
					dctx, cancel := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addrs)-i))
					c, err := r.dial(dctx, network, net.JoinHostPort(a.String(), port))
					cancel()
					if err == nil {
						return c, nil
					}
					errs = append(errs, err)
				}
				return nil, errors.Join(errs...)
			},
		},
		// Following one would mean a lookup past the point of no return.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	// Detached from ctx: an interrupt must not cut off the report of it.
	sendCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.cancel = cancel
	r.wg.Add(1)
	go r.send(sendCtx)
	return r, nil
}

func resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addrs, err := lookup(ctx, "ip", host)
	if err == nil && len(addrs) == 0 {
		err = errors.Newf("no address for %s", host)
	}
	// IPv4 comes back mapped into IPv6, as ::ffff:192.0.2.1.
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, errors.Wrap(err, "resolve the --report-url host")
}

// String says where reports go, without the URL's credentials or query.
func (r *Reporter) String() string {
	a := make([]string, len(r.addrs))
	for i, addr := range r.addrs {
		a[i] = addr.String()
	}
	return fmt.Sprintf("POST %s (%s)", r.shown, strings.Join(a, ", "))
}

// Send queues e without waiting. When the queue is full e is dropped; its
// sequence number is still spent, so the receiver sees the gap.
func (r *Reporter) Send(e Event) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sendLocked(e)
}

func (r *Reporter) sendLocked(e Event) {
	if r.closed {
		return
	}
	r.seq++
	b, err := json.Marshal(wire{
		Version: wireVersion, Run: r.run, Seq: r.seq, Time: r.now().UTC().Format(time.RFC3339Nano),
		Hostname: r.host, Disk: r.disk, Phase: e.Phase, Bytes: e.Bytes, Repairs: e.Repairs, Plan: e.Plan, Error: e.Error,
	})
	if err != nil {
		r.logf("progress report: %v", err)
		return
	}
	// Progress leaves the last slots to the phases, which are few and say
	// more.
	if (e.Phase == Writing || e.Phase == Verifying) && len(r.queue) >= queueLen-phaseSlots {
		return
	}
	select {
	case r.queue <- b:
	default:
	}
}

// Progress sends a report on a pass over the image when one is due: at the
// start of a pass, at its end, and between them every 5% or progressEvery.
func (r *Reporter) Progress(phase Phase, attempt int, done, total int64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, now := &r.prog, r.now()
	fresh := p.phase != phase || p.attempt != attempt || done < p.done
	if !fresh && done < total && done < p.next && now.Sub(p.at) < progressEvery {
		p.done = done
		return
	}
	*p = progress{phase: phase, attempt: attempt, done: done, next: done + max(total/progressStep, 1), at: now}
	r.sendLocked(Event{Phase: phase, Bytes: &Bytes{Done: done, Total: total, Attempt: attempt}})
}

// Close stops taking reports and waits up to budget for the queued ones;
// whatever is still in flight then is cut off.
func (r *Reporter) Close(budget time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.queue)
	sent := r.seq
	r.mu.Unlock()
	t := time.AfterFunc(budget, r.cancel)
	r.wg.Wait()
	t.Stop()
	r.cancel()
	r.client.CloseIdleConnections()
	r.logf("progress report: %d of %d reports delivered to %s", r.delivered, sent, r.shown)
}

func (r *Reporter) send(ctx context.Context) {
	defer r.wg.Done()
	for b := range r.queue {
		err := r.post(ctx, b)
		if err == nil {
			r.delivered++
			continue
		}
		if !r.failed {
			r.failed = true
			r.logf("progress report: %v; the install goes on without it", err)
		}
	}
}

func (r *Reporter) post(ctx context.Context, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "boot-to-kairos")
	resp, err := r.client.Do(req)
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Newf("no answer within %v", r.timeout)
	}
	if err != nil {
		// A *url.Error quotes the URL, query and all.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<12))
	if resp.StatusCode/100 != 2 {
		return errors.Newf("%s answered %s", r.shown, resp.Status)
	}
	return nil
}
