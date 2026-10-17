package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sys/unix"
)

// faultyRegistry serves img from an in-process registry and lets fault
// answer every GET of a path ending in suffix instead of the registry while
// it returns true.
func faultyRegistry(t *testing.T, img v1.Image, suffix string, fault func(w http.ResponseWriter, body []byte) bool) (ref string, gets *atomic.Int32) {
	t.Helper()
	saved := retryDelay
	t.Cleanup(func() { retryDelay = saved })
	retryDelay = 0
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	gets = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, suffix) {
			inner.ServeHTTP(w, r)
			return
		}
		gets.Add(1)
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)
		if fault(w, rec.Body.Bytes()) {
			return
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(srv.Close)
	ref = strings.TrimPrefix(srv.URL, "http://") + "/kairos/hadron:" + tag
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	return ref, gets
}

const tag = "test"

func blobPathSuffix(h v1.Hash) string { return "/blobs/" + h.String() }

// cut sends the headers and half of the body, then drops the connection,
// as a registry or a proxy does when a stream breaks mid-layer.
func cut(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body[:len(body)/2])
	// Unflushed, the client would see no response at all and retry the
	// request on its own; the field failure is a body that stops.
	w.(http.Flusher).Flush()
	panic(http.ErrAbortHandler)
}

func pullAndExtract(t *testing.T, ctx context.Context, ref string) (string, error) {
	t.Helper()
	img, err := Open(ctx, ref, "linux/"+runtime.GOARCH, false)
	if err != nil {
		return "", err
	}
	dest := t.TempDir()
	return dest, img.Extract(ctx, dest, t.TempDir(), func(int64) error { return nil })
}

func TestPullRetriesALayerStreamThatBreaks(t *testing.T) {
	img, _ := twoLayers(t)
	l := layerDigests(t, img)[1]
	var cuts atomic.Int32
	ref, gets := faultyRegistry(t, img, blobPathSuffix(l), func(w http.ResponseWriter, body []byte) bool {
		if cuts.Add(1) > 2 {
			return false
		}
		cut(w, body)
		return true
	})
	dest, err := pullAndExtract(t, t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	assertInstalled(t, dest)
	if img, err := Open(t.Context(), ref, "linux/"+runtime.GOARCH, false); err != nil || img.Transport() != "registry" {
		t.Fatalf("transport of %s: %v", ref, err)
	}
	if n := gets.Load(); n != 3 {
		t.Fatalf("%d GETs of the layer, want 3: two cut, then a whole one", n)
	}
}

func TestPullGivesUpAfterBoundedAttempts(t *testing.T) {
	img, _ := twoLayers(t)
	l := layerDigests(t, img)[0]
	ref, gets := faultyRegistry(t, img, blobPathSuffix(l), func(w http.ResponseWriter, body []byte) bool {
		cut(w, body)
		return true
	})
	dest, err := pullAndExtract(t, t.Context(), ref)
	if err == nil || errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want the broken stream, not a mismatch: the layer never arrived whole", err)
	}
	if n := gets.Load(); n != fetchAttempts {
		t.Fatalf("%d GETs of the layer, want %d", n, fetchAttempts)
	}
	assertEmpty(t, dest)
}

func TestPullRetriesWrongBytesThenRefuses(t *testing.T) {
	img, _ := twoLayers(t)
	l := layerDigests(t, img)[0]
	ref, gets := faultyRegistry(t, img, blobPathSuffix(l), func(w http.ResponseWriter, body []byte) bool {
		bad := append([]byte(nil), body...)
		bad[len(bad)/2] ^= 0xff
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bad)
		return true
	})
	dest, err := pullAndExtract(t, t.Context(), ref)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch for a layer that does not match its digest", err)
	}
	if n := gets.Load(); n != fetchAttempts {
		t.Fatalf("%d GETs of the layer, want %d", n, fetchAttempts)
	}
	assertEmpty(t, dest)
}

func TestPullRefusesALayerOfAnotherSize(t *testing.T) {
	for _, tc := range []struct {
		what  string
		serve func(body []byte) []byte
	}{
		{"longer", func(body []byte) []byte { return append(body, 'x') }},
		{"shorter", func(body []byte) []byte { return body[:len(body)-1] }},
	} {
		img, _ := twoLayers(t)
		ref, _ := faultyRegistry(t, img, blobPathSuffix(layerDigests(t, img)[0]), func(w http.ResponseWriter, body []byte) bool {
			// Flushed without a Content-Length, the body is chunked and
			// ends cleanly, as a truncated blob in storage would.
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = w.Write(tc.serve(body))
			return true
		})
		if _, err := pullAndExtract(t, t.Context(), ref); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: err = %v, want ErrMismatch for a layer %s than its descriptor", tc.what, err, tc.what)
		}
	}
}

func TestPullRefusesAChildManifestThatDoesNotMatch(t *testing.T) {
	saved := retryDelay
	t.Cleanup(func() { retryDelay = saved })
	retryDelay = 0
	img, _ := twoLayers(t)
	child, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}}})
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/manifests/"+child.String()) {
			inner.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)
		w.Header().Set("Content-Type", rec.Header().Get("Content-Type"))
		_, _ = w.Write(append(rec.Body.Bytes(), ' '))
	}))
	t.Cleanup(srv.Close)
	ref := strings.TrimPrefix(srv.URL, "http://") + "/kairos/hadron:" + tag
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(r, idx); err != nil {
		t.Fatal(err)
	}
	if _, err := pullAndExtract(t, t.Context(), ref); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch for a child manifest that does not match its digest", err)
	}
	byDigest := strings.TrimPrefix(srv.URL, "http://") + "/kairos/hadron@" + child.String()
	if _, err := pullAndExtract(t, t.Context(), byDigest); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch for a manifest pulled by a digest it does not match", err)
	}
}

func TestPullRetriesOnlyStatusesThatMayPass(t *testing.T) {
	for _, tc := range []struct {
		status int
		gets   int32
	}{
		{http.StatusServiceUnavailable, 2},
		{http.StatusTooManyRequests, 2},
		{http.StatusNotFound, 1},
		{http.StatusUnauthorized, 1},
		{http.StatusForbidden, 1},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			img, _ := twoLayers(t)
			var calls atomic.Int32
			ref, gets := faultyRegistry(t, img, blobPathSuffix(layerDigests(t, img)[0]), func(w http.ResponseWriter, _ []byte) bool {
				if calls.Add(1) > 1 {
					return false
				}
				w.WriteHeader(tc.status)
				return true
			})
			_, err := pullAndExtract(t, t.Context(), ref)
			if n := gets.Load(); n != tc.gets {
				t.Fatalf("%d GETs after a %d (err %v), want %d", n, tc.status, err, tc.gets)
			}
			if (tc.gets == 2) != (err == nil) {
				t.Fatalf("err = %v after a %d", err, tc.status)
			}
		})
	}
}

func TestPullStopsRetryingWhenCancelled(t *testing.T) {
	img, _ := twoLayers(t)
	ctx, cancel := context.WithCancel(t.Context())
	ref, gets := faultyRegistry(t, img, blobPathSuffix(layerDigests(t, img)[0]), func(w http.ResponseWriter, body []byte) bool {
		cancel()
		cut(w, body)
		return true
	})
	retryDelay = 1 << 40
	var logged bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&logged)
	if _, err := pullAndExtract(t, ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation, not a wait through the backoff", err)
	}
	if strings.Contains(logged.String(), "retrying") {
		t.Fatalf("a cancelled fetch announced a retry: %s", logged.String())
	}
	if n := gets.Load(); n != 1 {
		t.Fatalf("%d GETs, want 1", n)
	}
}

func TestPullRefusesASingleManifestForAnotherArchitecture(t *testing.T) {
	img := platformImage(t, "s390x", layer(t, entry{name: "f", typ: tar.TypeReg, body: "x"}))
	ref, _ := faultyRegistry(t, img, "/none", func(http.ResponseWriter, []byte) bool { return false })
	if _, err := Open(t.Context(), ref, "linux/amd64", false); !errors.Is(err, ErrPlatform) {
		t.Fatalf("err = %v, want ErrPlatform", err)
	}
}

func TestPullReadsTheMediaTypeFromAGenericContentType(t *testing.T) {
	img, _ := twoLayers(t)
	ref, _ := faultyRegistry(t, img, "/manifests/"+tag, func(w http.ResponseWriter, body []byte) bool {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
		return true
	})
	if _, err := Open(t.Context(), ref, "linux/"+runtime.GOARCH, false); err != nil {
		t.Fatalf("a manifest served as application/octet-stream: %v", err)
	}
}

func TestPullRefusesAnUnsupportedManifestType(t *testing.T) {
	img, _ := twoLayers(t)
	ref, _ := faultyRegistry(t, img, "/manifests/"+tag, func(w http.ResponseWriter, _ []byte) bool {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v1+prettyjws")
		_, _ = w.Write([]byte(`{"schemaVersion":1,"name":"kairos/hadron","fsLayers":[]}`))
		return true
	})
	if _, err := Open(t.Context(), ref, "linux/"+runtime.GOARCH, false); err == nil || !strings.Contains(err.Error(), "unsupported media type") {
		t.Fatalf("err = %v, want the media type refused rather than read as an index", err)
	}
}

func TestPullOwnsTheRetriesOfAPersistentServerError(t *testing.T) {
	img, _ := twoLayers(t)
	ref, gets := faultyRegistry(t, img, blobPathSuffix(layerDigests(t, img)[0]), func(w http.ResponseWriter, _ []byte) bool {
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	})
	if _, err := pullAndExtract(t, t.Context(), ref); err == nil {
		t.Fatal("a layer that is never served was accepted")
	}
	if n := gets.Load(); n != fetchAttempts {
		t.Fatalf("%d GETs, want %d: the registry client must not retry on its own as well", n, fetchAttempts)
	}
}

func TestPullRetriesAStalledStream(t *testing.T) {
	img, _ := twoLayers(t)
	saved := stallTimeout
	t.Cleanup(func() { stallTimeout = saved })
	stallTimeout = time.Second
	release := make(chan struct{})
	var calls atomic.Int32
	ref, gets := faultyRegistry(t, img, blobPathSuffix(layerDigests(t, img)[1]), func(w http.ResponseWriter, body []byte) bool {
		if calls.Add(1) > 1 {
			return false
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body[:len(body)/2])
		w.(http.Flusher).Flush()
		<-release
		return true
	})
	// Registered after the server's cleanup, so it runs first and lets the
	// stalled handler return before the server waits for it.
	t.Cleanup(func() { close(release) })
	var logged bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&logged)
	dest, err := pullAndExtract(t, t.Context(), ref)
	if err != nil {
		t.Fatalf("err = %v: a stream that stops sending must be dropped and fetched again", err)
	}
	if !strings.Contains(logged.String(), "no data received") {
		t.Fatalf("the retry does not say the stream stalled: %s", logged.String())
	}
	assertInstalled(t, dest)
	if n := gets.Load(); n != 2 {
		t.Fatalf("%d GETs, want 2", n)
	}
}

func TestPullWaitsOnASlowStream(t *testing.T) {
	img, _ := twoLayers(t)
	saved := stallTimeout
	t.Cleanup(func() { stallTimeout = saved })
	stallTimeout = time.Second
	ref, gets := faultyRegistry(t, img, blobPathSuffix(layerDigests(t, img)[1]), func(w http.ResponseWriter, body []byte) bool {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		// Slower in all than the stall timeout, never silent for as long.
		for i := range body {
			_, _ = w.Write(body[i : i+1])
			w.(http.Flusher).Flush()
			time.Sleep(3 * time.Second / time.Duration(len(body)))
		}
		return true
	})
	if _, err := pullAndExtract(t, t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if n := gets.Load(); n != 1 {
		t.Fatalf("%d GETs, want 1: a stream that keeps sending is not stalled", n)
	}
}

func TestPullRetriesAStalledManifest(t *testing.T) {
	img, _ := twoLayers(t)
	saved := stallTimeout
	t.Cleanup(func() { stallTimeout = saved })
	stallTimeout = time.Second
	release := make(chan struct{})
	var calls atomic.Int32
	ref, gets := faultyRegistry(t, img, "/manifests/"+tag, func(w http.ResponseWriter, _ []byte) bool {
		if calls.Add(1) > 1 {
			return false
		}
		<-release
		return true
	})
	t.Cleanup(func() { close(release) })
	if _, err := Open(t.Context(), ref, "linux/"+runtime.GOARCH, false); err != nil {
		t.Fatalf("err = %v: a manifest that never comes must be asked for again", err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("%d GETs, want 2", n)
	}
}

func TestACertificateErrorIsNotRetried(t *testing.T) {
	for _, err := range []error{
		&url.Error{Op: "Get", URL: "https://registry.example/v2/", Err: x509.UnknownAuthorityError{}},
		&url.Error{Op: "Get", URL: "https://registry.example/v2/", Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "registry.example"}},
		&url.Error{Op: "Get", URL: "https://registry.example/v2/", Err: x509.CertificateInvalidError{Reason: x509.Expired}},
	} {
		if (registrySource{}).transient(err) {
			t.Errorf("%v is retried; another attempt gets the same certificate", err)
		}
	}
	if !(registrySource{}).transient(&url.Error{Op: "Get", URL: "https://registry.example/v2/", Err: io.ErrUnexpectedEOF}) {
		t.Error("a broken connection is not retried")
	}
}

type recordingTransport struct{ sent []string }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.sent = append(r.sent, req.URL.String())
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// Over plain http anyone on the path can answer the tag with a manifest of
// their own, and every digest checked after comes from it.
func TestPlainHTTPGoesOnlyToALoopbackAddress(t *testing.T) {
	for _, tc := range []struct {
		url, sent string // sent "" is refused when redirected to
	}{
		{"http://10.0.0.5:5000/v2/", "https://10.0.0.5:5000/v2/"},
		{"http://172.16.0.1/v2/", "https://172.16.0.1/v2/"},
		{"http://192.168.1.10:5000/v2/", "https://192.168.1.10:5000/v2/"},
		{"http://registry.local/v2/", "https://registry.local/v2/"},
		{"http://127.0.0.1.nip.io/v2/", "https://127.0.0.1.nip.io/v2/"},
		{"http://localhost:5000/v2/", "https://localhost:5000/v2/"},
		{"http://[fe80::1]:5000/v2/", "https://[fe80::1]:5000/v2/"},
		{"http://auth.example.com/token?scope=x", "https://auth.example.com/token?scope=x"},
		{"http://127.0.0.1:5000/v2/", "http://127.0.0.1:5000/v2/"},
		{"http://127.0.0.2/v2/", "http://127.0.0.2/v2/"},
		{"http://[::1]:5000/v2/", "http://[::1]:5000/v2/"},
		{"http://[::ffff:127.0.0.1]:5000/v2/", "http://[::ffff:127.0.0.1]:5000/v2/"},
		{"https://10.0.0.5:5000/v2/", "https://10.0.0.5:5000/v2/"},
		{"https://quay.io/v2/", "https://quay.io/v2/"},
	} {
		for _, redirected := range []bool{false, true} {
			next := &recordingTransport{}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.url, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			if redirected {
				req.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect}
			}
			resp, err := httpsOnly{next}.RoundTrip(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			plainRefused := redirected && strings.HasPrefix(tc.url, "http:") && !strings.HasPrefix(tc.sent, "http:")
			switch {
			case plainRefused && (!errors.Is(err, ErrInsecureRegistry) || len(next.sent) != 0):
				t.Errorf("redirect to %s: err = %v, sent %v, want ErrInsecureRegistry and nothing sent", tc.url, err, next.sent)
			case !plainRefused && (err != nil || len(next.sent) != 1 || next.sent[0] != tc.sent):
				t.Errorf("%s (redirect %v): err = %v, sent %v, want %s", tc.url, redirected, err, next.sent, tc.sent)
			case req.URL.String() != tc.url:
				t.Errorf("%s: the caller's request was changed to %s", tc.url, req.URL)
			}
		}
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, unix.ECONNREFUSED
}

// The client reports the URL it asked for, which is http.
func TestAnUpgradedRequestSaysItWentOverHTTPS(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://10.0.0.5:5000/v2/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := httpsOnly{failingTransport{}}.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, unix.ECONNREFUSED) || !strings.Contains(err.Error(), "sent over https") {
		t.Fatalf("err = %v, want the failure, saying it was sent over https", err)
	}
}

// A registry may itself switch to plain http with a redirect; localhost is
// a name, which DNS may resolve elsewhere.
func TestPullRefusesARedirectToPlainHTTP(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		img, _ := twoLayers(t)
		var ref string
		var redirects atomic.Int32
		ref, _ = faultyRegistry(t, img, "/manifests/"+tag, func(w http.ResponseWriter, _ []byte) bool {
			if redirects.Add(1) > 1 {
				return false
			}
			_, port, err := net.SplitHostPort(strings.SplitN(ref, "/", 2)[0])
			if err != nil {
				t.Error(err)
			}
			w.Header().Set("Location", "http://localhost:"+port+"/v2/kairos/hadron/manifests/"+tag)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return true
		})
		got, err := Open(t.Context(), ref, "linux/"+runtime.GOARCH, insecure)
		switch {
		case !insecure && !errors.Is(err, ErrInsecureRegistry):
			t.Errorf("without --insecure-registry: err = %v, want ErrInsecureRegistry", err)
		case !insecure && redirects.Load() != 1:
			t.Errorf("without --insecure-registry: %d GETs of the manifest, want 1: the refusal is not retried", redirects.Load())
		case insecure && err != nil:
			t.Errorf("with --insecure-registry: %v", err)
		case insecure && got.Transport() != "registry, plain http allowed":
			t.Errorf("with --insecure-registry: transport %q, want plain http allowed", got.Transport())
		}
	}
}

func TestInsecureRegistryLetsTheClientFallBackToHTTP(t *testing.T) {
	for _, ref := range []string{"10.0.0.5:5000/kairos/hadron:v1", "quay.io/kairos/hadron:v1"} {
		src, err := openSource(ref, false)
		if err != nil || src.transport() != "registry" {
			t.Errorf("%s: transport %v, %v, want registry", ref, src, err)
		}
		src, err = openSource(ref, true)
		if err != nil {
			t.Fatal(err)
		}
		if s := src.(registrySource).ref.Context().Scheme(); s != "http" || src.transport() != "registry, plain http allowed" {
			t.Errorf("%s with --insecure-registry: scheme %s, transport %q, want http allowed and said", ref, s, src.transport())
		}
	}
}

// For a private address ggcr follows a failed https ping with an http one
// at once; asked over https instead, it is as good as a retry, and the
// https error, not the refusal, decides whether to try again.
func TestPullRetriesAPrivateRegistryOverHTTPS(t *testing.T) {
	savedDelay, savedTransport := retryDelay, registryTransport
	t.Cleanup(func() { retryDelay, registryTransport = savedDelay, savedTransport })
	retryDelay = 0
	img, _ := twoLayers(t)
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	plain := httptest.NewServer(inner)
	t.Cleanup(plain.Close)
	r, err := name.ParseReference(strings.TrimPrefix(plain.URL, "http://") + "/kairos/hadron:" + tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	var pings atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" && pings.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	registryTransport = tr
	var logged bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&logged)
	dest, err := pullAndExtract(t, t.Context(), "10.0.0.5:5000/kairos/hadron:"+tag)
	if err != nil {
		t.Fatal(err)
	}
	assertInstalled(t, dest)
	if !strings.Contains(logged.String(), "attempt 1 of 5: GET https://10.0.0.5:5000/v2/: unexpected status code 503 Service Unavailable; GET https://10.0.0.5:5000/v2/: unexpected status code 503 Service Unavailable; retrying") {
		t.Fatalf("log %q, want the first attempt to fail on both pings over https and be retried", logged.String())
	}
}

// Over HTTP/2 the client reports a cancelled request as context.Canceled,
// not its cause, which would read as an interrupted install.
func TestAStallOverHTTP2IsReportedAsAStall(t *testing.T) {
	savedDelay, savedTransport, savedStall := retryDelay, registryTransport, stallTimeout
	t.Cleanup(func() { retryDelay, registryTransport, stallTimeout = savedDelay, savedTransport, savedStall })
	retryDelay, stallTimeout = 0, 300*time.Millisecond
	img, _ := twoLayers(t)
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	plain := httptest.NewServer(inner)
	t.Cleanup(plain.Close)
	r, err := name.ParseReference(strings.TrimPrefix(plain.URL, "http://") + "/kairos/hadron:" + tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	blob := blobPathSuffix(layerDigests(t, img)[1])
	var h2 atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, blob) {
			inner.ServeHTTP(w, r)
			return
		}
		h2.Store(r.ProtoMajor == 2)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	registryTransport = srv.Client().Transport
	_, err = pullAndExtract(t, t.Context(), strings.TrimPrefix(srv.URL, "https://")+"/kairos/hadron:"+tag)
	if !h2.Load() {
		t.Fatal("the layer was not fetched over HTTP/2")
	}
	if !errors.Is(err, errStalled) || errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want a stall, not a cancellation", err)
	}
}
