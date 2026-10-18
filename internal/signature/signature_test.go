package signature

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/lexfrei/boot-to-kairos/internal/image"
)

// The fixtures are public data from quay.io/kairos/hadron: two release
// indexes as Kairos's pipeline signed them, v4.3.0 with a sigstore bundle
// attached as a referrer and v4.2.0 with a legacy .sig tag, and a Sigstore
// trusted root fetched through its TUF repository.
const (
	tag430     = "v0.5.1-core-amd64-generic-v4.3.0"
	tag420     = "v0.5.1-core-amd64-generic-v4.2.0"
	digest430  = "sha256:0642483eb9f7a3d42cc2d4e4b15afc37ced49d42b15d836e59a8ea0ab25dd9af"
	digest420  = "sha256:ca75eb00118696ead63c689f92138da23c7231eb63c2903d7a7e7375ff5f7e83"
	san430     = "https://github.com/kairos-io/kairos/.github/workflows/reusable-factory.yaml@refs/tags/v4.3.0"
	logIdx430  = 2755351284
	emptyJSON  = "{}"
	repository = "kairos/hadron"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHash(t *testing.T, s string) v1.Hash {
	t.Helper()
	h, err := v1.NewHash(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func trusted(t *testing.T) root.TrustedMaterial {
	t.Helper()
	tm, err := Trusted(context.Background(), filepath.Join("testdata", "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// testRegistry is an in-process registry that records the paths of the
// requests it gets.
type testRegistry struct {
	host string
	mu   sync.Mutex
	gets []string
}

// newRegistry serves the referrers API unless withoutReferrersAPI, when
// clients fall back to the tag schema.
func newRegistry(t *testing.T, withoutReferrersAPI ...bool) *testRegistry {
	t.Helper()
	r := &testRegistry{}
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)), registry.WithReferrersSupport(len(withoutReferrersAPI) == 0))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			r.mu.Lock()
			r.gets = append(r.gets, req.URL.Path)
			r.mu.Unlock()
		}
		inner.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	r.host = strings.TrimPrefix(srv.URL, "http://")
	return r
}

func (r *testRegistry) requested() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.gets...)
}

type rawManifest struct {
	raw []byte
	mt  types.MediaType
}

func (m rawManifest) RawManifest() ([]byte, error)        { return m.raw, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return m.mt, nil }

// putManifest stores raw under its digest and, if ref is not empty, under
// that tag too.
func (r *testRegistry) putManifest(t *testing.T, raw []byte, ref string) v1.Hash {
	t.Helper()
	var m struct {
		MediaType types.MediaType `json:"mediaType"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	h, _, err := v1.SHA256(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	refs := []string{"@" + h.String()}
	if ref != "" {
		refs = append(refs, ":"+ref)
	}
	for _, s := range refs {
		nr, err := name.ParseReference(r.host + "/" + repository + s)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Put(nr, rawManifest{raw, m.MediaType}); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (r *testRegistry) putBlob(t *testing.T, b []byte) {
	t.Helper()
	repo, err := name.NewRepository(r.host + "/" + repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteLayer(repo, static.NewLayer(b, types.MediaType("application/octet-stream"))); err != nil {
		t.Fatal(err)
	}
}

// index430 stores the v4.3.0 index, without its signature, under ref.
func (r *testRegistry) index430(t *testing.T, ref string) {
	t.Helper()
	r.putManifest(t, fixture(t, "v4.3.0-f29481c2351b.json"), "")
	r.putManifest(t, fixture(t, "v4.3.0-70ea476c09b5.json"), "")
	r.putManifest(t, fixture(t, "v4.3.0-index.json"), ref)
}

// bundle430 attaches referrer, a manifest whose layer is bundle.
func (r *testRegistry) bundle430(t *testing.T, referrer, bundle []byte) {
	t.Helper()
	r.putBlob(t, []byte(emptyJSON))
	r.putBlob(t, bundle)
	r.putManifest(t, referrer, "")
}

// signed420 stores the v4.2.0 index with its legacy signature under ref.
func (r *testRegistry) signed420(t *testing.T, ref string) {
	t.Helper()
	r.putManifest(t, fixture(t, "v4.2.0-1fd511085681.json"), "")
	r.putManifest(t, fixture(t, "v4.2.0-e0b1fa677037.json"), "")
	r.putManifest(t, fixture(t, "v4.2.0-index.json"), ref)
	r.putBlob(t, []byte(emptyJSON))
	r.putBlob(t, fixture(t, "v4.2.0-sig-payload.json"))
	r.putManifest(t, fixture(t, "v4.2.0-sig.json"), strings.Replace(digest420, ":", "-", 1)+".sig")
}

func (r *testRegistry) source(t *testing.T, digest, tag string) image.SignatureSource {
	t.Helper()
	repo, err := name.NewRepository(r.host + "/" + repository)
	if err != nil {
		t.Fatal(err)
	}
	return image.SignatureSource{
		Digests:    []v1.Hash{mustHash(t, digest)},
		Tag:        tag,
		Repository: repo,
		Options:    []remote.Option{remote.WithContext(context.Background())},
	}
}

func TestAReleaseSignedWithABundleVerifies(t *testing.T) {
	for _, api := range []bool{true, false} {
		r := newRegistry(t)
		if !api {
			r = newRegistry(t, true)
		}
		r.index430(t, tag430)
		r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
		res, err := Verify(context.Background(), r.source(t, digest430, tag430), Policy{}, trusted(t))
		if err != nil {
			t.Fatalf("referrers API %v: %v", api, err)
		}
		if res.Digest.String() != digest430 || res.Identity != san430 || res.Issuer != GitHubIssuer || res.SourceRef != "refs/tags/v4.3.0" || res.LogIndex != logIdx430 {
			t.Fatalf("referrers API %v: got %+v", api, res)
		}
	}
}

func TestAReleaseSignedTheLegacyWayVerifies(t *testing.T) {
	r := newRegistry(t)
	r.signed420(t, tag420)
	res, err := Verify(context.Background(), r.source(t, digest420, tag420), Policy{}, trusted(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Digest.String() != digest420 || res.SourceRef != "refs/tags/v4.2.0" || res.Issuer != GitHubIssuer || res.LogIndex == 0 ||
		!strings.HasPrefix(res.Identity, "https://github.com/kairos-io/kairos-factory-action/") {
		t.Fatalf("got %+v", res)
	}
}

func TestADigestReferenceIsVerifiedWithoutATag(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, "")
	r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
	if _, err := Verify(context.Background(), r.source(t, digest430, ""), Policy{}, trusted(t)); err != nil {
		t.Fatal(err)
	}
}

func TestAnUnsignedImageIsRefused(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, tag430)
	_, err := Verify(context.Background(), r.source(t, digest430, tag430), Policy{}, trusted(t))
	if !errors.Is(err, ErrNoSignature) {
		t.Fatalf("got %v, want ErrNoSignature", err)
	}
}

// An older release, genuinely signed, served under a newer release's tag.
func TestARollbackToAnOlderSignedReleaseIsRefused(t *testing.T) {
	r := newRegistry(t)
	r.signed420(t, tag430)
	_, err := Verify(context.Background(), r.source(t, digest420, tag430), Policy{}, trusted(t))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
	r = newRegistry(t)
	r.index430(t, "v0.5.1-core-amd64-generic-v4.4.0")
	r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
	_, err = Verify(context.Background(), r.source(t, digest430, "v0.5.1-core-amd64-generic-v4.4.0"), Policy{}, trusted(t))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// v4.3.0's bundle pointed at the v4.2.0 index: the referrer is found for
// that digest, but what it signs is another one.
func TestABundleMovedToAnotherImageIsRefused(t *testing.T) {
	r := newRegistry(t)
	r.putManifest(t, fixture(t, "v4.2.0-1fd511085681.json"), "")
	r.putManifest(t, fixture(t, "v4.2.0-e0b1fa677037.json"), "")
	r.putManifest(t, fixture(t, "v4.2.0-index.json"), tag430)
	referrer := bytes.Replace(fixture(t, "v4.3.0-referrer.json"), []byte(digest430), []byte(digest420), 1)
	r.bundle430(t, referrer, fixture(t, "v4.3.0-bundle.json"))
	_, err := Verify(context.Background(), r.source(t, digest420, tag430), Policy{}, trusted(t))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestATamperedBundleIsRefused(t *testing.T) {
	var b map[string]any
	if err := json.Unmarshal(fixture(t, "v4.3.0-bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	env := b["dsseEnvelope"].(map[string]any)
	sig := env["signatures"].([]any)[0].(map[string]any)
	s := sig["sig"].(string)
	sig["sig"] = s[:10] + string(s[10]^1) + s[11:]
	bundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	h, size, err := v1.SHA256(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(fixture(t, "v4.3.0-referrer.json"), &m); err != nil {
		t.Fatal(err)
	}
	layer := m["layers"].([]any)[0].(map[string]any)
	layer["digest"], layer["size"] = h.String(), size
	referrer, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r := newRegistry(t)
	r.index430(t, tag430)
	r.bundle430(t, referrer, bundle)
	_, err = Verify(context.Background(), r.source(t, digest430, tag430), Policy{}, trusted(t))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestAnotherSignerIsRefused(t *testing.T) {
	for _, p := range []Policy{
		{Identity: `^https://github\.com/example/`, Issuer: GitHubIssuer},
		{Identity: `^https://github\.com/kairos-io/`, Issuer: "https://accounts.google.com"},
	} {
		r := newRegistry(t)
		r.index430(t, tag430)
		r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
		_, err := Verify(context.Background(), r.source(t, digest430, tag430), p, trusted(t))
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%+v: got %v, want ErrBadSignature", p, err)
		}
		r = newRegistry(t)
		r.signed420(t, tag420)
		_, err = Verify(context.Background(), r.source(t, digest420, tag420), p, trusted(t))
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("legacy, %+v: got %v, want ErrBadSignature", p, err)
		}
	}
}

// A policy of one's own names the signer and nothing else: the tag is not
// bound to Kairos's release naming.
func TestAnOwnPolicyAcceptsItsSignerUnderAnyTag(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, "anything")
	r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
	p := Policy{Identity: `^https://github\.com/kairos-io/kairos/`, Issuer: GitHubIssuer}
	if _, err := Verify(context.Background(), r.source(t, digest430, "anything"), p, trusted(t)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyingFetchesNoLayer(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, tag430)
	r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
	if _, err := Verify(context.Background(), r.source(t, digest430, tag430), Policy{}, trusted(t)); err != nil {
		t.Fatal(err)
	}
	// The referrer's own blobs: the bundle and its empty config.
	signature := []string{
		"sha256:cfa6de422ca9c0205f4dd142f400cfe552bf238e23db1cd20b18bb8b9ed74984",
		"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
	}
	for _, p := range r.requested() {
		if _, blob, ok := strings.Cut(p, "/blobs/"); ok && !slices.Contains(signature, blob) {
			t.Errorf("fetched %s", p)
		}
	}
}

func TestBundlesFromALayoutVerifyOffline(t *testing.T) {
	d := mustHash(t, digest430)
	src := image.SignatureSource{
		Digests: []v1.Hash{mustHash(t, "sha256:f29481c2351b91ab61d28a40eb76a0a406120689f9fa93ac53f7f6f502159d89"), d},
		Bundles: map[v1.Hash][][]byte{d: {fixture(t, "v4.3.0-bundle.json")}},
	}
	res, err := Verify(context.Background(), src, Policy{}, trusted(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Digest != d || res.LogIndex != logIdx430 {
		t.Fatalf("got %+v", res)
	}
	src.Bundles = nil
	if _, err := Verify(context.Background(), src, Policy{}, trusted(t)); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("got %v, want ErrNoSignature", err)
	}
	src.Bundles = map[v1.Hash][][]byte{src.Digests[0]: {fixture(t, "v4.3.0-bundle.json")}}
	if _, err := Verify(context.Background(), src, Policy{}, trusted(t)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a bundle for another digest: got %v, want ErrBadSignature", err)
	}
}

func TestTheReleaseMustBeTheOneTheTagNames(t *testing.T) {
	good := certificate.Summary{Extensions: certificate.Extensions{
		SourceRepositoryURI: "https://github.com/kairos-io/kairos",
		SourceRepositoryRef: "refs/tags/v4.3.0",
	}}
	for _, tc := range []struct {
		tag  string
		ext  func(*certificate.Extensions)
		fail bool
	}{
		{tag: tag430},
		{tag: ""},
		{tag: "v0.5.1-standard-amd64-generic-v4.3.0-k3s-v1.34.11-k3s1"},
		{tag: "v0.5.1-core-amd64-generic-v4.3.0-rc7", ext: func(e *certificate.Extensions) { e.SourceRepositoryRef = "refs/tags/v4.3.0-rc7" }},
		{tag: "v0.5.1-core-amd64-generic-v4.3.0", ext: func(e *certificate.Extensions) { e.SourceRepositoryRef = "refs/tags/v4.3.0-rc7" }, fail: true},
		{tag: "v0.5.1-core-amd64-generic-v4.3.1", fail: true},
		{tag: "v4.3.0-core-amd64-generic-v4.2.0", fail: true},
		{tag: "latest", fail: true},
		{tag: "", ext: func(e *certificate.Extensions) { e.SourceRepositoryURI = "https://github.com/example/kairos" }, fail: true},
		{tag: "", ext: func(e *certificate.Extensions) { e.SourceRepositoryRef = "refs/heads/master" }, fail: true},
		{tag: "", ext: func(e *certificate.Extensions) { e.SourceRepositoryRef = "" }, fail: true},
	} {
		s := good
		if tc.ext != nil {
			tc.ext(&s.Extensions)
		}
		err := checkRelease(&s, tc.tag)
		if (err != nil) != tc.fail {
			t.Errorf("tag %q, %+v: got %v", tc.tag, s.Extensions, err)
		}
	}
}

func TestOnlyACosignSignatureStatementCounts(t *testing.T) {
	if err := checkPredicate("https://sigstore.dev/cosign/sign/v1"); err != nil {
		t.Fatal(err)
	}
	if err := checkPredicate("https://spdx.dev/Document"); err == nil {
		t.Fatal("an SPDX statement was taken for a signature")
	}
}

func TestTheDefaultSignerIsKairossReleaseWorkflow(t *testing.T) {
	co := checkOpts(Policy{}, nil)
	if len(co.Identities) != 1 || co.Identities[0].Issuer != GitHubIssuer || co.Identities[0].SubjectRegExp != kairosIdentity || co.ClaimVerifier == nil {
		t.Fatalf("got %+v", co)
	}
	re := regexp.MustCompile(kairosIdentity)
	for san, want := range map[string]bool{
		san430: true,
		"https://github.com/kairos-io/kairos-factory-action/.github/workflows/reusable-factory.yaml@9bf6ee71187036eb832f28c29f0c699507bc1ca3": true,
		"https://github.com/kairos-io/kairos-fork/.github/workflows/reusable-factory.yaml@refs/tags/v4.3.0":                                   false,
		"https://github.com/example/kairos/.github/workflows/reusable-factory.yaml@refs/tags/v4.3.0":                                          false,
		"https://github.com/kairos-io/kairos/blob/x/.github/workflows/a.yaml":                                                                 false,
	} {
		if re.MatchString(san) != want {
			t.Errorf("%s: match %v, want %v", san, !want, want)
		}
	}
	own := Policy{Identity: "^x$", Issuer: "https://example.com"}
	if co := checkOpts(own, nil); co.Identities[0].Issuer != own.Issuer || co.Identities[0].SubjectRegExp != own.Identity {
		t.Fatalf("own policy: got %+v", co.Identities)
	}
}

// The legacy payload names the digest it signs; a .sig tag is found by
// the digest it is named after, which anyone with push access can choose.
func TestALegacySignatureMovedToAnotherImageIsRefused(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, tag430)
	r.putBlob(t, []byte(emptyJSON))
	r.putBlob(t, fixture(t, "v4.2.0-sig-payload.json"))
	r.putManifest(t, fixture(t, "v4.2.0-sig.json"), strings.Replace(digest430, ":", "-", 1)+".sig")
	// An own policy has no release to check, which would refuse it too.
	p := Policy{Identity: `^https://github\.com/kairos-io/`, Issuer: GitHubIssuer}
	_, err := Verify(context.Background(), r.source(t, digest430, tag430), p, trusted(t))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// A registry that fails to list referrers has not said the image is
// unsigned.
func TestAFailedReferrersLookupIsNotAMissingSignature(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, tag430)
	inner := http.DefaultTransport
	src := r.source(t, digest430, tag430)
	src.Options = append(src.Options, remote.WithTransport(roundTripper(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/referrers/") {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("")), Request: req, Header: http.Header{}}, nil
		}
		return inner.RoundTrip(req)
	})), remote.WithRetryBackoff(remote.Backoff{Steps: 1}))
	_, err := Verify(context.Background(), src, Policy{}, trusted(t))
	if err == nil || errors.Is(err, ErrNoSignature) || errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want a lookup error", err)
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestABundleMustBeACosignSignatureByACertificate(t *testing.T) {
	cert := &certificate.Summary{Extensions: certificate.Extensions{SourceRepositoryURI: kairosRepository, SourceRepositoryRef: "refs/tags/v4.3.0"}}
	ok := &verify.VerificationResult{
		Statement: &in_toto.Statement{PredicateType: signPredicate},
		Signature: &verify.SignatureVerificationResult{Certificate: cert},
	}
	if err := accept(ok, tag430, Policy{}); err != nil {
		t.Fatal(err)
	}
	sbom := *ok
	sbom.Statement = &in_toto.Statement{PredicateType: "https://spdx.dev/Document"}
	key := *ok
	key.Signature = &verify.SignatureVerificationResult{}
	rollback := *ok
	for name, vr := range map[string]*verify.VerificationResult{"sbom": &sbom, "key": &key} {
		if err := accept(vr, tag430, Policy{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := accept(&rollback, "v0.5.1-core-amd64-generic-v4.4.0", Policy{}); err == nil {
		t.Error("a release under another release's tag was accepted")
	}
}

// A bundle that fails to download has not said the image is unsigned, and
// must not be skipped for the legacy signature either.
func TestAFailedBundleDownloadIsNotAMissingSignature(t *testing.T) {
	for _, failing := range []string{
		"/manifests/sha256:8cb7dafc3126e0a185a7151e21dd30e150fa88ee7d2c7d0f25029a8fe5aff948",
		"/blobs/sha256:cfa6de422ca9c0205f4dd142f400cfe552bf238e23db1cd20b18bb8b9ed74984",
	} {
		r := newRegistry(t)
		r.index430(t, tag430)
		r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
		inner := http.DefaultTransport
		src := r.source(t, digest430, tag430)
		src.Options = append(src.Options, remote.WithTransport(roundTripper(func(req *http.Request) (*http.Response, error) {
			if strings.HasSuffix(req.URL.Path, failing) {
				return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("")), Request: req, Header: http.Header{}}, nil
			}
			return inner.RoundTrip(req)
		})), remote.WithRetryBackoff(remote.Backoff{Steps: 1}))
		_, err := Verify(context.Background(), src, Policy{}, trusted(t))
		if err == nil || errors.Is(err, ErrNoSignature) || errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s failing: got %v, want a download error", failing, err)
		}
	}
}

// A registry reached over plain http by --insecure-registry under a name
// the client would otherwise reach over https.
func TestTheBundleIsFetchedOverTheSameSchemeAsTheImage(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, tag430)
	r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
	_, port, err := net.SplitHostPort(r.host)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := name.NewRepository("registry.example:"+port+"/"+repository, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	dial := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, r.host)
	}}
	src := image.SignatureSource{
		Digests:    []v1.Hash{mustHash(t, digest430)},
		Tag:        tag430,
		Repository: repo,
		Options:    []remote.Option{remote.WithTransport(dial)},
	}
	if _, err := Verify(context.Background(), src, Policy{}, trusted(t)); err != nil {
		t.Fatal(err)
	}
}

// Bundles that verify but are statements other than a signature, an SBOM
// say, leave the image to its legacy signature.
func TestAttestationsAloneDoNotHideALegacySignature(t *testing.T) {
	saved := verifyBundle
	t.Cleanup(func() { verifyBundle = saved })
	verifyBundle = func(context.Context, *cosign.CheckOpts, verify.ArtifactPolicyOption, verify.SignedEntity) (*verify.VerificationResult, error) {
		return &verify.VerificationResult{Statement: &in_toto.Statement{PredicateType: "https://spdx.dev/Document"}}, nil
	}
	r := newRegistry(t)
	r.signed420(t, tag420)
	referrer := bytes.Replace(fixture(t, "v4.3.0-referrer.json"), []byte(digest430), []byte(digest420), 1)
	r.bundle430(t, referrer, fixture(t, "v4.3.0-bundle.json"))
	res, err := Verify(context.Background(), r.source(t, digest420, tag420), Policy{}, trusted(t))
	if err != nil || res.SourceRef != "refs/tags/v4.2.0" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestTheTrustedRootFetchStopsWithTheInstall(t *testing.T) {
	hung := make(chan struct{})
	var asked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		asked.Store(true)
		select {
		case <-req.Context().Done():
		case <-hung:
		}
	}))
	t.Cleanup(func() { close(hung); srv.Close() })
	saved := tufRepository
	t.Cleanup(func() { tufRepository = saved })
	tufRepository = srv.URL
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Trusted(ctx, ""); done <- err }()
	select {
	case err := <-done:
		if err == nil || !asked.Load() {
			t.Fatalf("got %v from a repository asked %v", err, asked.Load())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the fetch did not stop when its context ended")
	}
}

func TestTheTUFFetcherAnswersAsTheTUFClientExpects(t *testing.T) {
	saved := tufTimeout
	t.Cleanup(func() { tufTimeout = saved })
	tufTimeout = 200 * time.Millisecond
	hung := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/missing":
			http.NotFound(w, req)
		case "/large":
			_, _ = w.Write([]byte("0123456789"))
		case "/ok":
			_, _ = w.Write([]byte("01234"))
		default:
			select {
			case <-req.Context().Done():
			case <-hung:
			}
		}
	}))
	t.Cleanup(func() { close(hung); srv.Close() })
	f := ctxFetcher{context.Background()}
	// The client takes a 404 for the next root as there being none.
	_, err := f.DownloadFile(srv.URL+"/missing", 5, 0)
	if e := (*metadata.ErrDownloadHTTP)(nil); !errors.As(err, &e) || e.StatusCode != http.StatusNotFound {
		t.Errorf("missing: got %v", err)
	}
	if _, err := f.DownloadFile(srv.URL+"/large", 5, 0); !errors.Is(err, &metadata.ErrDownloadLengthMismatch{}) {
		t.Errorf("large: got %v", err)
	}
	if b, err := f.DownloadFile(srv.URL+"/ok", 5, 0); err != nil || string(b) != "01234" {
		t.Errorf("ok: got %q, %v", b, err)
	}
	start := time.Now()
	if _, err := f.DownloadFile(srv.URL+"/hang", 5, 0); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("hang: got %v after %s", err, time.Since(start))
	}
}

// A referrer that is not a sigstore bundle, an SBOM say, is no signature
// attempt either.
func TestAReferrerThatIsNoBundleLeavesTheLegacySignature(t *testing.T) {
	r := newRegistry(t)
	r.signed420(t, tag420)
	sbom := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	r.putBlob(t, sbom)
	h, size, err := v1.SHA256(bytes.NewReader(sbom))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.Replace(fixture(t, "v4.3.0-referrer.json"), []byte(digest430), []byte(digest420), 1), &m); err != nil {
		t.Fatal(err)
	}
	m["layers"] = []any{map[string]any{"mediaType": "application/spdx+json", "digest": h.String(), "size": size}}
	m["artifactType"] = "application/spdx+json"
	referrer, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r.putBlob(t, []byte(emptyJSON))
	r.putManifest(t, referrer, "")
	if _, err := Verify(context.Background(), r.source(t, digest420, tag420), Policy{}, trusted(t)); err != nil {
		t.Fatal(err)
	}
}

func TestABundleThatDoesNotParseIsRefused(t *testing.T) {
	d := mustHash(t, digest430)
	src := image.SignatureSource{Digests: []v1.Hash{d}, Bundles: map[v1.Hash][][]byte{d: {[]byte("not a bundle")}}}
	if _, err := Verify(context.Background(), src, Policy{}, trusted(t)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// otherStatement rewrites the v4.3.0 bundle into one whose statement is an
// SBOM, as another signer's attestation would be. Its signature no longer
// matches, which must not matter: it is not read as a signature at all.
func otherStatement(t *testing.T) []byte {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(fixture(t, "v4.3.0-bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	env := b["dsseEnvelope"].(map[string]any)
	stmt := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + strings.TrimPrefix(digest420, "sha256:") + `"}}],"predicateType":"https://spdx.dev/Document","predicate":{}}`
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(stmt))
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAnotherSignersAttestationDoesNotHideALegacySignature(t *testing.T) {
	r := newRegistry(t)
	r.signed420(t, tag420)
	bundle := otherStatement(t)
	h, size, err := v1.SHA256(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.Replace(fixture(t, "v4.3.0-referrer.json"), []byte(digest430), []byte(digest420), 1), &m); err != nil {
		t.Fatal(err)
	}
	layer := m["layers"].([]any)[0].(map[string]any)
	layer["digest"], layer["size"] = h.String(), size
	referrer, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r.bundle430(t, referrer, bundle)
	res, err := Verify(context.Background(), r.source(t, digest420, tag420), Policy{}, trusted(t))
	if err != nil || res.SourceRef != "refs/tags/v4.2.0" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

// A referrer that is an index, or that a registry still lists after
// deleting it, does not stop the lookup.
func TestReferrersOtherThanBundlesAreNotFetched(t *testing.T) {
	r := newRegistry(t)
	r.index430(t, tag430)
	r.bundle430(t, fixture(t, "v4.3.0-referrer.json"), fixture(t, "v4.3.0-bundle.json"))
	gone := v1.Descriptor{MediaType: types.OCIManifestSchema1, Size: 10, Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("d", 64)}, ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json"}
	sbom := v1.Descriptor{MediaType: types.OCIManifestSchema1, Size: 10, Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("e", 64)}, ArtifactType: "application/spdx+json"}
	// An index with nothing for any platform: reading it as an image fails.
	emptyIndex := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	nested := v1.Descriptor{MediaType: types.OCIImageIndex, Size: int64(len(emptyIndex)), Digest: r.putManifest(t, emptyIndex, "")}
	inner := http.DefaultTransport
	src := r.source(t, digest430, tag430)
	src.Options = append(src.Options, remote.WithTransport(roundTripper(func(req *http.Request) (*http.Response, error) {
		res, err := inner.RoundTrip(req)
		if err != nil || res.StatusCode != http.StatusOK || !strings.Contains(req.URL.Path, "/referrers/") {
			return res, err
		}
		defer res.Body.Close()
		var idx v1.IndexManifest
		if err := json.NewDecoder(res.Body).Decode(&idx); err != nil {
			return nil, err
		}
		idx.Manifests = append([]v1.Descriptor{gone, sbom, nested}, idx.Manifests...)
		b, err := json.Marshal(idx)
		if err != nil {
			return nil, err
		}
		res.Body = io.NopCloser(bytes.NewReader(b))
		res.ContentLength = int64(len(b))
		res.Header.Del("Content-Length")
		return res, nil
	})), remote.WithRetryBackoff(remote.Backoff{Steps: 1}))
	if _, err := Verify(context.Background(), src, Policy{}, trusted(t)); err != nil {
		t.Fatal(err)
	}
}
