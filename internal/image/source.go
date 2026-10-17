package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

var (
	// ErrMismatch is a manifest, config or layer that differs from the
	// digest or size its parent names.
	ErrMismatch = errors.New("does not match its descriptor")
	// ErrPlatform is an image with nothing for the requested platform.
	ErrPlatform = errors.New("no image for this platform")
	// ErrAmbiguous is a layout with more than one image to choose from.
	ErrAmbiguous = errors.New("the image layout holds more than one image for this platform")
	// ErrLegacyDockerArchive is a docker save archive in the format Docker
	// 25 replaced with an OCI image layout.
	ErrLegacyDockerArchive = errors.New("a docker save archive without an OCI index is not supported")
	// ErrInsecureRegistry is a redirect to plain http to an address other
	// than a loopback one.
	ErrInsecureRegistry = errors.New("plain http to a registry on another machine is refused")

	errLocal   = errors.New("local write")
	errStalled = errors.New("no data received")
)

const (
	ociPrefix        = "oci:"
	ociArchivePrefix = "oci-archive:"
	// fetchAttempts bounds the fetches of one blob from a registry.
	fetchAttempts = 5
	// maxManifest caps the size a descriptor may give an index, a manifest
	// or a config, which are read into memory; real ones are a few KiB.
	maxManifest = 4 << 20
	// maxDepth bounds indexes nested in indexes.
	maxDepth = 4
)

// retryDelay is the first wait between fetches; it doubles each time.
var retryDelay = time.Second //nolint:gochecknoglobals // test seam

var registryTransport = remote.DefaultTransport //nolint:gochecknoglobals // test seam

// stallTimeout drops a fetch that has received nothing for this long, so a
// stream that stops without breaking is retried rather than waited on.
var stallTimeout = time.Minute //nolint:gochecknoglobals // test seam

// source reads manifests and blobs by descriptor. What it returns is
// verified by the caller, whatever the source checks on its own.
type source interface {
	// root returns the starting index or manifest: the one a registry
	// reference names, or a layout's index.json. A layout's index.json may
	// list several images and has no digest.
	root(ctx context.Context) (raw []byte, mt types.MediaType, d v1.Hash, layout bool, err error)
	open(ctx context.Context, d *v1.Descriptor) (io.ReadCloser, error)
	// transient says whether fetching again may give another result.
	transient(err error) bool
	transport() string
	close() error
}

// Open resolves ref for platform, for example linux/amd64, and reads its
// manifest and config; layers are fetched by Extract. ref is a registry
// reference, oci:DIR for an OCI image layout directory or oci-archive:FILE
// for the same as a tar archive. ctx bounds the requests. insecure allows
// plain http to a registry other than this machine. Close the image once it
// is extracted.
func Open(ctx context.Context, ref, platform string, insecure bool) (*Image, error) {
	want, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, errors.Wrapf(err, "parse platform %s", platform)
	}
	src, err := openSource(ref, insecure)
	if err != nil {
		return nil, err
	}
	digest, m, err := resolveManifest(ctx, src, want)
	if err != nil {
		_ = src.close()
		return nil, errors.Wrapf(err, "resolve %s", ref)
	}
	return &Image{Digest: digest, Layers: m.Layers, src: src}, nil
}

func openSource(ref string, insecure bool) (source, error) {
	if dir, ok := strings.CutPrefix(ref, ociPrefix); ok {
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, errors.Wrap(err, "open image layout")
		}
		return layoutSource{file: func(name string) (io.ReadCloser, error) { return root.Open(name) }, closer: root.Close, kind: "OCI image layout"}, nil
	}
	if file, ok := strings.CutPrefix(ref, ociArchivePrefix); ok {
		open, closer, err := indexTar(file)
		if err != nil {
			return nil, errors.Wrap(err, "open image archive")
		}
		return layoutSource{file: open, closer: closer, kind: "OCI image archive"}, nil
	}
	var opts []name.Option
	if insecure {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", ref)
	}
	if insecure {
		log.Printf("plain http allowed for %s", r.Context().RegistryStr())
	}
	return registrySource{ref: r, insecure: insecure}, nil
}

// resolveManifest walks from the source's root down to the image manifest
// for want, whose config must name want's platform too.
func resolveManifest(ctx context.Context, src source, want *v1.Platform) (v1.Hash, *v1.Manifest, error) {
	raw, mt, digest, anchor, err := src.root(ctx)
	if err != nil {
		return v1.Hash{}, nil, err
	}
	if !anchor && !mt.IsIndex() && !mt.IsImage() {
		// A registry may serve a manifest under a generic content type.
		mt = bodyMediaType(raw)
	}
	r, err := resolveNode(ctx, src, node{raw: raw, mt: mt, digest: digest}, want, anchor, 0)
	if err != nil {
		return v1.Hash{}, nil, err
	}
	return r.digest, r.m, nil
}

type node struct {
	raw    []byte
	mt     types.MediaType
	digest v1.Hash
}

type resolved struct {
	digest v1.Hash
	m      *v1.Manifest
}

func resolveNode(ctx context.Context, src source, n node, want *v1.Platform, anchor bool, depth int) (resolved, error) {
	if depth > maxDepth {
		return resolved{}, errors.New("indexes nested too deep")
	}
	if n.mt.IsImage() {
		m, err := v1.ParseManifest(bytes.NewReader(n.raw))
		if err != nil {
			return resolved{}, errors.Wrap(err, "parse manifest")
		}
		return resolved{n.digest, m}, checkConfig(ctx, src, &m.Config, want)
	}
	if !n.mt.IsIndex() && !anchor {
		return resolved{}, errors.Newf("unsupported media type %q", n.mt)
	}
	idx, err := v1.ParseIndexManifest(bytes.NewReader(n.raw))
	if err != nil {
		return resolved{}, errors.Wrap(err, "parse index")
	}
	return pick(ctx, src, idx, want, anchor, depth)
}

// pick resolves the children of idx that may be for want, in order, and
// takes the first, as a registry client does. A child without a platform
// is followed and dropped if its config names another one. In a layout's
// own index.json the children are separate images, so more than one that
// resolves to a different manifest is refused rather than guessed, as is
// one that cannot be read, which might have been a match. One manifest
// reached twice, as docker save lists an image with two tags, counts once.
func pick(ctx context.Context, src source, idx *v1.IndexManifest, want *v1.Platform, anchor bool, depth int) (resolved, error) {
	var found []resolved
	var names, seen []string
	for i := range idx.Manifests {
		d := &idx.Manifests[i]
		if !d.MediaType.IsImage() && !d.MediaType.IsIndex() {
			continue
		}
		if d.Platform != nil && !d.Platform.Satisfies(*want) {
			seen = append(seen, d.Platform.String())
			continue
		}
		raw, err := fetchSmall(ctx, src, d)
		if err != nil {
			return resolved{}, errors.Wrapf(err, "manifest %s", d.Digest)
		}
		r, err := resolveNode(ctx, src, node{raw: raw, mt: d.MediaType, digest: d.Digest}, want, false, depth+1)
		if errors.Is(err, ErrPlatform) && d.Platform == nil {
			seen = append(seen, "an unlabelled "+d.Digest.String())
			continue
		}
		if err != nil {
			return resolved{}, err
		}
		if !anchor {
			return r, nil
		}
		if slices.ContainsFunc(found, func(f resolved) bool { return f.digest == r.digest }) {
			continue
		}
		found = append(found, r)
		names = append(names, d.Annotations["org.opencontainers.image.ref.name"]+"@"+d.Digest.String())
	}
	switch {
	case len(found) == 0 && len(seen) == 0:
		return resolved{}, errors.Wrapf(ErrPlatform, "want %s, the index lists no images", want.String())
	case len(found) == 0:
		return resolved{}, errors.Wrapf(ErrPlatform, "want %s, the index has %s", want.String(), strings.Join(seen, ", "))
	case len(found) > 1:
		return resolved{}, errors.Wrapf(ErrAmbiguous, "%s; keep one image in it", strings.Join(names, ", "))
	}
	return found[0], nil
}

// bodyMediaType reads the media type a manifest or an index names itself
// with, or infers it from its fields as older ones do not name one.
func bodyMediaType(raw []byte) types.MediaType {
	var b struct {
		MediaType types.MediaType `json:"mediaType"`
		Manifests json.RawMessage `json:"manifests"`
		Layers    json.RawMessage `json:"layers"`
	}
	switch {
	case json.Unmarshal(raw, &b) != nil:
		return ""
	case b.MediaType != "":
		return b.MediaType
	case b.Manifests != nil:
		return types.OCIImageIndex
	case b.Layers != nil:
		return types.OCIManifestSchema1
	}
	return ""
}

func checkConfig(ctx context.Context, src source, d *v1.Descriptor, want *v1.Platform) error {
	raw, err := fetchSmall(ctx, src, d)
	if err != nil {
		return errors.Wrap(err, "config")
	}
	cf, err := v1.ParseConfigFile(bytes.NewReader(raw))
	if err != nil {
		return errors.Wrap(err, "parse config")
	}
	if cf.OS != want.OS || cf.Architecture != want.Architecture {
		return errors.Wrapf(ErrPlatform, "want %s/%s, the image is %s/%s", want.OS, want.Architecture, cf.OS, cf.Architecture)
	}
	return nil
}

// fetchSmall reads and verifies a manifest or a config.
func fetchSmall(ctx context.Context, src source, d *v1.Descriptor) ([]byte, error) {
	if d.Size > maxManifest {
		return nil, errors.Newf("%s names %d bytes, more than the %d a manifest or config may have", d.Digest, d.Size, maxManifest)
	}
	var buf bytes.Buffer
	err := retry(ctx, src, d.Digest.String(), func() error {
		buf.Reset()
		return fetchVerified(ctx, src, d, &buf)
	})
	return buf.Bytes(), err
}

// stageBlob copies a layer to a new file in dir and verifies it. The file
// is removed again unless it is returned.
func stageBlob(ctx context.Context, src source, d *v1.Descriptor, dir string) (string, error) {
	f, err := os.CreateTemp(dir, "blob-")
	if err != nil {
		return "", errors.Wrap(err, "create staging file")
	}
	err = retry(ctx, src, d.Digest.String(), func() error {
		if err := f.Truncate(0); err != nil {
			return errors.Mark(err, errLocal)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return errors.Mark(err, errLocal)
		}
		return fetchVerified(ctx, src, d, f)
	})
	if cerr := f.Close(); err == nil && cerr != nil {
		err = errors.Mark(cerr, errLocal)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// fetchVerified copies the blob d names to w and checks it against d's
// size and digest. Errors writing to w are marked local.
func fetchVerified(ctx context.Context, src source, d *v1.Descriptor, w io.Writer) error {
	return watchStall(ctx, func(ctx context.Context, stall *time.Timer) error {
		rc, err := src.open(ctx, d)
		if err != nil {
			return err
		}
		defer rc.Close()
		h := sha256.New()
		// One byte past the size is enough to tell a longer blob.
		r := io.LimitReader(stallReader{ctxReader{ctx, rc}, stall}, d.Size+1)
		n, err := io.Copy(io.MultiWriter(h, localWriter{w}), r)
		// ggcr checks a registry blob itself when the body ends and fails
		// that read, saying so only in the message. A body that ended is
		// final, so our own checks decide; a broken one is retried as such.
		if err != nil && n < d.Size && !strings.Contains(err.Error(), "error verifying") {
			return err
		}
		if n != d.Size {
			return errors.Wrapf(ErrMismatch, "%s: got %d bytes, want %d", d.Digest, n, d.Size)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != d.Digest.Hex {
			return errors.Wrapf(ErrMismatch, "%s: got sha256:%s", d.Digest, got)
		}
		return nil
	})
}

// watchStall runs fetch under a context cancelled with errStalled once
// stallTimeout passes without the timer being reset.
func watchStall(ctx context.Context, fetch func(context.Context, *time.Timer) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stall := time.AfterFunc(stallTimeout, func() { cancel(errStalled) })
	defer stall.Stop()
	err := fetch(ctx, stall)
	// Over HTTP/2 the client returns context.Canceled rather than the cause,
	// which would be taken for an interrupted install.
	if errors.Is(err, context.Canceled) && errors.Is(context.Cause(ctx), errStalled) {
		return errors.Wrap(errStalled, err.Error())
	}
	return err
}

// stallReader restarts the stall timer whenever data arrives.
type stallReader struct {
	r     io.Reader
	timer *time.Timer
}

func (s stallReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.timer.Reset(stallTimeout)
	}
	return n, err
}

// ctxReader stops a copy from a local file, which does not watch ctx.
type ctxReader struct {
	ctx context.Context //nolint:containedctx // scoped to one copy
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, context.Cause(c.ctx)
	}
	return c.r.Read(p)
}

type localWriter struct{ w io.Writer }

func (l localWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	if err != nil {
		err = errors.Mark(err, errLocal)
	}
	return n, err
}

// retry runs fetch until it succeeds, fails for good or runs out of
// attempts, waiting retryDelay, then twice as long each time, in between.
func retry(ctx context.Context, src source, what string, fetch func() error) error {
	delay := retryDelay
	for attempt := 1; ; attempt++ {
		err := fetch()
		if cerr := ctx.Err(); err != nil && cerr != nil {
			return errors.Wrapf(cerr, "fetch %s", what)
		}
		if err == nil || attempt == fetchAttempts || errors.Is(err, errLocal) || !src.transient(err) {
			if err != nil && attempt > 1 {
				err = errors.Wrapf(err, "after %d attempts", attempt)
			}
			return err
		}
		log.Printf("fetch %s, attempt %d of %d: %v; retrying in %s", what, attempt, fetchAttempts, err, delay)
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return errors.Wrapf(ctx.Err(), "fetch %s", what)
		case <-t.C:
		}
		delay *= 2
	}
}

// registrySource reads from a registry. The client's own retries are off:
// they cover only the request, not the body, and would multiply with ours.
type registrySource struct {
	ref      name.Reference
	insecure bool
}

func (r registrySource) options(ctx context.Context) []remote.Option {
	var t http.RoundTripper = httpsOnly{registryTransport}
	if r.insecure {
		t = registryTransport
	}
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithTransport(t),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithRetryBackoff(remote.Backoff{Steps: 1}),
		remote.WithRetryStatusCodes(),
	}
}

func (r registrySource) root(ctx context.Context) ([]byte, types.MediaType, v1.Hash, bool, error) {
	var desc *remote.Descriptor
	err := retry(ctx, r, r.ref.String(), func() error {
		return watchStall(ctx, func(ctx context.Context, _ *time.Timer) error {
			var err error
			desc, err = remote.Get(r.ref, r.options(ctx)...)
			return manifestMismatch(err)
		})
	})
	if err != nil {
		return nil, "", v1.Hash{}, false, errors.Wrapf(err, "pull %s", r.ref)
	}
	return desc.Manifest, desc.MediaType, desc.Digest, false, nil
}

func (r registrySource) open(ctx context.Context, d *v1.Descriptor) (io.ReadCloser, error) {
	ref := r.ref.Context().Digest(d.Digest.String())
	if d.MediaType.IsIndex() || d.MediaType.IsImage() {
		desc, err := remote.Get(ref, r.options(ctx)...)
		if err != nil {
			return nil, manifestMismatch(err)
		}
		return io.NopCloser(bytes.NewReader(desc.Manifest)), nil
	}
	l, err := remote.Layer(ref, r.options(ctx)...)
	if err != nil {
		return nil, err
	}
	return l.Compressed()
}

// manifestMismatch marks ggcr's own check of a manifest fetched by digest,
// which it reports only in the message.
func manifestMismatch(err error) error {
	if err != nil && strings.Contains(err.Error(), "does not match requested digest") {
		return errors.Wrap(ErrMismatch, err.Error())
	}
	return err
}

func (registrySource) close() error { return nil }

func (r registrySource) transport() string {
	if r.insecure {
		return "registry, plain http allowed"
	}
	return "registry"
}

// transient is everything but an answer the registry would give again,
// a certificate this machine does not accept, or a redirect to plain http.
func (registrySource) transient(err error) bool {
	if errors.Is(err, ErrInsecureRegistry) {
		return false
	}
	var te *transport.Error
	if errors.As(err, &te) {
		return te.StatusCode == http.StatusRequestTimeout || te.StatusCode == http.StatusTooManyRequests || te.StatusCode >= 500
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var host x509.HostnameError
	return !errors.As(err, &unknown) && !errors.As(err, &invalid) && !errors.As(err, &host)
}

// layoutSource reads an OCI image layout. Nothing in it changes between
// reads, so nothing is retried.
type layoutSource struct {
	file   func(name string) (io.ReadCloser, error)
	closer func() error
	kind   string
}

func (l layoutSource) root(context.Context) ([]byte, types.MediaType, v1.Hash, bool, error) {
	rc, err := l.file("index.json")
	if errors.Is(err, fs.ErrNotExist) {
		if rc, err := l.file("manifest.json"); err == nil {
			rc.Close()
			return nil, "", v1.Hash{}, false, errors.Wrap(ErrLegacyDockerArchive,
				"save it with Docker 25 or later, or convert it with skopeo copy docker-archive:FILE oci-archive:FILE")
		}
		return nil, "", v1.Hash{}, false, errors.New("no index.json at the root of the archive or directory: not an OCI image layout")
	}
	if err != nil {
		return nil, "", v1.Hash{}, false, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, maxManifest+1))
	if err != nil {
		return nil, "", v1.Hash{}, false, errors.Wrap(err, "read index.json")
	}
	if len(raw) > maxManifest {
		return nil, "", v1.Hash{}, false, errors.Newf("index.json is larger than %d bytes", maxManifest)
	}
	return raw, types.OCIImageIndex, v1.Hash{}, true, nil
}

func (l layoutSource) open(_ context.Context, d *v1.Descriptor) (io.ReadCloser, error) {
	rc, err := l.file(path.Join("blobs", d.Digest.Algorithm, d.Digest.Hex))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.Wrap(err, "the layout lacks this blob; it must hold its own blobs, not use a shared blob directory")
	}
	return rc, err
}

func (layoutSource) transient(error) bool { return false }

func (l layoutSource) close() error { return l.closer() }

func (l layoutSource) transport() string { return l.kind }

// indexTar finds where each regular file of a tar archive starts, so that
// blobs are read in place rather than unpacked first.
func indexTar(file string) (open func(name string) (io.ReadCloser, error), closer func() error, err error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	type span struct{ off, size int64 }
	files := map[string]span{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			f.Close()
			return nil, nil, errors.Wrap(err, "read archive")
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// tar.Reader reads headers straight from f, so f is now at the data.
		off, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		files[path.Clean(h.Name)] = span{off, h.Size}
	}
	return func(name string) (io.ReadCloser, error) {
		s, ok := files[name]
		if !ok {
			return nil, errors.Wrapf(fs.ErrNotExist, "%s in the archive", name)
		}
		return io.NopCloser(io.NewSectionReader(f, s.off, s.size)), nil
	}, f.Close, nil
}

// httpsOnly sends nothing over plain http but to a loopback address;
// localhost is a name and may resolve elsewhere. ggcr asks for http on its
// own: for a private address or a .local name whose https ping failed, and
// for a token realm the registry names. Those go over https instead, so the
// https answer decides, and a redirect to http is refused.
type httpsOnly struct{ next http.RoundTripper }

func (h httpsOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return h.next.RoundTrip(req)
	}
	if ip := net.ParseIP(req.URL.Hostname()); ip != nil && ip.IsLoopback() {
		return h.next.RoundTrip(req)
	}
	if req.Response != nil {
		return nil, errors.Wrapf(ErrInsecureRegistry, "redirect to %s; --insecure-registry allows it", req.URL.Redacted())
	}
	req = req.Clone(req.Context())
	req.URL.Scheme = "https"
	resp, err := h.next.RoundTrip(req)
	return resp, errors.Wrap(err, "sent over https")
}
