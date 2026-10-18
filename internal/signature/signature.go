// Package signature verifies the cosign signature of an image before any of
// it is installed.
package signature

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/lexfrei/boot-to-kairos/internal/image"
)

var (
	// ErrNoSignature is an image with no signature for its digest.
	ErrNoSignature = errors.New("the image is not signed")
	// ErrBadSignature is a signature that does not verify, or not one by
	// the signer the policy names.
	ErrBadSignature = errors.New("the image signature is not accepted")
)

const (
	// GitHubIssuer is the OIDC issuer of GitHub Actions.
	GitHubIssuer = "https://token.actions.githubusercontent.com"
	// Kairos signs its releases from a reusable workflow, which moved from
	// kairos-factory-action into the kairos repository with v4.3.0.
	kairosIdentity   = `^https://github\.com/kairos-io/(kairos|kairos-factory-action)/\.github/workflows/`
	kairosRepository = "https://github.com/kairos-io/kairos"
	releaseRef       = "refs/tags/"
	// signPredicate is what cosign sign attests. Other statements on the
	// same digest, an SBOM say, do not make it a signed image.
	signPredicate = "https://sigstore.dev/cosign/sign/v1"
)

// Policy names the signer whose signature is accepted. The zero Policy is
// Kairos's release pipeline.
type Policy struct {
	// Identity is a regular expression the subject alternative name of the
	// signing certificate must match.
	Identity string
	// Issuer is the OIDC issuer the signing certificate must name.
	Issuer string
}

func (p Policy) kairos() bool { return p == Policy{} }

// Result is the signature that was accepted.
type Result struct {
	// Digest is the digest it signs.
	Digest   v1.Hash
	Identity string
	Issuer   string
	// SourceRef is the git ref the signing workflow ran for, if it names one.
	SourceRef string
	LogIndex  int64
}

func (r Result) String() string {
	s := fmt.Sprintf("%s signed by %s, issuer %s", r.Digest, r.Identity, r.Issuer)
	if r.SourceRef != "" {
		s += ", from " + r.SourceRef
	}
	return fmt.Sprintf("%s, Rekor log index %d", s, r.LogIndex)
}

// Trusted reads a Sigstore trusted root from path or, if path is empty,
// fetches the current one from Sigstore's TUF repository over https,
// keeping nothing on disk.
func Trusted(ctx context.Context, path string) (root.TrustedMaterial, error) {
	if path != "" {
		tr, err := root.NewTrustedRootFromPath(path)
		return tr, errors.Wrapf(err, "read trusted root %s", path)
	}
	opts := tuf.DefaultOptions().WithDisableLocalCache().WithRepositoryBaseURL(tufRepository).WithFetcher(ctxFetcher{ctx})
	tr, err := root.FetchTrustedRootWithOptions(opts)
	return tr, errors.Wrap(err, "fetch the Sigstore trusted root; --trusted-root verifies without it")
}

// tufTimeout bounds the download of one TUF metadata file.
var tufTimeout = time.Minute //nolint:gochecknoglobals // test seam

// ctxFetcher downloads TUF metadata under ctx. The TUF client's own
// fetcher ignores any context and waits on a stalled server for good.
type ctxFetcher struct {
	ctx context.Context //nolint:containedctx // the TUF fetcher interface takes none
}

func (f ctxFetcher) DownloadFile(url string, maxLength int64, _ time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(f.ctx, tufTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// The TUF client reads a 404 for the next root as there being none.
	if res.StatusCode != http.StatusOK {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: url}
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxLength+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("%s is larger than %d bytes", url, maxLength)}
	}
	return b, nil
}

// Verify accepts the image if a signature for one of src's digests
// verifies against tm and is by p's signer. With the zero Policy that is
// Kairos's release pipeline: a GitHub Actions workflow of Kairos run for a
// release tag of kairos-io/kairos, and when src names a tag, that tag must
// name the release, as in v0.5.1-core-amd64-generic-v4.3.0 for v4.3.0, so
// that an older release cannot be passed off under a newer tag. Nothing is
// looked up in Rekor online: the signature carries its log entry.
func Verify(ctx context.Context, src image.SignatureSource, p Policy, tm root.TrustedMaterial) (Result, error) {
	var bad, other, none error
	for _, d := range src.Digests {
		res, err := verifyDigest(ctx, src, d, p, tm)
		switch {
		case err == nil:
			return res, nil
		case errors.Is(err, image.ErrInvalidJSON):
			return Result{}, err
		case errors.Is(err, ErrBadSignature):
			bad = errors.CombineErrors(bad, err)
		case errors.Is(err, ErrNoSignature):
			none = errors.CombineErrors(none, err)
		default:
			other = errors.CombineErrors(other, err)
		}
	}
	switch {
	case bad != nil:
		return Result{}, bad
	case other != nil:
		return Result{}, other
	case none != nil:
		return Result{}, none
	}
	return Result{}, ErrNoSignature
}

var verifyBundle = cosign.VerifyNewBundle //nolint:gochecknoglobals // test seam

var tufRepository = tuf.DefaultMirror //nolint:gochecknoglobals // test seam

func checkOpts(p Policy, tm root.TrustedMaterial) *cosign.CheckOpts {
	id := cosign.Identity{Issuer: p.Issuer, SubjectRegExp: p.Identity}
	if p.kairos() {
		id = cosign.Identity{Issuer: GitHubIssuer, SubjectRegExp: kairosIdentity}
	}
	return &cosign.CheckOpts{
		TrustedMaterial: tm,
		Identities:      []cosign.Identity{id},
		ClaimVerifier:   cosign.SimpleClaimVerifier,
	}
}

func verifyDigest(ctx context.Context, src image.SignatureSource, d v1.Hash, p Policy, tm root.TrustedMaterial) (Result, error) {
	co := checkOpts(p, tm)
	if src.Repository == (name.Repository{}) {
		res, err := verifyBundles(ctx, co, d, src.Bundles[d], src.Tag, p)
		if errors.Is(err, errNoBundle) {
			return Result{}, errors.Wrapf(ErrNoSignature, "the layout holds no sigstore bundle signing %s", d)
		}
		return res, err
	}
	ref := src.Repository.Digest(d.String())
	bundles, err := registryBundles(ref, src.Options)
	if err != nil {
		return Result{}, errors.Wrapf(err, "fetch the signature bundles of %s", ref)
	}
	if res, err := verifyBundles(ctx, co, d, bundles, src.Tag, p); !errors.Is(err, errNoBundle) {
		return res, err
	}
	co.RegistryClientOpts = []ociremote.Option{ociremote.WithRemoteOptions(src.Options...)}
	sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, co)
	if e := (*cosign.ErrNoSignaturesFound)(nil); errors.As(err, &e) {
		return Result{}, errors.Wrapf(ErrNoSignature, "%s has neither a sigstore bundle nor a cosign signature", ref)
	}
	if e := (*cosign.ErrNoMatchingSignatures)(nil); errors.As(err, &e) {
		return Result{}, errors.Wrapf(ErrBadSignature, "%s: %v", d, err)
	}
	if err != nil {
		return Result{}, errors.Wrapf(err, "fetch the signature of %s", ref)
	}
	var reasons []string
	for _, sig := range sigs {
		cert, err := sig.Cert()
		if err != nil || cert == nil {
			reasons = append(reasons, fmt.Sprintf("no certificate: %v", err))
			continue
		}
		s, err := certificate.SummarizeCertificate(cert)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		if err := checkSigner(&s, src.Tag, p); err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		res := result(d, &s)
		if b, err := sig.Bundle(); err == nil && b != nil {
			res.LogIndex = b.Payload.LogIndex
		}
		return res, nil
	}
	return Result{}, errors.Wrapf(ErrBadSignature, "%s: %s", d, strings.Join(reasons, "; "))
}

// maxBundle caps the size of a sigstore bundle, read into memory; real
// ones are about 10 KiB.
const maxBundle = 4 << 20

// registryBundles fetches the sigstore bundles attached to ref as
// referrers. Unlike cosign's own lookup it reaches each bundle by ref's
// repository, plain http allowed or not, and fails on a bundle it cannot
// fetch rather than skipping it, skipping only a referrer the registry no
// longer has.
func registryBundles(ref name.Digest, opts []remote.Option) ([][]byte, error) {
	idx, err := remote.Referrers(ref, opts...)
	if err != nil {
		return nil, err
	}
	raw, err := idx.RawManifest()
	if err != nil {
		return nil, err
	}
	if err := image.StrictJSON(raw); err != nil {
		return nil, errors.Wrap(err, "referrers")
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var bundles [][]byte
	for n := range im.Manifests {
		d := &im.Manifests[n]
		if !d.MediaType.IsImage() {
			continue
		}
		desc, err := remote.Get(ref.Context().Digest(d.Digest.String()), opts...)
		// A registry may list a referrer it has since deleted.
		if te := (*transport.Error)(nil); errors.As(err, &te) && te.StatusCode == http.StatusNotFound {
			continue
		}
		if err == nil {
			err = image.StrictJSON(desc.Manifest)
		}
		// Image would resolve an index to a child of its own choosing. A
		// mismatch is retried as the image's own are: a mirror may serve
		// something else next time.
		if err == nil && desc.MediaType.IsIndex() {
			err = errors.Wrapf(image.ErrMismatch, "listed as an image manifest, served as %s", desc.MediaType)
		}
		if err != nil {
			return nil, errors.Wrapf(err, "referrer %s", d.Digest)
		}
		img, err := desc.Image()
		if err != nil {
			return nil, errors.Wrapf(err, "referrer %s", d.Digest)
		}
		m, err := img.Manifest()
		if err != nil {
			return nil, errors.Wrapf(err, "referrer %s", d.Digest)
		}
		for k := range m.Layers {
			l := &m.Layers[k]
			if !strings.HasPrefix(string(l.MediaType), image.SigstoreBundle) {
				continue
			}
			b, err := readBlob(img, l.Digest)
			if err != nil {
				return nil, errors.Wrapf(err, "bundle %s", l.Digest)
			}
			bundles = append(bundles, b)
		}
	}
	return bundles, nil
}

// readBlob reads a layer of img, which go-containerregistry checks against
// its digest once it is read to the end.
func readBlob(img v1.Image, h v1.Hash) ([]byte, error) {
	l, err := img.LayerByDigest(h)
	if err != nil {
		return nil, err
	}
	rc, err := l.Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxBundle+1))
	if err == nil && len(b) > maxBundle {
		err = errors.Newf("larger than %d bytes", maxBundle)
	}
	return b, err
}

// errNoBundle is a digest that no sigstore bundle signs: none at all, or
// only attestations of something else about it.
var errNoBundle = errors.New("no sigstore bundle signs the image")

// errNotASignature is a bundle that verifies as a statement other than a
// cosign signature.
var errNotASignature = errors.New("not a cosign signature")

func verifyBundles(ctx context.Context, co *cosign.CheckOpts, d v1.Hash, raws [][]byte, tag string, p Policy) (Result, error) {
	digest, err := hex.DecodeString(d.Hex)
	if err != nil {
		return Result{}, errors.Wrapf(err, "digest %s", d)
	}
	var reasons []string
	signatures := 0
	for _, raw := range raws {
		err := image.StrictJSON(raw)
		if err == nil {
			err = strictLogEntries(raw)
		}
		if err != nil {
			return Result{}, errors.Wrapf(err, "bundle for %s", d)
		}
		b := new(sgbundle.Bundle)
		if err := b.UnmarshalJSON(raw); err != nil {
			signatures++
			reasons = append(reasons, fmt.Sprintf("parse bundle: %v", err))
			continue
		}
		if err := strictStatement(b); err != nil {
			return Result{}, errors.Wrapf(err, "bundle for %s", d)
		}
		if claimsOther(b) {
			reasons = append(reasons, "an attestation of something else")
			continue
		}
		vr, err := verifyBundle(ctx, co, verify.WithArtifactDigest(d.Algorithm, digest), b)
		if err == nil {
			err = accept(vr, tag, p)
		}
		if !errors.Is(err, errNotASignature) {
			signatures++
		}
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		res := result(d, vr.Signature.Certificate)
		if entries, err := b.TlogEntries(); err == nil && len(entries) > 0 {
			res.LogIndex = entries[0].LogIndex()
		}
		return res, nil
	}
	if signatures == 0 {
		return Result{}, errNoBundle
	}
	return Result{}, errors.Wrapf(ErrBadSignature, "%s: %s", d, strings.Join(reasons, "; "))
}

// strictLogEntries checks the Rekor entry bodies in a bundle, base64 JSON
// that sigstore-go already parses while it reads the bundle. A bundle that
// protojson cannot read is left to sigstore-go.
func strictLogEntries(raw []byte) error {
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		return nil //nolint:nilerr // refused by the bundle parser too
	}
	for _, e := range pb.GetVerificationMaterial().GetTlogEntries() {
		if err := image.StrictJSON(e.GetCanonicalizedBody()); err != nil {
			return errors.Wrap(err, "log entry")
		}
	}
	return nil
}

// strictStatement checks the statement in a bundle's DSSE envelope, which
// is JSON too. A bundle that carries none, or whose payload is not base64,
// is left to the verification.
func strictStatement(b *sgbundle.Bundle) error {
	env, err := b.Envelope()
	if err != nil {
		return nil //nolint:nilerr // not a DSSE bundle
	}
	payload, err := env.DecodeB64Payload()
	if err != nil {
		return nil //nolint:nilerr // refused by the verification
	}
	return errors.Wrap(image.StrictJSON(payload), "statement")
}

// claimsOther says whether a bundle's statement, not yet verified, is one
// other than a cosign signature, an SBOM say, by whichever signer. That
// only steers the lookup to the legacy signature; it accepts nothing.
func claimsOther(b *sgbundle.Bundle) bool {
	env, err := b.Envelope()
	if err != nil {
		return false
	}
	st, err := env.Statement()
	return err == nil && st.GetPredicateType() != signPredicate
}

// accept applies to a verified bundle what cosign does not check itself.
func accept(vr *verify.VerificationResult, tag string, p Policy) error {
	if err := checkPredicate(vr.Statement.GetPredicateType()); err != nil {
		return err
	}
	if vr.Signature == nil || vr.Signature.Certificate == nil {
		return errors.New("signed with a key, not a certificate")
	}
	return checkSigner(vr.Signature.Certificate, tag, p)
}

func result(d v1.Hash, s *certificate.Summary) Result {
	return Result{Digest: d, Identity: s.SubjectAlternativeName, Issuer: s.Issuer, SourceRef: s.SourceRepositoryRef}
}

// checkSigner applies what the policy asks beyond the certificate identity
// cosign has matched.
func checkSigner(s *certificate.Summary, tag string, p Policy) error {
	if !p.kairos() {
		return nil
	}
	return checkRelease(s, tag)
}

// checkRelease accepts a certificate of a Kairos release workflow whose
// release the tag names: as its last part, or followed by a flavor suffix.
func checkRelease(s *certificate.Summary, tag string) error {
	if s.SourceRepositoryURI != kairosRepository {
		return errors.Newf("signed from %q, not %s", s.SourceRepositoryURI, kairosRepository)
	}
	release, ok := strings.CutPrefix(s.SourceRepositoryRef, releaseRef)
	if !ok || !strings.HasPrefix(release, "v") {
		return errors.Newf("signed for %q, not a release tag", s.SourceRepositoryRef)
	}
	if tag == "" || strings.HasSuffix(tag, "-"+release) || strings.Contains(tag, "-"+release+"-") {
		return nil
	}
	return errors.Newf("the tag %s does not name release %s, which the signature is for; pin the image by digest to accept it", tag, release)
}

func checkPredicate(t string) error {
	if t != signPredicate {
		return errors.Wrapf(errNotASignature, "the statement is a %q", t)
	}
	return nil
}
