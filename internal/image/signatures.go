package image

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// SigstoreBundle prefixes the media type of a sigstore bundle, whatever its
// version.
const SigstoreBundle = "application/vnd.dev.sigstore.bundle"

// SignatureSource says where the signatures of an image are.
type SignatureSource struct {
	// Digests are those a signature for the image may name: the one the
	// registry returned for the reference, or each entry of a layout's
	// index.json that resolves to the picked manifest.
	Digests []v1.Hash
	// Tag is the tag the reference names, empty for a digest reference and
	// a layout.
	Tag string
	// Repository and Options reach the registry; Repository is zero for a
	// layout. Options carry the transport the image was fetched with.
	Repository name.Repository
	Options    []remote.Option
	// Bundles are the sigstore bundles a layout holds for Digests, by the
	// digest their referrer names as its subject.
	Bundles map[v1.Hash][][]byte
}

// Signatures says where to look up the image's signatures. A layout's are
// read from it now: the sigstore bundle layers of the manifests listed in
// its index.json whose subject is the image, as oras copy writes them,
// verified against their digests like the image.
func (i *Image) Signatures(ctx context.Context) (SignatureSource, error) {
	return i.src.signatures(ctx, i.signed)
}

// Retry runs fetch, requests to where the image comes from, retrying it as
// the image's own fetches are, except for an error that is one of final.
// An attempt that has not finished within the stall timeout is dropped as
// stalled; fetch must give up when its ctx is cancelled.
func (i *Image) Retry(ctx context.Context, what string, fetch func(ctx context.Context) error, final ...error) error {
	return retry(ctx, finalErrors{i.src, final}, what, func() error {
		return watchStall(ctx, func(ctx context.Context, _ *time.Timer) error { return fetch(ctx) })
	})
}

type finalErrors struct {
	source

	final []error
}

func (f finalErrors) transient(err error) bool {
	return !errors.IsAny(err, f.final...) && f.source.transient(err)
}

func (r registrySource) signatures(ctx context.Context, signed []v1.Hash) (SignatureSource, error) {
	var tag string
	if t, ok := r.ref.(name.Tag); ok {
		tag = t.TagStr()
	}
	return SignatureSource{Digests: signed, Tag: tag, Repository: r.ref.Context(), Options: r.options(ctx)}, nil
}

func (l layoutSource) signatures(ctx context.Context, signed []v1.Hash) (SignatureSource, error) {
	src := SignatureSource{Digests: signed}
	raw, _, _, _, err := l.root(ctx) //nolint:dogsled // a layout's root is index.json and nothing else
	if err != nil {
		return src, err
	}
	idx, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return src, errors.Wrap(err, "parse index.json")
	}
	for n := range idx.Manifests {
		d := &idx.Manifests[n]
		// Referrers carry no platform; pick reads no entry that does.
		if !d.MediaType.IsImage() || d.Platform != nil {
			continue
		}
		raw, err := fetchSmall(ctx, l, d)
		if err != nil {
			return src, errors.Wrapf(err, "signature %s", d.Digest)
		}
		m, err := v1.ParseManifest(bytes.NewReader(raw))
		if err != nil {
			return src, errors.Wrapf(err, "parse signature %s", d.Digest)
		}
		if m.Subject == nil || !slices.Contains(signed, m.Subject.Digest) {
			continue
		}
		for k := range m.Layers {
			ld := &m.Layers[k]
			if !strings.HasPrefix(string(ld.MediaType), SigstoreBundle) {
				continue
			}
			b, err := fetchSmall(ctx, l, ld)
			if err != nil {
				return src, errors.Wrapf(err, "signature %s", d.Digest)
			}
			if src.Bundles == nil {
				src.Bundles = map[v1.Hash][][]byte{}
			}
			src.Bundles[m.Subject.Digest] = append(src.Bundles[m.Subject.Digest], b)
		}
	}
	return src, nil
}
