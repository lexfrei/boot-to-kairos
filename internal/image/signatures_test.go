package image

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const bundleType = "application/vnd.dev.sigstore.bundle.v0.3+json"

func noFault(http.ResponseWriter, []byte) bool { return false }

func TestTheSignatureOfAPulledImageIsLookedUpForTheRootTheRegistryReturned(t *testing.T) {
	img := platformImage(t, runtime.GOARCH, layer(t, entry{name: "a", typ: tar.TypeReg, body: "a"}))
	ref, _ := faultyRegistry(t, img, "/none", noFault)
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        img,
		Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}},
	})
	if err := remote.WriteIndex(r, idx); err != nil {
		t.Fatal(err)
	}
	want, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ref, tag string }{{ref, tag}, {r.Context().Digest(want.String()).String(), ""}} {
		i, err := Open(context.Background(), tc.ref, "linux/"+runtime.GOARCH, false)
		if err != nil {
			t.Fatal(err)
		}
		src, err := i.Signatures(context.Background())
		_ = i.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(src.Digests, []v1.Hash{want}) || src.Tag != tc.tag || src.Repository != r.Context() || src.Options == nil || src.Bundles != nil {
			t.Fatalf("%s: got %+v, want index %s and tag %q", tc.ref, src, want, tc.tag)
		}
	}
}

// writeBlob writes b into the layout and returns its descriptor.
func writeBlob(t *testing.T, p layout.Path, b []byte, mt types.MediaType) v1.Descriptor {
	t.Helper()
	h, size, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.WriteBlob(h, io.NopCloser(bytes.NewReader(b))); err != nil {
		t.Fatal(err)
	}
	return v1.Descriptor{MediaType: mt, Size: size, Digest: h}
}

// attach adds a referrer of subject to the layout, listed in index.json as
// oras copy --to-oci-layout lists one, with a single layer holding body.
func attach(t *testing.T, p layout.Path, subject v1.Descriptor, artifactType string, layerType types.MediaType, body []byte) {
	t.Helper()
	cfg := writeBlob(t, p, []byte("{}"), "application/vnd.oci.empty.v1+json")
	l := writeBlob(t, p, body, layerType)
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     types.OCIManifestSchema1,
		"artifactType":  artifactType,
		"config":        cfg,
		"layers":        []v1.Descriptor{l},
		"subject":       subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	d := writeBlob(t, p, raw, types.OCIManifestSchema1)
	d.ArtifactType = artifactType
	if err := p.AppendDescriptor(d); err != nil {
		t.Fatal(err)
	}
}

// orasLayout writes an index for this architecture, its manifest listed on
// its own too, and a sigstore bundle attached to the index, plus one
// attached to a digest the layout does not hold.
func orasLayout(t *testing.T) (dir string, index v1.Hash, bundle []byte) {
	t.Helper()
	img := platformImage(t, runtime.GOARCH, layer(t, entry{name: "a", typ: tar.TypeReg, body: "a"}))
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        img,
		Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}},
	})
	dir = t.TempDir()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AppendIndex(idx); err != nil {
		t.Fatal(err)
	}
	if err := p.AppendImage(img); err != nil {
		t.Fatal(err)
	}
	idxDesc, err := partialDescriptor(idx)
	if err != nil {
		t.Fatal(err)
	}
	bundle = []byte(`{"mediaType":"` + bundleType + `"}`)
	attach(t, p, idxDesc, bundleType, bundleType, bundle)
	other := v1.Descriptor{MediaType: types.OCIImageIndex, Size: 2, Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)}}
	attach(t, p, other, bundleType, bundleType, []byte(`{"other":true}`))
	attach(t, p, idxDesc, "application/spdx+json", "application/spdx+json", []byte(`{"sbom":true}`))
	return dir, idxDesc.Digest, bundle
}

func partialDescriptor(idx v1.ImageIndex) (v1.Descriptor, error) {
	h, err := idx.Digest()
	if err != nil {
		return v1.Descriptor{}, err
	}
	size, err := idx.Size()
	if err != nil {
		return v1.Descriptor{}, err
	}
	return v1.Descriptor{MediaType: types.OCIImageIndex, Size: size, Digest: h}, nil
}

func TestALayoutCarriesTheBundlesAttachedToTheImage(t *testing.T) {
	dir, index, bundle := orasLayout(t)
	for _, ref := range []string{"oci:" + dir, "oci-archive:" + tarDir(t, dir, "")} {
		i, err := Open(context.Background(), ref, "linux/"+runtime.GOARCH, false)
		if err != nil {
			t.Fatal(err)
		}
		src, err := i.Signatures(context.Background())
		_ = i.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(src.Digests, index) || !slices.Contains(src.Digests, i.Digest) || len(src.Digests) != 2 {
			t.Fatalf("%s: digests %v, want the index %s and the manifest %s", ref, src.Digests, index, i.Digest)
		}
		if len(src.Bundles) != 1 || len(src.Bundles[index]) != 1 || !bytes.Equal(src.Bundles[index][0], bundle) {
			t.Fatalf("%s: bundles %q", ref, src.Bundles)
		}
		if src.Tag != "" || src.Options != nil {
			t.Fatalf("%s: got %+v", ref, src)
		}
	}
}

func TestALayoutWithoutReferrersCarriesNoBundle(t *testing.T) {
	img, dir := twoLayers(t)
	i, err := Open(context.Background(), "oci:"+dir, "linux/"+runtime.GOARCH, false)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	src, err := i.Signatures(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(src.Digests, []v1.Hash{h}) || len(src.Bundles) != 0 {
		t.Fatalf("got %+v", src)
	}
}

func TestATamperedBundleInALayoutIsRefused(t *testing.T) {
	dir, _, bundle := orasLayout(t)
	h, _, err := v1.SHA256(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	flipByte(t, blobPath(dir, h))
	i, err := Open(context.Background(), "oci:"+dir, "linux/"+runtime.GOARCH, false)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	if _, err := i.Signatures(context.Background()); !errors.Is(err, ErrMismatch) {
		t.Fatalf("got %v, want ErrMismatch", err)
	}
}

func TestRetryStopsAtAFinalError(t *testing.T) {
	saved := retryDelay
	t.Cleanup(func() { retryDelay = saved })
	retryDelay = 0
	final := errFinal
	i := &Image{src: registrySource{}}
	n := 0
	err := i.Retry(context.Background(), "x", func(context.Context) error { n++; return errTransient }, final)
	if err == nil || n != fetchAttempts {
		t.Fatalf("transient: %d attempts, %v", n, err)
	}
	n = 0
	err = i.Retry(context.Background(), "x", func(context.Context) error { n++; return wrapped{final} }, final)
	if !errors.Is(err, final) || n != 1 {
		t.Fatalf("final: %d attempts, %v", n, err)
	}
}

var (
	errFinal     = errors.New("final")
	errTransient = errors.New("transient")
)

type wrapped struct{ error }

func (w wrapped) Unwrap() error { return w.error }

func TestRetryDropsAnAttemptThatStalls(t *testing.T) {
	saved, savedStall := retryDelay, stallTimeout
	t.Cleanup(func() { retryDelay, stallTimeout = saved, savedStall })
	retryDelay, stallTimeout = 0, 50*time.Millisecond
	i := &Image{src: registrySource{}}
	n := 0
	err := i.Retry(context.Background(), "x", func(ctx context.Context) error {
		n++
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, errStalled) || n != fetchAttempts {
		t.Fatalf("%d attempts, %v; want each dropped as stalled", n, err)
	}
}

// pick never reads an entry for another platform, so neither may the
// lookup of signatures: a layout copied for one machine may lack it.
func TestALayoutEntryForAnotherPlatformIsNotRead(t *testing.T) {
	dir, index, _ := orasLayout(t)
	p, err := layout.FromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	missing := v1.Descriptor{
		MediaType: types.OCIManifestSchema1, Size: 100,
		Digest:   v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("e", 64)},
		Platform: &v1.Platform{OS: "linux", Architecture: "s390x"},
	}
	if err := p.AppendDescriptor(missing); err != nil {
		t.Fatal(err)
	}
	i, err := Open(context.Background(), "oci:"+dir, "linux/"+runtime.GOARCH, false)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	src, err := i.Signatures(context.Background())
	if err != nil || len(src.Bundles[index]) != 1 {
		t.Fatalf("got %+v, %v", src, err)
	}
}
