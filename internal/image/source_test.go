package image

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sys/unix"
)

// platformImage builds an image whose config says linux/arch.
func platformImage(t *testing.T, arch string, layers ...[]byte) v1.Image {
	t.Helper()
	img := empty.Image
	for _, l := range layers {
		b := l
		ly, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
		if err != nil {
			t.Fatal(err)
		}
		if img, err = mutate.AppendLayers(img, ly); err != nil {
			t.Fatal(err)
		}
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", arch
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	return img
}

// writeLayout writes images into an OCI image layout at dir, each listed in
// index.json without a platform, as skopeo writes a single image.
func writeLayout(t *testing.T, dir string, imgs ...v1.Image) layout.Path {
	t.Helper()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range imgs {
		if err := p.AppendImage(img); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// multiArch writes one index that carries an image per architecture.
func multiArch(t *testing.T, dir string, imgs map[string]v1.Image) {
	t.Helper()
	idx := v1.ImageIndex(empty.Index)
	for arch, img := range imgs {
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AppendIndex(idx); err != nil {
		t.Fatal(err)
	}
}

// tarDir packs dir into a tar file, every name with prefix in front.
func tarDir(t *testing.T, dir, prefix string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = prefix + filepath.ToSlash(rel)
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

func blobPath(dir string, h v1.Hash) string {
	return filepath.Join(dir, "blobs", h.Algorithm, h.Hex)
}

// flipByte changes one byte in the middle of a blob, keeping its size.
func flipByte(t *testing.T, p string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func layerDigests(t *testing.T, img v1.Image) []v1.Hash {
	t.Helper()
	ls, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	var hs []v1.Hash
	for _, l := range ls {
		h, err := l.Digest()
		if err != nil {
			t.Fatal(err)
		}
		hs = append(hs, h)
	}
	return hs
}

func twoLayers(t *testing.T) (v1.Image, string) {
	t.Helper()
	img := platformImage(t, runtime.GOARCH,
		layer(t, entry{name: "etc/os-release", typ: tar.TypeReg, body: "ID=kairos\n"}),
		layer(t, entry{name: "usr/bin/kairos-agent", typ: tar.TypeReg, body: "agent", mode: 0o755}),
	)
	dir := t.TempDir()
	writeLayout(t, dir, img)
	return img, dir
}

func assertInstalled(t *testing.T, dest string) {
	t.Helper()
	for p, want := range map[string]string{"etc/os-release": "ID=kairos\n", "usr/bin/kairos-agent": "agent"} {
		if b, err := os.ReadFile(filepath.Join(dest, p)); err != nil || string(b) != want {
			t.Fatalf("%s = %q, %v; want %q", p, b, err, want)
		}
	}
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s holds %v, want nothing applied", dir, entries)
	}
}

func TestOpenReadsALayoutDirectoryAndArchive(t *testing.T) {
	img, dir := twoLayers(t)
	want, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// skopeo writes bare names, other tools ./-prefixed ones.
	for _, tc := range []struct{ ref, transport string }{
		{"oci:" + dir, "OCI image layout"},
		{"oci-archive:" + tarDir(t, dir, ""), "OCI image archive"},
		{"oci-archive:" + tarDir(t, dir, "./"), "OCI image archive"},
	} {
		t.Run(tc.ref[:strings.Index(tc.ref, ":")], func(t *testing.T) {
			got, err := Open(t.Context(), tc.ref, "linux/"+runtime.GOARCH, false)
			if err != nil {
				t.Fatal(err)
			}
			if got.Digest != want || len(got.Layers) != 2 || got.Transport() != tc.transport {
				t.Fatalf("digest %s, %d layers, %q; want %s, 2, %q", got.Digest, len(got.Layers), got.Transport(), want, tc.transport)
			}
			dest, stage := t.TempDir(), t.TempDir()
			if err := got.Extract(t.Context(), dest, stage, func(int64) error { return nil }); err != nil {
				t.Fatal(err)
			}
			assertInstalled(t, dest)
			assertEmpty(t, stage)
		})
	}
}

func TestATamperedLayerIsRefusedBeforeItIsApplied(t *testing.T) {
	img, dir := twoLayers(t)
	flipByte(t, blobPath(dir, layerDigests(t, img)[0]))
	var logged bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&logged)
	for _, ref := range []string{"oci:" + dir, "oci-archive:" + tarDir(t, dir, "")} {
		got, err := Open(t.Context(), ref, "linux/"+runtime.GOARCH, false)
		if err != nil {
			t.Fatal(err)
		}
		dest, stage := t.TempDir(), t.TempDir()
		err = got.Extract(t.Context(), dest, stage, func(int64) error { return nil })
		if !errors.Is(err, ErrMismatch) {
			t.Fatalf("%s: err = %v, want ErrMismatch", ref, err)
		}
		assertEmpty(t, dest)
		assertEmpty(t, stage)
	}
	if strings.Contains(logged.String(), "retrying") {
		t.Fatalf("a local image was fetched again, as if it could change: %s", logged.String())
	}
}

func TestATruncatedLayerIsRefused(t *testing.T) {
	img, dir := twoLayers(t)
	p := blobPath(dir, layerDigests(t, img)[1])
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b[:len(b)-1], 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := extract(t, got, t.TempDir()); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch for a blob shorter than its descriptor", err)
	}
}

func TestATamperedManifestOrConfigIsRefused(t *testing.T) {
	for _, which := range []string{"manifest", "config"} {
		t.Run(which, func(t *testing.T) {
			img, dir := twoLayers(t)
			h, err := img.Digest()
			if which == "config" {
				h, err = img.ConfigName()
			}
			if err != nil {
				t.Fatal(err)
			}
			flipByte(t, blobPath(dir, h))
			if _, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false); !errors.Is(err, ErrMismatch) {
				t.Fatalf("err = %v, want ErrMismatch", err)
			}
		})
	}
}

func TestOpenPicksTheRequestedArchitecture(t *testing.T) {
	dir := t.TempDir()
	multiArch(t, dir, map[string]v1.Image{
		"amd64": platformImage(t, "amd64", layer(t, entry{name: "arch", typ: tar.TypeReg, body: "amd64"})),
		"arm64": platformImage(t, "arm64", layer(t, entry{name: "arch", typ: tar.TypeReg, body: "arm64"})),
	})
	for _, ref := range []string{"oci:" + dir, "oci-archive:" + tarDir(t, dir, "")} {
		for _, arch := range []string{"amd64", "arm64"} {
			img, err := Open(t.Context(), ref, "linux/"+arch, false)
			if err != nil {
				t.Fatal(err)
			}
			dest := t.TempDir()
			if err := extract(t, img, dest); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(filepath.Join(dest, "arch")); string(b) != arch {
				t.Fatalf("%s for linux/%s unpacked the %q image", ref, arch, b)
			}
		}
	}
}

func TestOpenRefusesAnImageForAnotherArchitecture(t *testing.T) {
	dir := t.TempDir()
	multiArch(t, dir, map[string]v1.Image{"s390x": platformImage(t, "s390x")})
	if _, err := Open(t.Context(), "oci:"+dir, "linux/amd64", false); !errors.Is(err, ErrPlatform) {
		t.Fatalf("index without the platform: err = %v, want ErrPlatform", err)
	}
	// A single manifest names its platform only in the config.
	dir = t.TempDir()
	writeLayout(t, dir, platformImage(t, "arm64"))
	if _, err := Open(t.Context(), "oci:"+dir, "linux/amd64", false); !errors.Is(err, ErrPlatform) {
		t.Fatalf("single arm64 manifest: err = %v, want ErrPlatform", err)
	}
}

func TestOpenRefusesAnImageForAnotherOS(t *testing.T) {
	img := platformImage(t, runtime.GOARCH)
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS = "windows"
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeLayout(t, dir, img)
	if _, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false); !errors.Is(err, ErrPlatform) {
		t.Fatalf("err = %v, want ErrPlatform", err)
	}
}

func TestOpenBoundsNestedIndexes(t *testing.T) {
	for _, tc := range []struct {
		depth int
		ok    bool
	}{{maxDepth - 1, true}, {maxDepth, false}} {
		idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: platformImage(t, runtime.GOARCH)})
		for range tc.depth - 1 {
			idx = mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: idx})
		}
		dir := t.TempDir()
		p, err := layout.Write(dir, empty.Index)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.AppendIndex(idx); err != nil {
			t.Fatal(err)
		}
		_, err = Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false)
		if (err == nil) != tc.ok {
			t.Fatalf("%d nested indexes: err = %v", tc.depth, err)
		}
	}
}

// fakeSource serves body for every descriptor, or bodies in turn, and
// counts the opens.
type fakeSource struct {
	body    []byte
	bodies  [][]byte
	opens   int
	retries bool
}

func (*fakeSource) root(context.Context) ([]byte, types.MediaType, v1.Hash, bool, error) {
	return nil, "", v1.Hash{}, false, errors.ErrUnsupported
}

func (f *fakeSource) open(context.Context, *v1.Descriptor) (io.ReadCloser, error) {
	f.opens++
	if len(f.bodies) > 0 {
		b := f.bodies[0]
		f.bodies = f.bodies[1:]
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	return io.NopCloser(bytes.NewReader(f.body)), nil
}

func (f *fakeSource) transient(error) bool { return f.retries }

func (*fakeSource) close() error { return nil }

func (*fakeSource) transport() string { return "fake" }

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, unix.ENOSPC }

func TestALocalWriteErrorIsNotRetried(t *testing.T) {
	src := &fakeSource{body: []byte("blob"), retries: true}
	h, n, err := v1.SHA256(bytes.NewReader(src.body))
	if err != nil {
		t.Fatal(err)
	}
	d := v1.Descriptor{Digest: h, Size: n}
	err = retry(t.Context(), src, "blob", func() error { return fetchVerified(t.Context(), src, &d, failWriter{}) })
	if !errors.Is(err, unix.ENOSPC) || src.opens != 1 {
		t.Fatalf("err = %v after %d opens, want ENOSPC after one: a full tmpfs stays full", err, src.opens)
	}
}

type countingWriter struct{ n int }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += len(p)
	return len(p), nil
}

func TestABlobIsReadNoFurtherThanItsSize(t *testing.T) {
	src := &fakeSource{body: bytes.Repeat([]byte("x"), 1<<20)}
	h, _, err := v1.SHA256(bytes.NewReader(src.body[:10]))
	if err != nil {
		t.Fatal(err)
	}
	var w countingWriter
	err = fetchVerified(t.Context(), src, &v1.Descriptor{Digest: h, Size: 10}, &w)
	if !errors.Is(err, ErrMismatch) || w.n > 11 {
		t.Fatalf("err = %v after %d bytes, want ErrMismatch after at most 11: a stream that does not end must not fill the tmpfs", err, w.n)
	}
}

func TestAnOversizedManifestIsNotRead(t *testing.T) {
	src := &fakeSource{}
	d := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)}, Size: maxManifest + 1}
	if _, err := fetchSmall(t.Context(), src, &d); err == nil || errors.Is(err, ErrMismatch) || src.opens != 0 {
		t.Fatalf("err = %v after %d opens, want a refusal before reading %d bytes into memory", err, src.opens, d.Size)
	}
}

func TestOpenRefusesALayoutHoldingSeveralImages(t *testing.T) {
	dir := t.TempDir()
	writeLayout(t, dir, platformImage(t, runtime.GOARCH), platformImage(t, runtime.GOARCH, layer(t)))
	if _, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous", err)
	}
}

func TestOpenRefusesALegacyDockerArchive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`[{"Config":"c.json","Layers":["l/layer.tar"]}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(t.Context(), "oci-archive:"+tarDir(t, dir, ""), "linux/amd64", false)
	if !errors.Is(err, ErrLegacyDockerArchive) || !strings.Contains(err.Error(), "skopeo copy") {
		t.Fatalf("err = %v, want ErrLegacyDockerArchive with how to convert it", err)
	}
}

func TestOpenRefusesAMalformedDigest(t *testing.T) {
	// A digest is joined into a path under blobs/, so it must be refused
	// before anything is opened.
	dir := t.TempDir()
	idx := map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"digest":    "sha256:../../../etc/passwd",
		"size":      1,
	}}}
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), "oci:"+dir, "linux/amd64", false); err == nil || !strings.Contains(err.Error(), "non-hex") {
		t.Fatalf("err = %v, want the digest refused as malformed", err)
	}
}

func TestOpenRefusesAMissingLayout(t *testing.T) {
	for _, ref := range []string{"oci:" + t.TempDir(), "oci-archive:" + filepath.Join(t.TempDir(), "none.tar")} {
		if _, err := Open(t.Context(), ref, "linux/amd64", false); err == nil {
			t.Fatalf("%s: opened an image that is not there", ref)
		}
	}
}

var errFull = errors.New("full")

func TestExtractAsksBeforeFetchingEachLayer(t *testing.T) {
	img, dir := twoLayers(t)
	got, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false)
	if err != nil {
		t.Fatal(err)
	}
	ls, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	second, err := ls[1].Size()
	if err != nil {
		t.Fatal(err)
	}
	var asked []int64
	dest := t.TempDir()
	err = got.Extract(t.Context(), dest, t.TempDir(), func(size int64) error {
		asked = append(asked, size)
		if len(asked) == 2 {
			return errFull
		}
		return nil
	})
	if !errors.Is(err, errFull) || len(asked) != 2 || asked[1] != second {
		t.Fatalf("err = %v, asked %v; want the refusal for the second layer, asked with its size %d", err, asked, second)
	}
	if _, err := os.Stat(filepath.Join(dest, "usr")); !os.IsNotExist(err) {
		t.Fatalf("the refused layer was applied: %v", err)
	}
}

func TestOpenSkipsAnUnlabelledImageForAnotherArchitecture(t *testing.T) {
	amd := platformImage(t, "amd64", layer(t, entry{name: "arch", typ: tar.TypeReg, body: "amd64"}))
	arm := platformImage(t, "arm64", layer(t, entry{name: "arch", typ: tar.TypeReg, body: "arm64"}))
	nested := t.TempDir()
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: amd},
		mutate.IndexAddendum{Add: arm, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}})
	p, err := layout.Write(nested, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AppendIndex(idx); err != nil {
		t.Fatal(err)
	}
	flat := t.TempDir()
	writeLayout(t, flat, amd, arm)
	for _, dir := range []string{nested, flat} {
		for _, arch := range []string{"amd64", "arm64"} {
			img, err := Open(t.Context(), "oci:"+dir, "linux/"+arch, false)
			if err != nil {
				t.Fatalf("%s for linux/%s: %v", dir, arch, err)
			}
			dest := t.TempDir()
			if err := extract(t, img, dest); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(filepath.Join(dest, "arch")); string(b) != arch {
				t.Fatalf("linux/%s unpacked the %q image", arch, b)
			}
		}
	}
}

func TestOpenCountsAnImageListedTwiceOnce(t *testing.T) {
	img, _ := twoLayers(t)
	dir := t.TempDir()
	writeLayout(t, dir, img, img)
	if _, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false); err != nil {
		t.Fatalf("one image under two names: %v", err)
	}
}

func TestALocalCopyStopsWhenCancelled(t *testing.T) {
	src := &fakeSource{body: []byte("blob")}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var w countingWriter
	err := fetchVerified(ctx, src, &v1.Descriptor{Size: 4}, &w)
	if !errors.Is(err, context.Canceled) || w.n != 0 {
		t.Fatalf("err = %v after %d bytes, want the cancellation before any", err, w.n)
	}
}

func TestABlobShorterThanItsDescriptorIsRefused(t *testing.T) {
	body := []byte("blob")
	h, _, err := v1.SHA256(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	err = fetchVerified(t.Context(), &fakeSource{body: body}, &v1.Descriptor{Size: int64(len(body)) + 1, Digest: h}, &w)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch for a blob one byte short of its size", err)
	}
}

func TestAnIndexWithNoImagesSaysSo(t *testing.T) {
	_, err := pick(t.Context(), &fakeSource{}, &v1.IndexManifest{}, &v1.Platform{OS: "linux", Architecture: "amd64"}, true, 0)
	if !errors.Is(err, ErrPlatform) || !strings.Contains(err.Error(), "the index lists no images") {
		t.Fatalf("err = %v, want ErrPlatform saying the index is empty", err)
	}
}

func TestCloseReleasesTheArchive(t *testing.T) {
	_, dir := twoLayers(t)
	img, err := Open(t.Context(), "oci-archive:"+tarDir(t, dir, ""), "linux/"+runtime.GOARCH, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := img.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, img, t.TempDir()); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("err = %v, want the archive closed", err)
	}
}

func TestAStagedBlobHoldsOnlyTheLastAttempt(t *testing.T) {
	saved := retryDelay
	t.Cleanup(func() { retryDelay = saved })
	retryDelay = 0
	blob := []byte("layer")
	h, n, err := v1.SHA256(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{bodies: [][]byte{[]byte("a longer wrong answer"), blob}, retries: true}
	p, err := stageBlob(t.Context(), src, &v1.Descriptor{Digest: h, Size: n}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, blob) || src.opens != 2 {
		t.Fatalf("staged %q after %d opens, want %q after 2", b, src.opens, blob)
	}
}

func TestOpenCountsAManifestReachedTwiceOnce(t *testing.T) {
	img, _ := twoLayers(t)
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        img,
		Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}},
	})
	dir := t.TempDir()
	p := writeLayout(t, dir, img)
	if err := p.AppendIndex(idx); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false); err != nil {
		t.Fatalf("one manifest, named directly and through an index: %v", err)
	}
}

// fetchVerified computes only sha256 and relies on ggcr refusing a digest
// that names another algorithm when it parses one.
func TestOpenRefusesADigestThatIsNotSHA256(t *testing.T) {
	img, dir := twoLayers(t)
	h, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(blobPath(dir, h))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha512"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha512", h.Hex), b, 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	idx = bytes.ReplaceAll(idx, []byte(h.String()), []byte("sha512:"+h.Hex))
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false); err == nil || !strings.Contains(err.Error(), "unsupported hash") {
		t.Fatalf("err = %v, want the sha512 digest refused", err)
	}
}

func TestApplyingALayerStopsWhenCancelled(t *testing.T) {
	img, dir := twoLayers(t)
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	d := m.Layers[0]
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dest := t.TempDir()
	if err := applyLayer(ctx, dest, blobPath(dir, d.Digest), &d); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", err)
	}
	assertEmpty(t, dest)
}

// skopeo's --dest-shared-blob-dir keeps blobs outside the layout, and a
// tar of the layout's parent puts index.json one level down.
func TestALayoutThatIsNotSelfContainedSaysWhatIsMissing(t *testing.T) {
	img, dir := twoLayers(t)
	if _, err := Open(t.Context(), "oci-archive:"+tarDir(t, dir, "image/"), "linux/"+runtime.GOARCH, false); err == nil || !strings.Contains(err.Error(), "at the root of the archive or directory") {
		t.Fatalf("err = %v, want a hint that index.json must be at the root", err)
	}
	if err := os.Remove(blobPath(dir, layerDigests(t, img)[1])); err != nil {
		t.Fatal(err)
	}
	got, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH, false)
	if err != nil {
		t.Fatal(err)
	}
	err = got.Extract(t.Context(), t.TempDir(), t.TempDir(), func(int64) error { return nil })
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "must hold its own blobs") {
		t.Fatalf("err = %v, want a hint that the layout must hold its blobs", err)
	}
}
