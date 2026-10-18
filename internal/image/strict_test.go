package image

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestStrictJSON(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		ok        bool
	}{
		{"valid", `{"a":1,"b":{"c":[1,2]}}`, true},
		{"trailing whitespace", "{}\n", true},
		{"duplicate at the top", `{"a":1,"a":2}`, false},
		{"duplicate in a nested object", `{"m":[{"digest":"x","size":1,"digest":"y"}]}`, false},
		{"duplicate spelled with an escape", `{"a":1,"\u0061":2}`, false},
		{"invalid UTF-8 in a value", "{\"a\":\"\xff\"}", false},
		{"invalid UTF-8 in a name", "{\"\xff\":1}", false},
		{"a lone surrogate", `{"a":"\ud800"}`, false},
		{"a second value", `{}{}`, false},
		{"trailing garbage", `{}x`, false},
		{"empty, left to the parser", ``, true},
		{"truncated, left to the parser", `{"a":`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := StrictJSON([]byte(tc.raw))
			if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrInvalidJSON)) {
				t.Fatalf("StrictJSON(%q) = %v, want ok %v", tc.raw, err, tc.ok)
			}
		})
	}
}

// metadata is an image as raw JSON: root, an index naming child, an index
// naming manifest, which names config and a layer, with each object's
// bytes and media type by digest.
type metadata struct {
	root                               []byte
	blobs                              map[v1.Hash][]byte
	mediaTypes                         map[v1.Hash]types.MediaType
	child, manifest, config, layerBlob v1.Hash
}

func put(m *metadata, raw string, mt types.MediaType) (v1.Hash, int) {
	b := []byte(raw)
	h, n, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		panic(err)
	}
	m.blobs[h] = b
	m.mediaTypes[h] = mt
	return h, int(n)
}

// buildMetadata spoils the object named which, one of root, child,
// manifest and config, with spoil.
func buildMetadata(arch, which string, spoil func(object string) string) *metadata {
	m := &metadata{blobs: map[v1.Hash][]byte{}, mediaTypes: map[v1.Hash]types.MediaType{}}
	keep := func(name, s string) string {
		if name == which {
			return spoil(s)
		}
		return s
	}
	m.layerBlob, _ = put(m, "layer", types.OCILayer)
	cfg := keep("config", fmt.Sprintf(`{"architecture":%q,"os":"linux","config":{"Labels":{"note":"ok"}},"rootfs":{"type":"layers","diff_ids":[]}}`, arch))
	var cfgSize, manSize, childSize int
	m.config, cfgSize = put(m, cfg, types.OCIConfigJSON)
	man := keep("manifest", fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"digest":%q,"size":%d},"layers":[{"mediaType":%q,"digest":%q,"size":5}],"annotations":{"note":"ok"}}`,
		types.OCIManifestSchema1, types.OCIConfigJSON, m.config, cfgSize, types.OCILayer, m.layerBlob))
	m.manifest, manSize = put(m, man, types.OCIManifestSchema1)
	child := keep("child", fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"digest":%q,"size":%d,"platform":{"architecture":%q,"os":"linux"}}],"annotations":{"note":"ok"}}`,
		types.OCIImageIndex, types.OCIManifestSchema1, m.manifest, manSize, arch))
	m.child, childSize = put(m, child, types.OCIImageIndex)
	m.root = []byte(keep("root", fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"digest":%q,"size":%d}],"annotations":{"note":"ok"}}`,
		types.OCIImageIndex, types.OCIImageIndex, m.child, childSize)))
	return m
}

// spoils are the parser differentials each object is spoiled with: a
// member named twice, with the value encoding/json keeps last being the
// right one, so that only a strict parser refuses the object, and invalid
// UTF-8.
func spoils() map[string]map[string]func(string) string {
	dup := func(member, bogus string) func(string) string {
		return func(s string) string {
			i := strings.Index(s, `"`+member+`":`)
			if i < 0 {
				panic(member + " not in " + s)
			}
			return s[:i] + `"` + member + `":` + bogus + "," + s[i:]
		}
	}
	badUTF8 := func(s string) string { return strings.Replace(s, `"note":"ok"`, "\"note\":\"o\xffk\"", 1) }
	zero := `"sha256:` + strings.Repeat("0", 64) + `"`
	return map[string]map[string]func(string) string{
		"root": {
			"digest":    dup("digest", zero),
			"size":      dup("size", "1"),
			"mediaType": dup("mediaType", `"application/x-other"`),
			"utf8":      badUTF8,
		},
		"child": {
			"digest":   dup("digest", zero),
			"platform": dup("platform", `{"architecture":"s390x","os":"linux"}`),
			"utf8":     badUTF8,
		},
		"manifest": {
			"digest":    dup("digest", zero),
			"size":      dup("size", "1"),
			"mediaType": dup("mediaType", `"application/x-other"`),
			"utf8":      badUTF8,
		},
		"config": {
			"architecture": dup("architecture", `"s390x"`),
			"utf8":         badUTF8,
		},
	}
}

const testArch = "amd64"

var testPlatform = &v1.Platform{OS: "linux", Architecture: testArch}

func (m *metadata) layoutDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), m.root, 0o644); err != nil {
		t.Fatal(err)
	}
	for h, b := range m.blobs {
		if err := os.WriteFile(blobPath(dir, h), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// recording wraps a layout source to list the files it opens.
func recording(t *testing.T, ref string) (layoutSource, *[]string) {
	t.Helper()
	src, err := openSource(ref, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.close() })
	ls := src.(layoutSource)
	var opened []string
	file := ls.file
	ls.file = func(name string) (io.ReadCloser, error) {
		opened = append(opened, name)
		return file(name)
	}
	return ls, &opened
}

// readOrder is the objects as resolving reads them.
func (m *metadata) readOrder() []string { return []string{"root", "child", "manifest", "config"} }

func (m *metadata) digestOf(object string) v1.Hash {
	return map[string]v1.Hash{"child": m.child, "manifest": m.manifest, "config": m.config}[object]
}

func TestALayoutWithAmbiguousMetadataIsRefusedWhereItIsRead(t *testing.T) {
	for which, cases := range spoils() {
		for how, spoil := range cases {
			t.Run(which+"/"+how, func(t *testing.T) {
				m := buildMetadata(testArch, which, spoil)
				dir := m.layoutDir(t)
				for _, ref := range []string{"oci:" + dir, "oci-archive:" + tarDir(t, dir, "")} {
					src, opened := recording(t, ref)
					_, err := resolveManifest(t.Context(), src, testPlatform)
					if !errors.Is(err, ErrInvalidJSON) {
						t.Fatalf("%s: err = %v, want ErrInvalidJSON", ref, err)
					}
					want := []string{"index.json"}
					for _, o := range m.readOrder()[1 : slices.Index(m.readOrder(), which)+1] {
						want = append(want, blobName(m.digestOf(o)))
					}
					if !slices.Equal(*opened, want) {
						t.Fatalf("%s: opened %v, want %v and nothing after the spoiled %s", ref, *opened, want, which)
					}
				}
			})
		}
	}
}

func blobName(h v1.Hash) string { return "blobs/sha256/" + h.Hex }

func TestALayoutWithStrictMetadataResolves(t *testing.T) {
	m := buildMetadata(testArch, "", nil)
	src, _ := recording(t, "oci:"+m.layoutDir(t))
	r, err := resolveManifest(t.Context(), src, testPlatform)
	if err != nil || r.digest != m.manifest {
		t.Fatalf("resolved %s, %v; want %s", r.digest, err, m.manifest)
	}
}

// rawRegistry serves m with the root under tag, byte for byte, and
// records the paths it is asked for.
func rawRegistry(t *testing.T, m *metadata) (ref string, requested func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		p := r.URL.Path
		if p == "/v2/" {
			return
		}
		body, mt := []byte(nil), types.MediaType("")
		switch {
		case strings.HasSuffix(p, "/manifests/"+tag):
			body, mt = m.root, types.OCIImageIndex
		case strings.Contains(p, "/manifests/sha256:"), strings.Contains(p, "/blobs/sha256:"):
			h, err := v1.NewHash(p[strings.LastIndex(p, "/")+1:])
			if err != nil {
				http.NotFound(w, r)
				return
			}
			body, mt = m.blobs[h], m.mediaTypes[h]
		}
		if body == nil {
			http.NotFound(w, r)
			return
		}
		h, _, _ := v1.SHA256(bytes.NewReader(body))
		w.Header().Set("Content-Type", string(mt))
		w.Header().Set("Docker-Content-Digest", h.String())
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://") + "/kairos/hadron:" + tag, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(paths)
	}
}

func TestARegistryImageWithAmbiguousMetadataIsRefusedWhereItIsRead(t *testing.T) {
	for which, cases := range spoils() {
		for how, spoil := range cases {
			t.Run(which+"/"+how, func(t *testing.T) {
				m := buildMetadata(testArch, which, spoil)
				ref, requested := rawRegistry(t, m)
				_, err := Open(t.Context(), ref, "linux/"+testArch, false)
				if !errors.Is(err, ErrInvalidJSON) {
					t.Fatalf("err = %v, want ErrInvalidJSON", err)
				}
				read := m.readOrder()[1 : slices.Index(m.readOrder(), which)+1]
				for _, o := range m.readOrder()[1:] {
					asked := slices.ContainsFunc(requested(), func(p string) bool { return strings.HasSuffix(p, m.digestOf(o).String()) })
					if asked != slices.Contains(read, o) {
						t.Fatalf("%s requested: %v; want only %v, nothing after the spoiled %s: %v", o, asked, read, which, requested())
					}
				}
				if slices.ContainsFunc(requested(), func(p string) bool { return strings.HasSuffix(p, m.layerBlob.String()) }) {
					t.Fatalf("the layer was fetched: %v", requested())
				}
			})
		}
	}
}

func TestARegistryImageWithStrictMetadataResolves(t *testing.T) {
	m := buildMetadata(testArch, "", nil)
	ref, _ := rawRegistry(t, m)
	img, err := Open(t.Context(), ref, "linux/"+testArch, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = img.Close()
	if img.Digest != m.manifest {
		t.Fatalf("resolved %s, want %s", img.Digest, m.manifest)
	}
}

// hadron is the index, amd64 manifest and config of
// quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0, as published.
func hadron(t *testing.T) *metadata {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "signature", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	m := &metadata{blobs: map[v1.Hash][]byte{}, mediaTypes: map[v1.Hash]types.MediaType{}, root: read("v4.3.0-index.json")}
	m.manifest, _ = put(m, string(read("v4.3.0-f29481c2351b.json")), types.OCIManifestSchema1)
	m.config, _ = put(m, string(read("v4.3.0-fdb8c34d07c9.json")), types.OCIConfigJSON)
	return m
}

func TestTheReleasedHadronMetadataIsStrict(t *testing.T) {
	m := hadron(t)
	ref, _ := rawRegistry(t, m)
	src, _ := recording(t, "oci:"+m.layoutDir(t))
	r, err := resolveManifest(t.Context(), src, testPlatform)
	if err != nil || r.digest != m.manifest {
		t.Fatalf("layout: resolved %s, %v; want %s", r.digest, err, m.manifest)
	}
	img, err := Open(context.Background(), ref, "linux/amd64", false)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	_ = img.Close()
	if img.Digest != m.manifest {
		t.Fatalf("registry: resolved %s, want %s", img.Digest, m.manifest)
	}
}

func TestALayoutReferrerOrBundleWithAmbiguousJSONIsRefused(t *testing.T) {
	zero := `"sha256:` + strings.Repeat("0", 64) + `"`
	for _, tc := range []struct {
		name, referrer, inSubject, bundle string
	}{
		{name: "subject named twice", referrer: `"subject":{"mediaType":%q,"size":1,"digest":` + zero + `},`},
		{name: "subject digest named twice", inSubject: `"digest":` + zero + `,`},
		{name: "referrer with invalid UTF-8", referrer: "\"annotations\":{\"note\":\"\xff\"},"},
		{name: "bundle with a member named twice", bundle: `{"mediaType":"x","mediaType":"` + bundleType + `"}`},
		{name: "bundle with invalid UTF-8", bundle: "{\"mediaType\":\"" + bundleType + "\",\"note\":\"\xff\"}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, index, _ := orasLayout(t)
			p, err := layout.FromPath(dir)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"mediaType":"` + bundleType + `","of":"this referrer"}`
			if tc.bundle != "" {
				body = tc.bundle
			}
			cfg := writeBlob(t, p, []byte("{}"), "application/vnd.oci.empty.v1+json")
			l := writeBlob(t, p, []byte(body), bundleType)
			idxSize := len(mustRead(t, blobPath(dir, index)))
			extra := tc.referrer
			if strings.Contains(extra, "%q") {
				extra = fmt.Sprintf(extra, types.OCIImageIndex)
			}
			raw := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"artifactType":%q,"config":{"mediaType":%q,"size":2,"digest":%q},"layers":[{"mediaType":%q,"size":%d,"digest":%q}],`+
				extra+`"subject":{`+tc.inSubject+`"mediaType":%q,"size":%d,"digest":%q}}`,
				types.OCIManifestSchema1, bundleType, cfg.MediaType, cfg.Digest, bundleType, l.Size, l.Digest, types.OCIImageIndex, idxSize, index)
			d := writeBlob(t, p, []byte(raw), types.OCIManifestSchema1)
			if err := p.AppendDescriptor(d); err != nil {
				t.Fatal(err)
			}
			src, opened := recording(t, "oci:"+dir)
			i := &Image{src: src, signed: []v1.Hash{index}}
			_, err = i.Signatures(t.Context())
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("err = %v, want ErrInvalidJSON", err)
			}
			if tc.bundle == "" && slices.Contains(*opened, blobName(l.Digest)) {
				t.Fatalf("the bundle of the refused referrer was read: %v", *opened)
			}
		})
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
