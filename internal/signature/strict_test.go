package signature

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/lexfrei/boot-to-kairos/internal/image"
)

const zeroDigest = `"sha256:0000000000000000000000000000000000000000000000000000000000000000"`

// twice names member in raw twice, the first time with bogus, so that
// encoding/json reads the value it already had. The member is the first
// one past the text after names, if it is given.
func twice(t *testing.T, raw []byte, member, bogus string, after ...string) []byte {
	t.Helper()
	from := 0
	if len(after) > 0 {
		from = bytes.Index(raw, []byte(after[0]))
	}
	m := []byte(`"` + member + `":`)
	i := bytes.Index(raw[max(from, 0):], m)
	if from < 0 || i < 0 {
		t.Fatalf("%s not in %s", member, raw)
	}
	i += from
	return slices.Concat(raw[:i], m, []byte(bogus+","), raw[i:])
}

// withBundle returns the v4.3.0 referrer rewritten to carry bundle.
func withBundle(t *testing.T, bundle []byte) []byte {
	t.Helper()
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
	return referrer
}

// spoiledLogEntry rewrites the Rekor entry body inside the v4.3.0 bundle
// with spoil.
func spoiledLogEntry(t *testing.T, spoil func([]byte) []byte) []byte {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(fixture(t, "v4.3.0-bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	entry := b["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
	body, err := base64.StdEncoding.DecodeString(entry["canonicalizedBody"].(string))
	if err != nil {
		t.Fatal(err)
	}
	entry["canonicalizedBody"] = base64.StdEncoding.EncodeToString(spoil(body))
	bundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

// spoiledPayload rewrites the statement inside the v4.3.0 bundle's DSSE
// envelope with spoil.
func spoiledPayload(t *testing.T, spoil func([]byte) []byte) []byte {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(fixture(t, "v4.3.0-bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	env := b["dsseEnvelope"].(map[string]any)
	payload, err := base64.StdEncoding.DecodeString(env["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	env["payload"] = base64.StdEncoding.EncodeToString(spoil(payload))
	bundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

// protojson refuses a bundle with a duplicate or invalid UTF-8 itself, and a
// spoiled statement or log entry no longer matches its signature, so in
// those cases the check only makes the refusal bad-image rather than
// bad-signature, and makes it before anything is verified.
func TestARegistryReferrerOrBundleWithAmbiguousJSONIsRefused(t *testing.T) {
	bundle := fixture(t, "v4.3.0-bundle.json")
	for _, tc := range []struct {
		name             string
		referrer, bundle []byte
	}{
		{name: "referrer subject digest named twice", referrer: twice(t, fixture(t, "v4.3.0-referrer.json"), "digest", zeroDigest, `"subject":`)},
		{name: "referrer layer size named twice", referrer: twice(t, fixture(t, "v4.3.0-referrer.json"), "size", "1", `"layers":`)},
		{name: "referrer with invalid UTF-8", referrer: bytes.Replace(fixture(t, "v4.3.0-referrer.json"), []byte("2026-09-08"), []byte("2026-09-0\xff"), 1)},
		{name: "bundle mediaType named twice", bundle: twice(t, bundle, "mediaType", `"application/json"`)},
		{name: "bundle with invalid UTF-8", bundle: bytes.Replace(bundle, []byte(`"mediaType":"`), []byte("\"mediaType\":\"\xff"), 1)},
		{name: "statement subject named twice", bundle: spoiledPayload(t, func(p []byte) []byte {
			return twice(t, p, "subject", `[{"digest":{"sha256":"00"}}]`)
		})},
		{name: "statement with invalid UTF-8", bundle: spoiledPayload(t, func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"predicate":{}`), []byte("\"predicate\":{\"note\":\"\xff\"}"), 1)
		})},
		{name: "log entry kind named twice", bundle: spoiledLogEntry(t, func(p []byte) []byte {
			return twice(t, p, "kind", `"hashedrekord"`)
		})},
		{name: "log entry with invalid UTF-8", bundle: spoiledLogEntry(t, func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"apiVersion":"0.0.1"`), []byte("\"apiVersion\":\"0.0.1\xff\""), 1)
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			referrer, b := tc.referrer, bundle
			if tc.bundle != nil {
				referrer, b = withBundle(t, tc.bundle), tc.bundle
			}
			r := newRegistry(t)
			r.index430(t, tag430)
			r.bundle430(t, referrer, b)
			before := len(r.requested())
			_, err := Verify(context.Background(), r.source(t, digest430, tag430), Policy{}, trusted(t))
			if !errors.Is(err, image.ErrInvalidJSON) {
				t.Fatalf("got %v, want ErrInvalidJSON", err)
			}
			h, _, err := v1.SHA256(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			during := r.requested()[before:]
			read := slices.ContainsFunc(during, func(p string) bool { return strings.HasSuffix(p, h.String()) })
			if tc.bundle == nil && read {
				t.Fatalf("the bundle of the refused referrer was fetched: %v", during)
			}
		})
	}
}

func TestAnAmbiguousReferrersListIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func([]byte) []byte
	}{
		{"digest named twice", func(b []byte) []byte { return twice(t, b, "digest", zeroDigest) }},
		{"mediaType named twice", func(b []byte) []byte { return twice(t, b, "mediaType", `"application/json"`) }},
		{"invalid UTF-8", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"manifests":`), []byte("\"annotations\":{\"note\":\"\xff\"},\"manifests\":"), 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry(t, true)
			r.index430(t, tag430)
			referrer := fixture(t, "v4.3.0-referrer.json")
			h, size, err := v1.SHA256(bytes.NewReader(referrer))
			if err != nil {
				t.Fatal(err)
			}
			// Without the referrers API the list is the index under the
			// fallback tag, which the registry serves as stored.
			list, err := json.Marshal(map[string]any{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.oci.image.index.v1+json",
				"manifests": []map[string]any{{
					"mediaType":    "application/vnd.oci.image.manifest.v1+json",
					"digest":       h.String(),
					"size":         size,
					"artifactType": bundleMediaType,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			r.bundle430(t, referrer, fixture(t, "v4.3.0-bundle.json"))
			r.putManifest(t, tc.spoil(list), strings.Replace(digest430, ":", "-", 1))
			before := len(r.requested())
			_, err = Verify(context.Background(), r.source(t, digest430, tag430), Policy{}, trusted(t))
			if !errors.Is(err, image.ErrInvalidJSON) {
				t.Fatalf("got %v, want ErrInvalidJSON", err)
			}
			if during := r.requested()[before:]; slices.ContainsFunc(during, func(p string) bool { return strings.HasSuffix(p, h.String()) }) {
				t.Fatalf("a referrer of the refused list was fetched: %v", during)
			}
		})
	}
}

const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// An ambiguous bundle refuses the image even when another digest it may be
// signed under has a signature that verifies.
func TestAnAmbiguousBundleIsNotOutweighedByAnotherDigest(t *testing.T) {
	other, good := mustHash(t, "sha256:"+strings.Repeat("1", 64)), mustHash(t, digest430)
	bad := twice(t, fixture(t, "v4.3.0-bundle.json"), "mediaType", `"application/json"`)
	src := image.SignatureSource{
		Digests: []v1.Hash{other, good},
		Bundles: map[v1.Hash][][]byte{other: {bad}, good: {fixture(t, "v4.3.0-bundle.json")}},
	}
	if _, err := Verify(context.Background(), src, Policy{}, trusted(t)); !errors.Is(err, image.ErrInvalidJSON) {
		t.Fatalf("got %v, want ErrInvalidJSON", err)
	}
}

// A referrer listed as an image manifest but served as an index would be
// resolved by go-containerregistry to a child of its own choosing, read
// leniently, so it is refused, ambiguous or not, before the child is
// fetched.
func TestAReferrerServedAsAnIndexIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func([]byte) []byte
		want  error
	}{
		{"digest named twice", func(b []byte) []byte { return twice(t, b, "digest", zeroDigest) }, image.ErrInvalidJSON},
		{"strict", func(b []byte) []byte { return b }, image.ErrMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry(t, true)
			r.index430(t, tag430)
			referrer := fixture(t, "v4.3.0-referrer.json")
			h, size, err := v1.SHA256(bytes.NewReader(referrer))
			if err != nil {
				t.Fatal(err)
			}
			r.bundle430(t, referrer, fixture(t, "v4.3.0-bundle.json"))
			wrapper, err := json.Marshal(map[string]any{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.oci.image.index.v1+json",
				"manifests": []map[string]any{{
					"mediaType": "application/vnd.oci.image.manifest.v1+json",
					"digest":    h.String(),
					"size":      size,
					"platform":  map[string]string{"architecture": "amd64", "os": "linux"},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			wrapper = tc.spoil(wrapper)
			wh, wsize, err := v1.SHA256(bytes.NewReader(wrapper))
			if err != nil {
				t.Fatal(err)
			}
			r.putManifest(t, wrapper, "")
			list, err := json.Marshal(map[string]any{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.oci.image.index.v1+json",
				"manifests": []map[string]any{{
					"mediaType":    "application/vnd.oci.image.manifest.v1+json",
					"digest":       wh.String(),
					"size":         wsize,
					"artifactType": bundleMediaType,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			r.putManifest(t, list, strings.Replace(digest430, ":", "-", 1))
			before := len(r.requested())
			_, err = Verify(context.Background(), r.source(t, digest430, tag430), Policy{}, trusted(t))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want a refusal (%v)", err, tc.want)
			}
			if during := r.requested()[before:]; slices.ContainsFunc(during, func(p string) bool { return strings.HasSuffix(p, h.String()) }) {
				t.Fatalf("the child of the index was fetched: %v", during)
			}
		})
	}
}
