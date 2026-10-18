//go:build linux

package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/lexfrei/boot-to-kairos/internal/image"
	"github.com/lexfrei/boot-to-kairos/internal/signature"
)

// fakeSigned serves a layout's signatures: the v4.3.0 release index and
// the bundle Kairos signed it with, or bundle, under the digest bundleFor
// names.
type fakeSigned struct {
	bundleFor string
	bundle    []byte
	calls     int
	final     []error
}

const signedIndex = "sha256:0642483eb9f7a3d42cc2d4e4b15afc37ced49d42b15d836e59a8ea0ab25dd9af"

func (f *fakeSigned) Signatures(context.Context) (image.SignatureSource, error) {
	f.calls++
	src := image.SignatureSource{Digests: []v1.Hash{mustHash(signedIndex)}}
	if f.bundleFor != "" {
		b, err := os.ReadFile(filepath.Join("..", "signature", "testdata", "v4.3.0-bundle.json"))
		if err != nil {
			return src, err
		}
		if f.bundle != nil {
			b = f.bundle
		}
		src.Bundles = map[v1.Hash][][]byte{mustHash(f.bundleFor): {b}}
	}
	return src, nil
}

func (f *fakeSigned) Retry(ctx context.Context, _ string, fetch func(ctx context.Context) error, final ...error) error {
	f.final = final
	return fetch(ctx)
}

func mustHash(s string) v1.Hash {
	h, err := v1.NewHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

var testRoot = filepath.Join("..", "signature", "testdata", "trusted_root.json")

func TestASignedImageIsNamedInThePlan(t *testing.T) {
	p := &Plan{}
	err := checkSignature(context.Background(), Options{Signature: &SignatureOptions{TrustedRoot: testRoot}}, &fakeSigned{bundleFor: signedIndex}, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.items) != 1 || p.items[0].name != "signature" ||
		!strings.HasPrefix(p.items[0].value, "verified: "+signedIndex+" signed by https://github.com/kairos-io/kairos/") ||
		!strings.HasSuffix(p.items[0].value, ", issuer https://token.actions.githubusercontent.com, from refs/tags/v4.3.0, Rekor log index 2755351284") {
		t.Fatalf("plan %+v", p.items)
	}
}

func TestAnImageWithoutAcceptedSignatureIsRefused(t *testing.T) {
	for _, tc := range []struct {
		bundleFor, class string
	}{
		{"", "no-signature"},
		{"sha256:" + strings.Repeat("1", 64), "no-signature"},
	} {
		f := &fakeSigned{bundleFor: tc.bundleFor}
		err := checkSignature(context.Background(), Options{Signature: &SignatureOptions{TrustedRoot: testRoot}}, f, &Plan{})
		if errorClass(err) != tc.class || !strings.Contains(err.Error(), "--verify-signature=false") {
			t.Fatalf("bundle for %q: got %v, class %q, want %s and the way to skip it", tc.bundleFor, err, errorClass(err), tc.class)
		}
		// Asking again would get the same answer.
		if !slices.Contains(f.final, signature.ErrNoSignature) || !slices.Contains(f.final, signature.ErrBadSignature) {
			t.Fatalf("retried unless %v", f.final)
		}
	}
}

func TestAnAmbiguousBundleRefusesTheImageAtOnce(t *testing.T) {
	f := &fakeSigned{bundleFor: signedIndex, bundle: []byte(`{"mediaType":"a","mediaType":"b"}`)}
	err := checkSignature(context.Background(), Options{Signature: &SignatureOptions{TrustedRoot: testRoot}}, f, &Plan{})
	if errorClass(err) != "bad-image" || strings.Contains(err.Error(), "--verify-signature=false") {
		t.Fatalf("got %v, class %q, want bad-image without the hint to skip the check", err, errorClass(err))
	}
	if !slices.Contains(f.final, image.ErrInvalidJSON) {
		t.Fatalf("retried unless %v", f.final)
	}
}

func TestAForeignSignerIsRefused(t *testing.T) {
	o := Options{Signature: &SignatureOptions{TrustedRoot: testRoot, Signer: signature.Policy{Identity: `^https://github\.com/example/`, Issuer: signature.GitHubIssuer}}}
	err := checkSignature(context.Background(), o, &fakeSigned{bundleFor: signedIndex}, &Plan{})
	if errorClass(err) != "bad-signature" {
		t.Fatalf("got %v, class %q", err, errorClass(err))
	}
}

func TestSkippingTheSignatureLooksNothingUp(t *testing.T) {
	p := &Plan{}
	f := &fakeSigned{}
	if err := checkSignature(context.Background(), Options{SkipSignature: true, Signature: &SignatureOptions{TrustedRoot: "/nonexistent"}}, f, p); err != nil {
		t.Fatal(err)
	}
	if f.calls != 0 || len(p.items) != 1 || p.items[0].value != "not verified: --verify-signature=false" {
		t.Fatalf("calls %d, plan %+v", f.calls, p.items)
	}
}

func TestAnUnreadableTrustedRootStopsTheInstall(t *testing.T) {
	err := checkSignature(context.Background(), Options{Signature: &SignatureOptions{TrustedRoot: "/nonexistent"}}, &fakeSigned{bundleFor: signedIndex}, &Plan{})
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}
