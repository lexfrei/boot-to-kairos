package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

type entry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func layer(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body))}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testImage(t *testing.T, layers ...[]byte) *Image {
	t.Helper()
	dir := t.TempDir()
	writeLayout(t, dir, platformImage(t, runtime.GOARCH, layers...))
	img, err := Open(t.Context(), "oci:"+dir, "linux/"+runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func extract(t *testing.T, img *Image, dest string) error {
	t.Helper()
	return img.Extract(t.Context(), dest, t.TempDir(), func(int64) error { return nil })
}

func TestExtractAppliesWhiteouts(t *testing.T) {
	img := testImage(t,
		layer(t,
			entry{name: "usr/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "usr/bin/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "usr/bin/kairos-agent", typ: tar.TypeReg, body: "agent", mode: 0o755},
			entry{name: "etc/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "etc/old.conf", typ: tar.TypeReg, body: "old"},
		),
		layer(t, entry{name: "etc/.wh.old.conf", typ: tar.TypeReg}),
	)
	dest := t.TempDir()
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "usr/bin/kairos-agent"))
	if err != nil || string(b) != "agent" {
		t.Fatalf("kairos-agent = %q, %v", b, err)
	}
	st, err := os.Stat(filepath.Join(dest, "usr/bin/kairos-agent"))
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, %v", st.Mode(), err)
	}
	if _, err := os.Stat(filepath.Join(dest, "etc/old.conf")); !os.IsNotExist(err) {
		t.Fatalf("whited-out file still present: %v", err)
	}
}

func TestExtractKeepsSpecialModeBits(t *testing.T) {
	stream := layer(t,
		entry{name: "usr/bin/sudo", typ: tar.TypeReg, body: "s", mode: 0o4755},
		entry{name: "usr/bin/wall", typ: tar.TypeReg, body: "w", mode: 0o2755},
		entry{name: "tmp/", typ: tar.TypeDir, mode: 0o1777},
	)
	dest := t.TempDir()
	if err := extractTar(dest, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{
		"usr/bin/sudo": os.ModeSetuid | 0o755,
		"usr/bin/wall": os.ModeSetgid | 0o755,
		"tmp":          os.ModeDir | os.ModeSticky | 0o777,
	} {
		st, err := os.Stat(filepath.Join(dest, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode() != want {
			t.Errorf("%s mode = %v, want %v", name, st.Mode(), want)
		}
	}
}

func TestExtractStaysInsideDestination(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "root")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	img := testImage(t, layer(t,
		entry{name: "../escape", typ: tar.TypeReg, body: "x"},
		entry{name: "bin", typ: tar.TypeSymlink, link: "usr/bin"},
		entry{name: "abs", typ: tar.TypeSymlink, link: "/etc/passwd"},
	))
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape")); !os.IsNotExist(err) {
		t.Fatalf("entry escaped the destination: %v", err)
	}
	if l, err := os.Readlink(filepath.Join(dest, "abs")); err != nil || l != "/etc/passwd" {
		t.Fatalf("absolute symlink inside the rootfs = %q, %v", l, err)
	}
	if l, err := os.Readlink(filepath.Join(dest, "bin")); err != nil || l != "usr/bin" {
		t.Fatalf("relative symlink = %q, %v", l, err)
	}
}

func TestExtractDoesNotWriteThroughSymlinkedDirectory(t *testing.T) {
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(parent, "root")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	// A raw stream, not through mutate.Extract, which would already drop the
	// second entry: this exercises the extractor's own guard.
	stream := layer(t,
		entry{name: "etc", typ: tar.TypeSymlink, link: outside},
		entry{name: "etc/planted", typ: tar.TypeReg, body: "x"},
	)
	if err := extractTar(dest, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "planted")); !os.IsNotExist(err) {
		t.Fatalf("file written through a symlink to outside the destination: %v", err)
	}
}

func TestExtractLinksToAFileFromALowerLayer(t *testing.T) {
	// Layers are flattened newest first, so the link arrives before its
	// target.
	img := testImage(t,
		layer(t, entry{name: "usr/bin/", typ: tar.TypeDir, mode: 0o755}, entry{name: "usr/bin/gzip", typ: tar.TypeReg, body: "gz", mode: 0o755}),
		layer(t, entry{name: "usr/bin/gunzip", typ: tar.TypeLink, link: "usr/bin/gzip"}),
	)
	dest := t.TempDir()
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	a, err := os.Stat(filepath.Join(dest, "usr/bin/gzip"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dest, "usr/bin/gunzip"))
	if err != nil || !os.SameFile(a, b) {
		t.Fatalf("gunzip = %v, %v, want a hard link to gzip", b, err)
	}
}

func TestExtractKeepsExtendedAttributes(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	h := &tar.Header{
		Name: "usr/bin/ping", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"SCHILY.xattr.user.btk": "cap"},
	}
	if err := tw.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("p")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := unix.Setxattr(dest, "user.probe", []byte("x"), 0); err != nil {
		t.Skipf("no user xattrs on %s: %v", dest, err)
	}
	if err := extractTar(dest, &buf); err != nil {
		t.Fatal(err)
	}
	v := make([]byte, 16)
	n, err := unix.Getxattr(filepath.Join(dest, "usr/bin/ping"), "user.btk", v)
	if err != nil || string(v[:n]) != "cap" {
		t.Fatalf("user.btk = %q, %v, want cap: security.capability travels the same way", v[:n], err)
	}
}

func TestExtractAppliesOpaqueWhiteouts(t *testing.T) {
	img := testImage(t,
		layer(t,
			entry{name: "etc/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "etc/old.d/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "etc/old.d/stale.conf", typ: tar.TypeReg, body: "stale"},
		),
		// The marker may follow entries of its own layer, which it must
		// not hide.
		layer(t,
			entry{name: "etc/old.d/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "etc/old.d/early.conf", typ: tar.TypeReg, body: "early"},
			entry{name: "etc/old.d/.wh..wh..opq", typ: tar.TypeReg},
			entry{name: "etc/old.d/fresh.conf", typ: tar.TypeReg, body: "fresh"},
		),
	)
	dest := t.TempDir()
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "etc/old.d/stale.conf")); !os.IsNotExist(err) {
		t.Fatalf("stale.conf survived an opaque directory: %v", err)
	}
	for _, name := range []string{"etc/old.d/early.conf", "etc/old.d/fresh.conf"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dest, "etc/old.d/.wh..opq")); !os.IsNotExist(err) {
		t.Fatalf("the opaque marker itself was extracted: %v", err)
	}
}

func TestExtractKeepsALinkToAReplacedFile(t *testing.T) {
	// The link shares the inode of the lower a; a later layer replacing or
	// deleting a must not touch what b holds.
	img := testImage(t,
		layer(t,
			entry{name: "a", typ: tar.TypeReg, body: "old"},
			entry{name: "b", typ: tar.TypeLink, link: "a"},
			entry{name: "c", typ: tar.TypeReg, body: "old c"},
			entry{name: "d", typ: tar.TypeLink, link: "c"},
		),
		layer(t,
			entry{name: "a", typ: tar.TypeReg, body: "new"},
			entry{name: ".wh.c", typ: tar.TypeReg},
		),
	)
	dest := t.TempDir()
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a": "new", "b": "old", "d": "old c"} {
		if got, err := os.ReadFile(filepath.Join(dest, name)); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v, want %q", name, got, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "c")); !os.IsNotExist(err) {
		t.Errorf("c survived its whiteout: %v", err)
	}
}

func TestExtractReplacesADirectoryWithAFile(t *testing.T) {
	img := testImage(t,
		layer(t, entry{name: "x/", typ: tar.TypeDir, mode: 0o755}, entry{name: "x/y", typ: tar.TypeReg, body: "y"}),
		layer(t, entry{name: "x", typ: tar.TypeReg, body: "file"}),
	)
	dest := t.TempDir()
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "x")); err != nil || string(got) != "file" {
		t.Fatalf("x = %q, %v, want the file of the upper layer", got, err)
	}
}

func TestExtractSkipsOnlyUnsupportedNonSecurityXattrs(t *testing.T) {
	orig := fsetxattr
	t.Cleanup(func() { fsetxattr = orig })
	fsetxattr = func(int, string, []byte, int) error { return unix.EOPNOTSUPP }

	stream := func(attr string) *bytes.Buffer {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		h := &tar.Header{
			Name: "f", Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatPAX,
			PAXRecords: map[string]string{"SCHILY.xattr." + attr: "v"},
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		return &buf
	}
	if err := extractTar(t.TempDir(), stream("user.note")); err != nil {
		t.Fatalf("err = %v: a user xattr the filesystem cannot hold is not worth failing the install", err)
	}
	if err := extractTar(t.TempDir(), stream("security.capability")); err == nil {
		t.Fatal("a lost file capability must fail the install")
	}
}

func TestOpaqueWhiteoutReachesLowerDescendants(t *testing.T) {
	lower := layer(t,
		entry{name: "etc/", typ: tar.TypeDir, mode: 0o755},
		entry{name: "etc/sub/", typ: tar.TypeDir, mode: 0o755},
		entry{name: "etc/sub/old.conf", typ: tar.TypeReg, body: "old"},
		entry{name: "etc/gone.conf", typ: tar.TypeReg, body: "gone"},
	)
	for name, upper := range map[string][]byte{
		// A writer that sorts names puts the marker after its siblings.
		"directory entry first": layer(t,
			entry{name: "etc/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "etc/sub/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "etc/sub/new.conf", typ: tar.TypeReg, body: "new"},
			entry{name: "etc/.wh..wh..opq", typ: tar.TypeReg},
		),
		"no directory entry": layer(t,
			entry{name: "etc/sub/new.conf", typ: tar.TypeReg, body: "new"},
			entry{name: "etc/.wh..wh..opq", typ: tar.TypeReg},
		),
	} {
		t.Run(name, func(t *testing.T) {
			dest := t.TempDir()
			if err := extract(t, testImage(t, lower, upper), dest); err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(filepath.Join(dest, "etc/sub/new.conf")); err != nil || string(b) != "new" {
				t.Errorf("new.conf = %q, %v: the marker hides lower layers only", b, err)
			}
			for _, gone := range []string{"etc/sub/old.conf", "etc/gone.conf"} {
				if _, err := os.Lstat(filepath.Join(dest, gone)); !os.IsNotExist(err) {
					t.Errorf("%s survived an opaque parent: %v", gone, err)
				}
			}
		})
	}
}

func TestWhiteoutsOfDotNamesAreIgnored(t *testing.T) {
	img := testImage(t,
		layer(t, entry{name: "etc/", typ: tar.TypeDir, mode: 0o755}, entry{name: "etc/keep", typ: tar.TypeReg, body: "k"}),
		layer(t,
			entry{name: "etc/.wh..", typ: tar.TypeReg},
			entry{name: "etc/.wh.", typ: tar.TypeReg},
			entry{name: "nothere/.wh..wh..opq", typ: tar.TypeReg},
		),
	)
	dest := t.TempDir()
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "etc/keep")); err != nil {
		t.Fatalf("a whiteout named .. or empty removed its own directory: %v", err)
	}
}

func TestWhiteoutHidesOnlyLowerLayers(t *testing.T) {
	img := testImage(t,
		layer(t,
			entry{name: "foo", typ: tar.TypeReg, body: "old"},
			entry{name: "d/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "d/old", typ: tar.TypeReg, body: "old"},
		),
		// Whiteouts after entries of their own layer: allowed, and they must
		// not hide those entries.
		layer(t,
			entry{name: "foo", typ: tar.TypeReg, body: "new"},
			entry{name: ".wh.foo", typ: tar.TypeReg},
			entry{name: "d/new", typ: tar.TypeReg, body: "new"},
			entry{name: ".wh.d", typ: tar.TypeReg},
		),
	)
	dest := t.TempDir()
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"foo", "d/new"} {
		if b, err := os.ReadFile(filepath.Join(dest, name)); err != nil || string(b) != "new" {
			t.Errorf("%s = %q, %v, want the entry of the whiteout's own layer", name, b, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dest, "d/old")); !os.IsNotExist(err) {
		t.Errorf("d/old survived the whiteout of d: %v", err)
	}
}

func TestExtractResolvesSymlinksInsideTheImage(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "root")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	img := testImage(t,
		layer(t,
			entry{name: "usr/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "usr/bin/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "bin", typ: tar.TypeSymlink, link: "/usr/bin"},
			entry{name: "up", typ: tar.TypeSymlink, link: "../../.."},
			entry{name: "opt/", typ: tar.TypeDir, mode: 0o755},
			entry{name: "opt/tools", typ: tar.TypeSymlink, link: "/usr/bin"},
		),
		layer(t,
			entry{name: "bin/tool", typ: tar.TypeReg, body: "t", mode: 0o755},
			entry{name: "up/planted", typ: tar.TypeReg, body: "x"},
			entry{name: "opt/tools/other", typ: tar.TypeReg, body: "o"},
		),
	)
	if err := extract(t, img, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "usr/bin/tool")); err != nil {
		t.Fatalf("bin/tool through bin -> /usr/bin: %v; an absolute link means the image's own root", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "usr/bin/other")); err != nil {
		t.Fatalf("opt/tools/other through opt/tools -> /usr/bin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "planted")); !os.IsNotExist(err) {
		t.Fatalf("up/planted escaped the destination: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "planted")); err != nil {
		t.Fatalf("up/planted = %v, want it at the image root, where .. stops as in a chroot", err)
	}
}

type failAtEOF struct{}

func (failAtEOF) Read([]byte) (int, error) { return 0, gzip.ErrChecksum }

func TestExtractReadsEachLayerToTheEnd(t *testing.T) {
	// A decompressor reports a bad checksum only at the end of its stream,
	// past the tar end marker.
	stream := io.MultiReader(bytes.NewReader(layer(t, entry{name: "f", typ: tar.TypeReg, body: "x"})), failAtEOF{})
	if err := extractTar(t.TempDir(), stream); !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("err = %v, want the checksum failure that comes after the tar end marker", err)
	}
}
