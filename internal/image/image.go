// Package image fetches a Kairos OCI image from a registry or a local image
// layout and unpacks its root filesystem.
package image

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"strings"

	"github.com/cockroachdb/errors"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sys/unix"
)

// Image is a resolved OCI image whose layers have not been fetched yet.
type Image struct {
	// Digest is the digest of the manifest picked for the platform.
	Digest v1.Hash
	// Layers are the manifest's layer descriptors, oldest first.
	Layers []v1.Descriptor

	// signed are the digests a signature for the image may name: the one a
	// registry returned for the reference, which may be an index above
	// Digest, or each entry of a layout's index.json that resolves to
	// Digest.
	signed []v1.Hash
	src    source
}

// Extract applies the image's layers to dest, oldest first, the way a
// container runtime does. Each layer is first copied to a file in stage and
// verified against its digest, then applied from that file and removed, so a
// layer that does not match is refused before any of it reaches dest. fits
// is asked before each layer is fetched, with its size as stored. Every
// path is resolved inside dest, so an entry or a symlink in the image can
// never make the extraction write outside it; such entries are skipped.
func (i *Image) Extract(ctx context.Context, dest, stage string, fits func(size int64) error) error {
	for n := range i.Layers {
		l := &i.Layers[n]
		if err := fits(l.Size); err != nil {
			return errors.Wrapf(err, "layer %d", n)
		}
		blob, err := stageBlob(ctx, i.src, l, stage)
		if err != nil {
			return errors.Wrapf(fmt.Errorf("%w: %w", ErrStage, err), "layer %d", n)
		}
		err = applyLayer(ctx, dest, blob, l)
		_ = os.Remove(blob)
		if err != nil {
			return errors.Wrapf(err, "layer %d", n)
		}
	}
	return nil
}

// ErrStage marks a failure to copy a layer to the staging dir.
var ErrStage = errors.New("staging")

// Transport names where the image is read from.
func (i *Image) Transport() string { return i.src.transport() }

// Close releases the local image layout or archive.
func (i *Image) Close() error { return i.src.close() }

// stagedLayer is a verified layer file. Read through partial, it is read
// once, sniffed for gzip or zstd; tarball.LayerFromOpener would digest it
// and unpack it once more first.
type stagedLayer struct {
	path string
	d    *v1.Descriptor
}

func (s stagedLayer) Digest() (v1.Hash, error)            { return s.d.Digest, nil }
func (s stagedLayer) Compressed() (io.ReadCloser, error)  { return os.Open(s.path) }
func (s stagedLayer) Size() (int64, error)                { return s.d.Size, nil }
func (s stagedLayer) MediaType() (types.MediaType, error) { return s.d.MediaType, nil }

// applyLayer applies a verified layer file, gzip, zstd or uncompressed.
func applyLayer(ctx context.Context, dest, blob string, d *v1.Descriptor) error {
	l, err := partial.CompressedToLayer(stagedLayer{blob, d})
	if err != nil {
		return errors.Wrap(err, "open layer")
	}
	rc, err := l.Uncompressed()
	if err != nil {
		return errors.Wrap(err, "open layer")
	}
	defer rc.Close()
	return extractTar(dest, ctxReader{ctx, rc})
}

const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
)

// extractTar applies one layer to dest.
func extractTar(dest string, r io.Reader) error {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return errors.Wrap(err, "open destination")
	}
	defer root.Close()

	// What this layer wrote, and every directory above it: an opaque marker
	// hides only lower layers, wherever in the stream it comes.
	written := map[string]bool{}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			// A decompressor reports a malformed stream, a gzip checksum
			// say, only at its end, which lies past the tar end marker.
			_, err = io.Copy(io.Discard, r)
			return errors.Wrap(err, "read layer to the end")
		}
		if err != nil {
			return errors.Wrap(err, "read layer")
		}
		rel, err := resolve(root, path.Clean("/" + h.Name)[1:])
		if err != nil {
			return errors.Wrapf(err, "resolve %s", h.Name)
		}
		if rel == "" {
			continue
		}
		dir, base := path.Dir(rel), path.Base(rel)
		switch {
		case base == opaqueMarker:
			err = clearLower(root, dir, written)
		case strings.HasPrefix(base, whiteoutPrefix):
			target := strings.TrimPrefix(base, whiteoutPrefix)
			if target == "" || target == "." || target == ".." {
				log.Printf("skipping whiteout %s: it names no entry", h.Name)
				continue
			}
			err = whiteout(root, path.Join(dir, target), written)
		default:
			err = extractEntry(root, rel, h, tr)
			for p := rel; p != "."; p = path.Dir(p) {
				written[p] = true
			}
		}
		if err != nil {
			return errors.Wrapf(err, "extract %s", h.Name)
		}
	}
}

// whiteout removes p as lower layers left it. What this layer wrote there
// stays: a whiteout hides only lower layers, wherever in the stream it is.
func whiteout(root *os.Root, p string, written map[string]bool) error {
	if !written[p] {
		return root.RemoveAll(p)
	}
	fi, err := root.Lstat(p)
	if err != nil || !fi.IsDir() {
		return err
	}
	return clearLower(root, p, written)
}

// maxLinks is the kernel's limit on symlinks followed in one lookup.
const maxLinks = 40

// resolve follows the symlinks in the parent directories of rel the way the
// installed system will see them: an absolute target starts again at the
// image root, and .. stops there. The last component is left alone. os.Root
// would refuse an absolute link instead, and an entry below one would be
// lost.
func resolve(root *os.Root, rel string) (string, error) {
	if rel == "" {
		return "", nil
	}
	parts := strings.Split(path.Dir(rel), "/")
	cur := "."
	for links := 0; len(parts) > 0; {
		p := parts[0]
		parts = parts[1:]
		switch p {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, p)
		fi, err := root.Lstat(next)
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		links++
		if links > maxLinks {
			return "", errors.Wrapf(unix.ELOOP, "%s", rel)
		}
		target, err := root.Readlink(next)
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			cur = "."
		}
		parts = append(strings.Split(target, "/"), parts...)
	}
	return path.Join(cur, path.Base(rel)), nil
}

// clearLower removes from dir everything below it that earlier layers put
// there, keeping what this layer wrote.
func clearLower(root *os.Root, dir string, written map[string]bool) error {
	f, err := root.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		switch {
		case !written[p]:
			err = root.RemoveAll(p)
		case e.IsDir():
			err = clearLower(root, p, written)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// makeRoom removes whatever is at rel unless it is a directory and a
// directory is wanted there.
func makeRoom(root *os.Root, rel string, dir bool) error {
	fi, err := root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if dir && fi.IsDir() {
		return nil
	}
	return root.RemoveAll(rel)
}

func extractEntry(root *os.Root, rel string, h *tar.Header, r io.Reader) error {
	// Tar keeps setuid/setgid/sticky as Unix bits; FileInfo maps them to the
	// os.FileMode flags, which a plain conversion does not.
	mode := h.FileInfo().Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if dir := path.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	switch h.Typeflag {
	case tar.TypeDir:
		if err := makeRoom(root, rel, true); err != nil {
			return err
		}
		if err := root.MkdirAll(rel, mode.Perm()); err != nil {
			return err
		}
	case tar.TypeReg:
		if err := makeRoom(root, rel, false); err != nil {
			return err
		}
		f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if err := makeRoom(root, rel, false); err != nil {
			return err
		}
		return root.Symlink(h.Linkname, rel)
	case tar.TypeLink:
		if err := makeRoom(root, rel, false); err != nil {
			return err
		}
		target, err := resolve(root, path.Clean("/" + h.Linkname)[1:])
		if err != nil {
			return err
		}
		return root.Link(target, rel)
	default:
		// Device nodes and FIFOs are not needed: /dev is mounted at runtime.
		return nil
	}
	// Ownership only sticks when running as root, which the installer is. It
	// goes first: chown clears setuid and setgid, for root too.
	_ = root.Lchown(rel, h.Uid, h.Gid)
	if err := root.Chmod(rel, mode); err != nil {
		return err
	}
	// After chown as well: it drops security.capability.
	return setXattrs(root, rel, h.PAXRecords)
}

var fsetxattr = unix.Fsetxattr //nolint:gochecknoglobals // test seam

func setXattrs(root *os.Root, rel string, pax map[string]string) error {
	attrs := map[string]string{}
	for k, v := range pax {
		if attr, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
			attrs[attr] = v
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	f, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer f.Close()
	for attr, v := range attrs {
		err := fsetxattr(int(f.Fd()), attr, []byte(v), 0)
		if errors.Is(err, unix.EOPNOTSUPP) && !strings.HasPrefix(attr, "security.") {
			// tmpfs takes user.* only since Linux 6.6.
			log.Printf("skipping xattr %s on %s: %v", attr, rel, err)
			continue
		}
		if err != nil {
			return errors.Wrapf(err, "set %s", attr)
		}
	}
	return nil
}
