// Package image pulls a Kairos OCI image and unpacks its root filesystem.
package image

import (
	"archive/tar"
	"context"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sys/unix"
)

// Image is a pulled OCI image.
type Image struct {
	img v1.Image
	ref string
}

// Pull resolves ref for the given platform (for example linux/amd64). ctx
// also bounds the layer downloads that Extract triggers.
func Pull(ctx context.Context, ref, platform string) (*Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", ref)
	}
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, errors.Wrapf(err, "parse platform %s", platform)
	}
	img, err := remote.Image(r, remote.WithContext(ctx), remote.WithPlatform(*p), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, errors.Wrapf(err, "pull %s", ref)
	}
	return &Image{img: img, ref: ref}, nil
}

// Extract applies the image's layers to dest, oldest first, the way a
// container runtime does. Every path is resolved inside dest, so an entry or
// a symlink in the image can never make the extraction write outside it;
// such entries are skipped.
func (i *Image) Extract(dest string) error {
	layers, err := i.img.Layers()
	if err != nil {
		return errors.Wrap(err, "list layers")
	}
	for n, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			return errors.Wrapf(err, "open layer %d", n)
		}
		err = extractTar(dest, rc)
		rc.Close()
		if err != nil {
			return errors.Wrapf(err, "layer %d", n)
		}
	}
	return nil
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
			// The layer's digest is checked only when its stream hits EOF,
			// which lies past the tar end marker.
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
