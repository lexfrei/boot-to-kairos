//go:build linux

package efiboot

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"golang.org/x/sys/unix"
)

// globalVendor is EFI_GLOBAL_VARIABLE, the vendor of Boot#### and BootOrder.
const globalVendor = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

// fsImmutable is FS_IMMUTABLE_FL from linux/fs.h, which x/sys lacks.
const fsImmutable = 0x10

// nvBsRt is EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS,
// the attributes every boot variable carries.
var nvBsRt = []byte{7, 0, 0, 0} //nolint:gochecknoglobals // constant

// Available reports whether dir is a writable efivarfs.
func Available(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return errors.Wrapf(err, "statfs %s", dir)
	}
	return errors.Wrap(usable(&st), dir)
}

func usable(st *unix.Statfs_t) error {
	if uint32(st.Type) != unix.EFIVARFS_MAGIC {
		return errors.New("not efivarfs")
	}
	if st.Flags&unix.ST_RDONLY != 0 {
		return errors.New("efivarfs is mounted read-only")
	}
	return nil
}

// Apply writes the plan into the efivarfs at dir.
func (p *Plan) Apply(dir string) (Result, error) {
	return p.apply(efivarfs(dir))
}

// efivarfs holds one file per variable: the attributes, then the value.
type efivarfs string

func (e efivarfs) path(name string) string {
	return filepath.Join(string(e), name+"-"+globalVendor)
}

func (e efivarfs) names() ([]string, error) {
	ents, err := os.ReadDir(string(e))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, ent := range ents {
		if name, ok := strings.CutSuffix(ent.Name(), "-"+globalVendor); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

func (e efivarfs) read(name string) ([]byte, error) {
	b, err := os.ReadFile(e.path(name))
	if err != nil {
		return nil, err
	}
	if len(b) < len(nvBsRt) {
		return nil, errors.Newf("%s: %d bytes, no attributes", name, len(b))
	}
	return b[len(nvBsRt):], nil
}

// write hands attributes and value to the kernel in one write(2): efivarfs
// takes each write as the whole variable.
func (e efivarfs) write(name string, data []byte) error {
	p := e.path(name)
	if err := mutable(p); err != nil {
		return err
	}
	fd, err := unix.Open(p, unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return errors.Wrapf(err, "open %s", name)
	}
	defer unix.Close(fd)
	buf := append(append([]byte{}, nvBsRt...), data...)
	n, err := unix.Write(fd, buf)
	if err != nil {
		return errors.Wrapf(err, "write %s", name)
	}
	if n != len(buf) {
		return errors.Wrapf(io.ErrShortWrite, "write %s", name)
	}
	return nil
}

func (e efivarfs) remove(name string) error {
	p := e.path(name)
	if err := mutable(p); err != nil {
		return err
	}
	return os.Remove(p)
}

// mutable clears the immutable flag, which the kernel sets on variables
// outside its allowlist and anyone may set with chattr.
func mutable(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer unix.Close(fd)
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "get flags of %s", path)
	}
	if flags&fsImmutable == 0 {
		return nil
	}
	return errors.Wrapf(unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags&^fsImmutable)), "clear immutable flag of %s", path)
}
