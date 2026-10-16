// Package efiboot points the firmware at the installed system: it writes a
// UEFI boot entry for the new disk's EFI system partition, puts it in
// BootOrder where the replaced system's entry stood and drops the entries of
// the system it replaced.
package efiboot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"
	"unicode/utf16"

	"github.com/cockroachdb/errors"
)

// Description is the name the firmware shows for the entry.
const Description = "Kairos"

// ErrReadBack means the firmware kept something other than what was written.
var ErrReadBack = errors.New("EFI variable differs on read-back")

const (
	noEntry          = -1
	loadOptionActive = 1
	hdLen            = 42
)

// Plan is the boot entry to write once the disk carries the image. It is made
// before the disk is overwritten: afterwards neither the old partition table
// nor anything else on that disk can be read.
type Plan struct {
	option []byte
	old    oldDisk
}

// Result is what Apply left in NVRAM.
type Result struct {
	// Entry is the Boot#### number written or reused, -1 if none.
	Entry int
	// Ordered is whether BootOrder has Entry, at Position counted from 0.
	Ordered  bool
	Position int
	Removed  []uint16
}

func (r Result) String() string {
	s := "no boot entry"
	switch {
	case r.Entry != noEntry && r.Ordered && r.Position == 0:
		s = fmt.Sprintf("Boot%04X %q first in BootOrder", r.Entry, Description)
	case r.Entry != noEntry && r.Ordered:
		s = fmt.Sprintf("Boot%04X %q at position %d in BootOrder", r.Entry, Description, r.Position+1)
	case r.Entry != noEntry:
		s = fmt.Sprintf("Boot%04X %q written, not in BootOrder", r.Entry, Description)
	}
	for _, n := range r.Removed {
		s += fmt.Sprintf(", removed Boot%04X", n)
	}
	return s
}

// store is the set of EFI global variables, named without the vendor GUID.
type store interface {
	names() ([]string, error)
	read(name string) ([]byte, error)
	write(name string, data []byte) error
	remove(name string) error
}

// NewPlan encodes the entry for the EFI system partition of the image, whose
// LBAs count in sectors of the given size, the disk's logical block size.
func NewPlan(image string, sector int, arch string) (*Plan, error) {
	loader, err := loaderPath(arch)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(image)
	if err != nil {
		return nil, errors.Wrap(err, "open image")
	}
	defer f.Close()
	parts, err := readGPT(f, sector)
	if err != nil {
		return nil, errors.Wrap(err, "image partition table")
	}
	esp, err := findESP(parts)
	if err != nil {
		return nil, err
	}
	return &Plan{option: loadOption(Description, esp, loader)}, nil
}

// Replacing records the partitions of disk, whose boot entries Apply removes.
func (p *Plan) Replacing(disk string, sector int) error {
	f, err := os.Open(disk)
	if err != nil {
		return errors.Wrap(err, "open disk")
	}
	defer f.Close()
	p.old = readOldDisk(f, sector)
	return nil
}

// apply does as much as it can and reports every failure. A failure leaves
// the firmware's fallback to \EFI\BOOT on the disk as it was, or better: the
// entries removed point at partitions that no longer exist.
func (p *Plan) apply(s store) (Result, error) {
	a := applier{s: s, res: Result{Entry: noEntry}, tried: map[int]bool{}}
	used, err := a.scan(p)
	if err != nil {
		return a.res, err
	}
	if a.res.Entry == noEntry {
		a.create(p.option, used)
	}
	if err := a.reorder(); err != nil {
		a.errs = append(a.errs, err)
	}
	if b, err := s.read("BootNext"); err == nil && len(b) == 2 && slices.Contains(a.stale, int(binary.LittleEndian.Uint16(b))) {
		if err := s.remove("BootNext"); err != nil {
			a.errs = append(a.errs, errors.Wrap(err, "remove BootNext"))
		}
	}
	a.removeStale()
	return a.res, errors.Join(a.errs...)
}

type applier struct {
	s     store
	res   Result
	stale []int
	tried map[int]bool
	errs  []error
}

// scan finds an entry equal to the plan's, to reuse, and the entries on the
// old disk.
func (a *applier) scan(p *Plan) (map[int]bool, error) {
	names, err := a.s.names()
	if err != nil {
		return nil, errors.Wrap(err, "list EFI variables")
	}
	slices.Sort(names)
	used := map[int]bool{}
	for _, name := range names {
		n := bootNumber(name)
		if n < 0 {
			continue
		}
		used[n] = true
		opt, err := a.s.read(name)
		if err != nil {
			continue
		}
		switch {
		case a.res.Entry == noEntry && bytes.Equal(opt, p.option):
			a.res.Entry = n
		case p.old.matches(opt):
			a.stale = append(a.stale, n)
		}
	}
	return used, nil
}

// create writes the entry under the lowest free number. A full NVRAM gets
// room from the stale entries, which go anyway.
func (a *applier) create(option []byte, used map[int]bool) {
	n := 0
	for used[n] {
		n++
	}
	if n > 0xFFFF {
		a.errs = append(a.errs, errors.New("no free boot entry number"))
		return
	}
	err := put(a.s, bootName(n), option)
	if errors.Is(err, syscall.ENOSPC) && len(a.stale) > 0 {
		a.removeStale()
		err = put(a.s, bootName(n), option)
	}
	if err != nil {
		a.errs = append(a.errs, errors.Wrapf(err, "write %s", bootName(n)))
		// The number was free: whatever is under it now is what failed.
		_ = a.s.remove(bootName(n))
		return
	}
	a.res.Entry = n
}

func (a *applier) removeStale() {
	for _, n := range a.stale {
		if a.tried[n] {
			continue
		}
		a.tried[n] = true
		if err := a.s.remove(bootName(n)); err != nil {
			a.errs = append(a.errs, errors.Wrapf(err, "remove %s", bootName(n)))
			continue
		}
		a.res.Removed = append(a.res.Removed, uint16(n))
	}
}

// reorder drops the stale entries from BootOrder and puts entry where the
// first of them, or entry itself, stood: a machine that boots from the
// network first, as provisioning systems set up, keeps doing so. Only with
// no such place does entry go first.
func (a *applier) reorder() error {
	entry := a.res.Entry
	cur, err := a.s.read("BootOrder")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Wrap(err, "read BootOrder")
	}
	var order []byte
	pos := -1
	for i := 0; i+1 < len(cur); i += 2 {
		n := int(binary.LittleEndian.Uint16(cur[i:]))
		if n != entry && !slices.Contains(a.stale, n) {
			order = append(order, cur[i:i+2]...)
		} else if pos < 0 {
			pos = len(order) / 2
		}
	}
	pos = max(pos, 0)
	if entry != noEntry {
		order = slices.Insert(order, 2*pos, byte(entry), byte(entry>>8))
	}
	switch {
	case bytes.Equal(order, cur):
	case len(order) == 0:
		// efivarfs would delete it on an empty write and fail the read-back.
		if err := a.s.remove("BootOrder"); err != nil {
			return errors.Wrap(err, "remove BootOrder")
		}
	default:
		if err := put(a.s, "BootOrder", order); err != nil {
			return errors.Wrap(err, "write BootOrder")
		}
	}
	a.res.Ordered = entry != noEntry
	a.res.Position = pos
	return nil
}

func put(s store, name string, data []byte) error {
	if err := s.write(name, data); err != nil {
		return err
	}
	got, err := s.read(name)
	if err != nil {
		return errors.Wrap(err, "read back")
	}
	if !bytes.Equal(got, data) {
		return ErrReadBack
	}
	return nil
}

func bootName(n int) string { return fmt.Sprintf("Boot%04X", n) }

// bootNumber parses Boot####; the spec has the digits upper-case.
func bootNumber(name string) int {
	hex, ok := strings.CutPrefix(name, "Boot")
	if !ok || len(hex) != 4 {
		return -1
	}
	n := 0
	for _, c := range hex {
		switch {
		case c >= '0' && c <= '9':
			n = n<<4 | int(c-'0')
		case c >= 'A' && c <= 'F':
			n = n<<4 | int(c-'A'+10)
		default:
			return -1
		}
	}
	return n
}

// loaderPath is the removable-media path, the one kairos-agent installs the
// shim to and the firmware falls back to.
func loaderPath(arch string) (string, error) {
	name, ok := map[string]string{"amd64": "X64", "arm64": "AA64", "riscv64": "RISCV64"}[arch]
	if !ok {
		return "", errors.Newf("no UEFI loader name for %s", arch)
	}
	return `\EFI\BOOT\BOOT` + name + ".EFI", nil
}

// loadOption encodes an EFI_LOAD_OPTION (UEFI 2.10, 3.1.3) that loads path
// from partition p: HD() media node, File() node, end of path.
func loadOption(desc string, p partition, path string) []byte {
	dp := []byte{4, 1}
	dp = binary.LittleEndian.AppendUint16(dp, hdLen)
	dp = binary.LittleEndian.AppendUint32(dp, p.num)
	dp = binary.LittleEndian.AppendUint64(dp, p.start)
	dp = binary.LittleEndian.AppendUint64(dp, p.size)
	dp = append(dp, p.guid[:]...)
	dp = append(dp, 2, 2) // GPT, GUID signature
	file := utf16z(path)
	dp = append(dp, 4, 4)
	dp = binary.LittleEndian.AppendUint16(dp, uint16(4+len(file)))
	dp = append(dp, file...)
	dp = append(dp, 0x7f, 0xff, 4, 0)

	b := binary.LittleEndian.AppendUint32(nil, loadOptionActive)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(dp)))
	b = append(b, utf16z(desc)...)
	return append(b, dp...)
}

func utf16z(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s + "\x00")) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}
