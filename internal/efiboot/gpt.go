package efiboot

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"

	"github.com/cockroachdb/errors"
)

// espType is C12A7328-F81F-11D2-BA4B-00A0C93EC93B in GPT byte order.
var espType = [16]byte{0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b} //nolint:gochecknoglobals // constant

// ErrNoGPT means the image carries no primary GPT that checks out.
var ErrNoGPT = errors.New("no valid GPT")

// maxEntries bounds the partition array read from a header that passed its
// CRC but may still be nonsense.
const maxEntries = 1 << 20

type partition struct {
	num         uint32
	start, size uint64
	typ, guid   [16]byte
}

// readGPT reads the primary GPT. LBAs count in sector-sized blocks.
func readGPT(r io.ReaderAt, sector int) ([]partition, error) {
	if sector < 512 {
		return nil, errors.Newf("logical sector size %d", sector)
	}
	h := make([]byte, sector)
	if _, err := r.ReadAt(h, int64(sector)); err != nil {
		return nil, errors.Wrap(err, "read GPT header")
	}
	if string(h[:8]) != "EFI PART" {
		return nil, errors.Wrap(ErrNoGPT, "no signature")
	}
	hsize := binary.LittleEndian.Uint32(h[12:])
	if hsize < 92 || int(hsize) > sector {
		return nil, errors.Wrapf(ErrNoGPT, "header size %d", hsize)
	}
	hdr := bytes.Clone(h[:hsize])
	binary.LittleEndian.PutUint32(hdr[16:], 0)
	if crc32.ChecksumIEEE(hdr) != binary.LittleEndian.Uint32(h[16:]) {
		return nil, errors.Wrap(ErrNoGPT, "header CRC mismatch")
	}
	lba := binary.LittleEndian.Uint64(h[72:])
	count := binary.LittleEndian.Uint32(h[80:])
	esize := binary.LittleEndian.Uint32(h[84:])
	if esize < 128 || esize%8 != 0 || uint64(count)*uint64(esize) > maxEntries {
		return nil, errors.Wrapf(ErrNoGPT, "%d entries of %d bytes", count, esize)
	}
	if lba > math.MaxInt64/uint64(sector) {
		return nil, errors.Wrapf(ErrNoGPT, "partition entries at LBA %d", lba)
	}
	entries := make([]byte, count*esize)
	if _, err := r.ReadAt(entries, int64(lba)*int64(sector)); err != nil {
		return nil, errors.Wrap(err, "read GPT entries")
	}
	if crc32.ChecksumIEEE(entries) != binary.LittleEndian.Uint32(h[88:]) {
		return nil, errors.Wrap(ErrNoGPT, "partition entries CRC mismatch")
	}
	var parts []partition
	for i := range count {
		e := entries[i*esize:]
		var p partition
		copy(p.typ[:], e[0:16])
		if p.typ == [16]byte{} {
			continue
		}
		copy(p.guid[:], e[16:32])
		p.num = i + 1
		p.start = binary.LittleEndian.Uint64(e[32:])
		last := binary.LittleEndian.Uint64(e[40:])
		if last < p.start {
			return nil, errors.Wrapf(ErrNoGPT, "partition %d ends before it starts", p.num)
		}
		p.size = last - p.start + 1
		parts = append(parts, p)
	}
	return parts, nil
}

func findESP(parts []partition) (partition, error) {
	for _, p := range parts {
		if p.typ == espType {
			return p, nil
		}
	}
	return partition{}, errors.New("the image has no EFI system partition")
}

// oldDisk identifies the disk being replaced the way HD() device path nodes
// do: by partition GUID on GPT, by disk signature on MBR.
type oldDisk struct {
	guids [][16]byte
	mbr   uint32
}

// readOldDisk never fails: a disk it cannot read leaves no entry to remove,
// and the new entry still goes into BootOrder.
func readOldDisk(r io.ReaderAt, sector int) oldDisk {
	if parts, err := readGPT(r, sector); err == nil {
		d := oldDisk{}
		for _, p := range parts {
			d.guids = append(d.guids, p.guid)
		}
		return d
	}
	mbr := make([]byte, 512)
	if _, err := r.ReadAt(mbr, 0); err != nil || mbr[510] != 0x55 || mbr[511] != 0xAA {
		return oldDisk{}
	}
	for i := range 4 {
		if mbr[446+16*i+4] == 0xEE {
			return oldDisk{}
		}
	}
	return oldDisk{mbr: binary.LittleEndian.Uint32(mbr[440:])}
}

// matches reports whether any HD() node of the load option's device path
// names a partition of this disk.
func (d oldDisk) matches(opt []byte) bool {
	path, ok := devicePath(opt)
	if !ok {
		return false
	}
	for len(path) >= 4 {
		n := int(binary.LittleEndian.Uint16(path[2:]))
		if n < 4 || n > len(path) {
			return false
		}
		if path[0] == 4 && path[1] == 1 && n == hdLen && d.owns(path[:n]) {
			return true
		}
		path = path[n:]
	}
	return false
}

func (d oldDisk) owns(hd []byte) bool {
	sig := hd[24:40]
	switch hd[41] {
	case 1:
		return d.mbr != 0 && binary.LittleEndian.Uint32(sig) == d.mbr
	case 2:
		for _, g := range d.guids {
			if bytes.Equal(sig, g[:]) {
				return true
			}
		}
	}
	return false
}

// devicePath returns the FilePathList of an EFI_LOAD_OPTION.
func devicePath(opt []byte) ([]byte, bool) {
	if len(opt) < 6 {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(opt[4:]))
	for i := 6; i+1 < len(opt); i += 2 {
		if opt[i] == 0 && opt[i+1] == 0 {
			if i+2+n > len(opt) {
				return nil, false
			}
			return opt[i+2 : i+2+n], true
		}
	}
	return nil, false
}
