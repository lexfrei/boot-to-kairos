package efiboot

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
)

type bpb struct {
	sectorSize        uint16
	sectorsPerCluster uint8
	reserved          uint16
	fats              uint8
	rootEntries       uint16
	sectors           uint32
	sectors16         uint16
	fat16Sectors      uint16
	fat32Sectors      uint32
}

func (b bpb) bytes() []byte {
	s := make([]byte, 512)
	s[0], s[1], s[2] = 0xEB, 0x58, 0x90
	binary.LittleEndian.PutUint16(s[11:], b.sectorSize)
	s[13] = b.sectorsPerCluster
	binary.LittleEndian.PutUint16(s[14:], b.reserved)
	s[16] = b.fats
	binary.LittleEndian.PutUint16(s[17:], b.rootEntries)
	binary.LittleEndian.PutUint16(s[19:], b.sectors16)
	s[21] = 0xF8
	binary.LittleEndian.PutUint16(s[22:], b.fat16Sectors)
	binary.LittleEndian.PutUint32(s[32:], b.sectors)
	binary.LittleEndian.PutUint32(s[36:], b.fat32Sectors)
	s[510], s[511] = 0x55, 0xAA
	return s
}

// imageWithESP lays out a disk image whose ESP starts at LBA 256 and holds
// the given boot sector.
func imageWithESP(t *testing.T, sector int, size uint64, boot []byte) string {
	t.Helper()
	esp := partition{num: 1, start: 256, size: size, typ: espType, guid: guidOf(t, "00112233445566778899aabbccddeeff")}
	img := make([]byte, 256*sector+len(boot))
	copy(img, makeGPT(t, sector, []partition{esp}))
	copy(img[256*sector:], boot)
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The cluster counts follow the FAT specification, and EDK2's FAT driver,
// which most UEFI firmware carries, refuses a volume whose BPB says FAT32
// with fewer than 65525 clusters, or FAT12/16 with more:
// https://github.com/tianocore/edk2/blob/master/FatPkg/EnhancedFatDxe/Init.c
func TestCheckESP(t *testing.T) {
	for name, tc := range map[string]struct {
		sector int
		bpb    bpb
		ok     bool
	}{
		// mkfs.vfat -F 32 on the 64 MiB ESP kairos-agent makes, 512-byte sectors.
		"FAT32 on 512-byte sectors": {512, bpb{512, 1, 32, 2, 0, 131072, 0, 0, 1009}, true},
		// The same partition on a 4Kn disk: 16384 sectors cannot make 65525 clusters.
		"FAT32 on a 64 MiB 4Kn ESP": {4096, bpb{4096, 1, 6, 2, 0, 16384, 0, 0, 16}, false},
		// What kairos-agent made of a 260 MiB ESP on a 4Kn disk: 8317 clusters.
		"FAT32 on a 260 MiB 4Kn ESP": {4096, bpb{4096, 8, 6, 2, 0, 66560, 0, 0, 9}, false},
		"FAT32 at the minimum":       {512, bpb{512, 1, 32, 2, 0, 32 + 2*512 + 65525, 0, 0, 512}, true},
		// EDK2 takes the root directory of a FAT32 from the data area, whatever
		// the FAT12/16 root entry count says.
		"FAT32 with a root entry count": {512, bpb{512, 1, 32, 2, 512, 32 + 2*512 + 65525, 0, 0, 512}, true},
		"FAT32 one cluster short":       {512, bpb{512, 1, 32, 2, 0, 32 + 2*512 + 65524, 0, 0, 512}, false},
		"FAT16 on a 64 MiB 4Kn ESP":     {4096, bpb{4096, 1, 1, 2, 512, 16384, 0, 16, 0}, true},
		"FAT16 at the maximum":          {512, bpb{512, 1, 1, 2, 512, 1 + 2*256 + 32 + 65524, 0, 256, 0}, true},
		"FAT16 one cluster too many":    {512, bpb{512, 1, 1, 2, 512, 1 + 2*256 + 32 + 65525, 0, 256, 0}, false},
		// The 16-bit count wins over the 32-bit one, which would make too many.
		"FAT16 with a 16-bit count": {4096, bpb{4096, 1, 1, 2, 512, 4000000, 16384, 16, 0}, true},
		"no FAT at all":             {512, bpb{}, false},
		"no sectors per cluster":    {512, bpb{512, 0, 32, 2, 0, 131072, 0, 0, 1009}, false},
		"3 sectors per cluster":     {512, bpb{512, 3, 32, 2, 0, 400000, 0, 0, 1009}, false},
		"FAT area past the volume":  {512, bpb{512, 1, 32, 2, 0, 1000, 0, 0, 1009}, false},
	} {
		t.Run(name, func(t *testing.T) {
			b := tc.bpb.bytes()
			err := CheckESP(imageWithESP(t, tc.sector, 1<<16, b), tc.sector)
			if tc.ok && err != nil {
				t.Fatalf("readable ESP refused: %v", err)
			}
			if !tc.ok && (!errors.Is(err, ErrESPUnreadable) || strings.Contains(err.Error(), ErrESPUnreadable.Error())) {
				t.Fatalf("got %v, want ErrESPUnreadable, marked rather than repeated in the text", err)
			}
		})
	}
}

func TestCheckESPReadsWhatItCannotBlameOnTheFirmware(t *testing.T) {
	linux := partition{num: 1, start: 256, size: 8, typ: guidOf(t, "af3dc60f838472478e793d69d8477de4")}
	noESP := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(noESP, append(makeGPT(t, 512, []partition{linux}), make([]byte, 256*512)...), 0o600); err != nil {
		t.Fatal(err)
	}
	cut := imageWithESP(t, 512, 1<<16, nil)
	for name, path := range map[string]string{"no ESP": noESP, "cut off before the ESP": cut} {
		if err := CheckESP(path, 512); err == nil || errors.Is(err, ErrESPUnreadable) {
			t.Errorf("%s: got %v, want an error that is not ErrESPUnreadable", name, err)
		}
	}
}

func TestCheckESPNeedsAPartitionTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckESP(path, 512); err == nil {
		t.Fatal("an image without a GPT passed")
	}
}
