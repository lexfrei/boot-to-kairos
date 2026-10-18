package efiboot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// guidOf is a GUID in the byte order GPT stores it.
func guidOf(t *testing.T, hexs string) [16]byte {
	t.Helper()
	var g [16]byte
	b := mustHex(t, hexs)
	copy(g[:], b)
	return g
}

// ubuntuESP is partition 15 of the Ubuntu 24.04 cloud image, as sgdisk
// prints it: F923FA2F-C2FA-401B-9021-B4594673BF6F, sectors 10240-227327.
func ubuntuESP(t *testing.T) partition {
	t.Helper()
	return partition{num: 15, start: 10240, size: 217088, typ: espType, guid: guidOf(t, "2ffa23f9fac21b409021b4594673bf6f")}
}

// makeGPT lays out a primary GPT for sector-sized blocks, entries at LBA 2.
func makeGPT(t *testing.T, sector int, parts []partition) []byte {
	t.Helper()
	const count, entrySize = 128, 128
	entriesLen := count * entrySize
	img := make([]byte, 2*sector+entriesLen+sector)
	img[510], img[511] = 0x55, 0xAA
	img[446+4] = 0xEE
	entries := img[2*sector : 2*sector+entriesLen]
	for _, p := range parts {
		e := entries[(p.num-1)*entrySize:]
		copy(e[0:16], p.typ[:])
		copy(e[16:32], p.guid[:])
		binary.LittleEndian.PutUint64(e[32:], p.start)
		binary.LittleEndian.PutUint64(e[40:], p.start+p.size-1)
	}
	h := img[sector : sector+92]
	copy(h, "EFI PART")
	binary.LittleEndian.PutUint32(h[8:], 0x00010000)
	binary.LittleEndian.PutUint32(h[12:], 92)
	binary.LittleEndian.PutUint64(h[24:], 1)
	binary.LittleEndian.PutUint64(h[72:], 2)
	binary.LittleEndian.PutUint32(h[80:], count)
	binary.LittleEndian.PutUint32(h[84:], entrySize)
	binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(entries))
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
	return img
}

func TestReadGPTUbuntuCloudImage(t *testing.T) {
	b, err := os.ReadFile("testdata/ubuntu-gpt.bin")
	if err != nil {
		t.Fatal(err)
	}
	parts, err := readGPT(bytes.NewReader(b), 512)
	if err != nil {
		t.Fatal(err)
	}
	nums := []uint32{}
	for _, p := range parts {
		nums = append(nums, p.num)
	}
	if len(nums) != 4 || nums[0] != 1 || nums[1] != 14 || nums[2] != 15 || nums[3] != 16 {
		t.Fatalf("partitions %v, want 1 14 15 16", nums)
	}
	esp, err := findESP(parts)
	if err != nil {
		t.Fatal(err)
	}
	if esp != ubuntuESP(t) {
		t.Fatalf("ESP %+v, want %+v", esp, ubuntuESP(t))
	}
}

func TestReadGPTRejectsDamage(t *testing.T) {
	good := makeGPT(t, 512, []partition{ubuntuESP(t)})
	for name, damage := range map[string]func([]byte){
		"signature":   func(b []byte) { b[512] = 'X'; fixCRCs(b) },
		"header crc":  func(b []byte) { b[512+40]++ },
		"entries crc": func(b []byte) { b[2*512+20]++ },
		"entry size":  func(b []byte) { setField(b, 84, 8) },
		"entry count": func(b []byte) { setField(b, 80, 1<<20) },
		// The byte offset wraps around to LBA 2, where the entries are.
		"entries lba": func(b []byte) { binary.LittleEndian.PutUint64(b[512+72:], 1<<55+2); fixCRCs(b) },
		"end < start": func(b []byte) { binary.LittleEndian.PutUint64(b[2*512+14*128+40:], 100); fixCRCs(b) },
	} {
		b := bytes.Clone(good)
		damage(b)
		if _, err := readGPT(bytes.NewReader(b), 512); !errors.Is(err, ErrNoGPT) {
			t.Errorf("%s: %v, want ErrNoGPT", name, err)
		}
	}
}

// setField sets a header field and makes both CRCs match, so only the field
// itself is wrong.
func setField(b []byte, off int, v uint32) {
	binary.LittleEndian.PutUint32(b[512+off:], v)
	fixCRCs(b)
}

func fixCRCs(b []byte) {
	h := b[512 : 512+92]
	n := binary.LittleEndian.Uint32(h[80:]) * binary.LittleEndian.Uint32(h[84:])
	if end := 2*512 + int(n); end <= len(b) {
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(b[2*512:end]))
	}
	binary.LittleEndian.PutUint32(h[16:], 0)
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
}

func TestReadGPTSectorSize(t *testing.T) {
	b := makeGPT(t, 512, []partition{ubuntuESP(t)})
	for _, sector := range []int{0, -512, 256} {
		if _, err := readGPT(bytes.NewReader(b), sector); err == nil {
			t.Errorf("sector size %d accepted", sector)
		}
	}
}

func TestFindESPMissing(t *testing.T) {
	linux := partition{num: 1, start: 2048, size: 8, typ: guidOf(t, "af3dc60f838472478e793d69d8477de4")}
	if _, err := findESP([]partition{linux}); err == nil {
		t.Fatal("no ESP, no error")
	}
}

// The image is built with the target disk's logical sector size, so its GPT
// and the HD node count in those units, not in 512-byte sectors.
func TestPlanUses4KSectors(t *testing.T) {
	esp := partition{num: 1, start: 256, size: 16384, typ: espType, guid: guidOf(t, "00112233445566778899aabbccddeeff")}
	img := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(img, makeGPT(t, 4096, []partition{esp}), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlan(img, 4096, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := loadOption("Kairos", esp, `\EFI\BOOT\BOOTX64.EFI`)
	if !bytes.Equal(p.option, want) {
		t.Fatalf("option\n%x\nwant\n%x", p.option, want)
	}
	if _, err := NewPlan(img, 512, "amd64"); err == nil {
		t.Fatal("a 4K GPT read as 512-byte sectors was accepted")
	}
}

func TestOldDiskGPT(t *testing.T) {
	b, err := os.ReadFile("testdata/ubuntu-gpt.bin")
	if err != nil {
		t.Fatal(err)
	}
	d := readOldDisk(bytes.NewReader(b), 512)
	if len(d.guids) != 4 || d.guids[2] != ubuntuESP(t).guid || d.mbr != 0 {
		t.Fatalf("old disk %+v", d)
	}
}

func TestOldDiskMBR(t *testing.T) {
	b := make([]byte, 4096)
	b[510], b[511] = 0x55, 0xAA
	binary.LittleEndian.PutUint32(b[440:], 0xdeadbeef)
	b[446+4] = 0x83
	if d := readOldDisk(bytes.NewReader(b), 512); d.mbr != 0xdeadbeef || len(d.guids) != 0 {
		t.Fatalf("MBR disk read as %+v", d)
	}
	// A protective MBR without a readable GPT says nothing about partitions.
	b[446+4] = 0xEE
	if d := readOldDisk(bytes.NewReader(b), 512); d.mbr != 0 || len(d.guids) != 0 {
		t.Fatalf("protective MBR read as %+v", d)
	}
	b[446+4] = 0x83
	b[511] = 0
	if d := readOldDisk(bytes.NewReader(b), 512); d.mbr != 0 || len(d.guids) != 0 {
		t.Fatalf("sector without boot signature read as %+v", d)
	}
	if d := readOldDisk(bytes.NewReader(make([]byte, 4096)), 512); d.mbr != 0 || len(d.guids) != 0 {
		t.Fatalf("blank disk read as %+v", d)
	}
}

func TestESPNumber(t *testing.T) {
	if n, err := ESPNumber("testdata/ubuntu-gpt.bin", 512); err != nil || n != 15 {
		t.Errorf("ESP %d, %v; want partition 15", n, err)
	}
	linux := partition{num: 1, start: 34, size: 8, typ: guidOf(t, "af3dc60f838472478e793d69d8477de4")}
	img := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(img, makeGPT(t, 512, []partition{linux}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ESPNumber(img, 512); err == nil {
		t.Error("an image without an ESP has no ESP number")
	}
}
