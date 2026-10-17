package efiboot

import (
	"encoding/binary"
	"os"

	"github.com/cockroachdb/errors"
)

// ErrESPUnreadable means the image's EFI system partition holds a FAT the
// firmware cannot read, so the installed disk would not boot.
var ErrESPUnreadable = errors.New("EFI system partition unreadable by the firmware")

// fat16MaxClusters is where FAT16 ends and FAT32 begins, counted in data
// clusters. The FAT specification tells the type by the count; EDK2 takes
// FAT32 from the boot sector and refuses a count on the wrong side.
const fat16MaxClusters = 65525

// CheckESP reads the boot sector of the image's EFI system partition, whose
// LBAs count in sectors of the given size, and fails when its cluster count
// does not fit the FAT type the boot sector gives, which EDK2 refuses.
// mkfs.vfat -F 32 on a small partition with 4096-byte sectors makes a FAT32
// with too few clusters: Linux mounts it, EDK2-based firmware does not see
// it at all. Fields EDK2 refuses that the count does not depend on, which
// mkfs.vfat does not write, are not checked.
func CheckESP(image string, sector int) error {
	esp, err := imageESP(image, sector)
	if err != nil {
		return err
	}
	f, err := os.Open(image)
	if err != nil {
		return errors.Wrap(err, "open image")
	}
	defer f.Close()
	bs := make([]byte, 512)
	if _, err := f.ReadAt(bs, int64(esp.start)*int64(sector)); err != nil {
		return errors.Wrap(err, "read the EFI system partition's boot sector")
	}
	return errors.Wrapf(checkFAT(bs), "partition %d", esp.num)
}

func checkFAT(bs []byte) error {
	sectorSize := uint32(binary.LittleEndian.Uint16(bs[11:]))
	perCluster := uint32(bs[13])
	reserved := uint32(binary.LittleEndian.Uint16(bs[14:]))
	fats := uint32(bs[16])
	rootEntries := uint32(binary.LittleEndian.Uint16(bs[17:]))
	sectors := uint32(binary.LittleEndian.Uint16(bs[19:]))
	if sectors == 0 {
		sectors = binary.LittleEndian.Uint32(bs[32:])
	}
	perFAT := uint32(binary.LittleEndian.Uint16(bs[22:]))
	fat32 := perFAT == 0
	if fat32 {
		perFAT = binary.LittleEndian.Uint32(bs[36:])
		rootEntries = 0
	}
	if sectorSize == 0 || perCluster == 0 || perCluster&(perCluster-1) != 0 || reserved == 0 || fats == 0 || sectors == 0 {
		return errors.Mark(errors.New("no FAT boot sector"), ErrESPUnreadable)
	}
	first := uint64(reserved) + uint64(fats)*uint64(perFAT) + (uint64(rootEntries)*32+uint64(sectorSize)-1)/uint64(sectorSize)
	if first >= uint64(sectors) {
		return errors.Mark(errors.New("its FAT leaves no room for data"), ErrESPUnreadable)
	}
	clusters := (uint64(sectors) - first) / uint64(perCluster)
	switch {
	case fat32 && clusters < fat16MaxClusters:
		return errors.Mark(errors.Newf("FAT32 with %d clusters, fewer than the %d the firmware needs", clusters, fat16MaxClusters), ErrESPUnreadable)
	case !fat32 && clusters >= fat16MaxClusters:
		return errors.Mark(errors.Newf("FAT12/16 with %d clusters, more than the %d it can have", clusters, fat16MaxClusters-1), ErrESPUnreadable)
	}
	return nil
}
