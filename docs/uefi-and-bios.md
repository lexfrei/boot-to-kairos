# UEFI and BIOS

## UEFI boot entry

Nothing in NVRAM changes unless the disk was written and read back without error. Then the installer writes a `Kairos` boot entry through efivarfs. The entry loads the image's shim, `\EFI\BOOT\BOOTX64.EFI`, from the new EFI system partition, which it names by partition GUID. On arm64 the file is `BOOTAA64.EFI`, on riscv64 `BOOTRISCV64.EFI`. An identical existing entry is reused.

- Entries that point at a partition of the replaced disk are removed, together with a `BootNext` that names one. A partition is recognised by its GPT partition GUID, or by the disk signature on MBR, both read before the write. A disk cloned from the target without new GUIDs or signature looks the same, and its entries go too. If NVRAM is full, the old entries are removed first.
- In `BootOrder` the new entry takes the place of whichever comes first, an old entry or the reused one. So a machine set to boot from the network first still does, when the old system had an entry of its own in `BootOrder`. Only when `BootOrder` named none of them does the new entry go first. Other entries keep their order.
- The build cannot write an entry early. Inside its chroot, efivarfs and `/sys/firmware/efi/vars` are covered by an empty read-only tmpfs, so an entry written by kairos-agent or a cloud-config stage fails. A stage that mounts them again on its own is not stopped.
- If writing the entry fails, the error is logged and the machine still reboots. The firmware then has to fall back to the same loader under `\EFI\BOOT`, as OVMF does and some firmware may not.
- Without efivarfs mounted read-write at `/sys/firmware/efi/efivars` no entry is written, and a warning says so before the disk is touched.

## Legacy BIOS

Legacy BIOS is supported on x86-64 only. It gets no boot entry and no Secure Boot check. A target disk whose logical sectors are not 512 bytes is refused with `bios-unsupported`, because legacy firmware commonly cannot boot from one. SeaBIOS does not even list such a disk.

## 4096-byte sectors on UEFI

A target disk with 4096-byte logical sectors gets an EFI system partition that most UEFI firmware cannot read, as long as the image's `kairos-agent` formats it the way v4.3.0 does. It makes a 64 MiB FAT32 partition, which on such a disk has fewer than the 65525 clusters FAT32 must have. Linux mounts it anyway, but EDK2's FAT driver refuses it, and OVMF and most UEFI firmware carry that driver.

So once the disk image is built, the installer counts the partition's clusters the way EDK2 does and refuses with `bad-image` before the disk is touched. An image whose installer gets this right is not refused. Setting `install.partitions.efi.size: 260` does not help: `mkfs.vfat` then picks 32 KiB clusters and ends up with 8317. Reaching 65525 would take about 2 GiB, which has not been tried.

## Secure Boot

With Secure Boot on, the image's boot chain must be one this firmware trusts. Once the disk image is built, the installer reads three files from it: the fallback loader `\EFI\BOOT\BOOTX64.EFI` (`BOOTAA64.EFI` on arm64), the GRUB beside it when that loader is shim, and `/boot/vmlinuz`. It looks up each file's Authenticode hash and signing certificates in the firmware's db and dbx. It also checks the shim's vendor certificate and deauthorized list, and the `MokListRT` and `MokListXRT` that the running system's shim left.

- If the firmware or shim would refuse one of the files, the install stops with `secure-boot` before the disk is touched, naming the file and the reason. It stops the same way when Secure Boot is on and the lists cannot be read through efivarfs or do not parse.
- `quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0` is refused, as its shim, GRUB and kernel are unsigned. An image built with kairos-init from Ubuntu passes on firmware with Microsoft's keys. It carries Ubuntu's shim, signed by Microsoft, and a GRUB and kernel signed by Canonical.
- Keys cannot be enrolled from the running system, because MOK enrollment needs a reboot and a confirmation at the console. Use an image signed for this firmware, or turn Secure Boot off.
- Without efivarfs the variables are read from `/sys/firmware/efi/vars`. That interface returns at most 1024 bytes of a variable, which is usually less than db and dbx. Then Secure Boot may be found on with its lists unreadable, and the install goes ahead without the check, with a warning to mount efivarfs. On a UEFI machine without either interface it goes ahead with a warning too.

The check has known gaps:

- It looks at who signed a binary, not at whether the signature covers the binary's hash. A binary changed after signing passes here and is refused at boot.
- It does not read SBAT revocation levels.
- It does not see `mokutil --disable-validation`, which boots a GRUB or kernel the check refuses, or `mokutil --ignore-db`, which refuses one the check lets through db.
- `MokListRT` also carries the vendor certificates of the shim the running system booted through. The installed shim may not trust them, so a GRUB or kernel signed only by one of those passes here and is refused at boot.
- Only the default boot path is checked.

A certificate in db or `MokListRT` that cannot be parsed is skipped with a warning. One in a list that revokes stops the install.
