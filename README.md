# boot-to-kairos

boot-to-kairos turns a running Linux machine into [Kairos](https://kairos.io) from userspace. You don't need a rescue system or a custom ISO. The idea comes from [boot-to-talos](https://github.com/cozystack/boot-to-talos).

This is early work, tested on one setup only (see below). It erases the target disk.

## How it works

1. It pulls the Kairos OCI image and unpacks it into a tmpfs.
2. It attaches a sparse file the size of the target disk as a loop device and runs the image's own `kairos-agent manual-install` on it, from a chroot of the image. Commands the agent would run against the whole host, `blkdeactivate` and a reboot or poweroff asked for in the config, are replaced with ones that do nothing. You get what that image's installer would give you: active, passive and recovery systems, and a persistent partition over the rest of the disk.
3. Until this point the running system is not touched, with one exception: the agent runs `udevadm trigger`, which replays device events host-wide, so udev rules on the host run again and may, for example, activate an LVM volume group left inactive. Everything above runs in a mount namespace of its own, so nothing it mounts reaches the rest of the system, and all of it goes away once the installer and whatever it started have exited, however they exit.
4. It turns off the swap on the target disk, partitions and files alike, and freezes every filesystem on it, so nothing writes to the disk anymore. A filesystem that cannot be frozen, like the vfat ESP, is remounted read-only instead. If any of this fails, or the first write attempt fails before its first byte, what was done is undone and nothing is written.
5. It copies the file over the disk. Data is copied and holes are zeroed. Then it reads the disk back, bypassing the page cache, and writes again any page that differs. If that fails, it tries the whole write again, three attempts in all. The machine sits frozen while the whole disk is written and read back, which on a large HDD takes a long time. Do not reset it.
6. It flushes the filesystems on other disks, each on its own so the old ones on the target disk stay untouched, and reboots into Kairos.

## Requirements

- Root on a UEFI machine. Legacy BIOS is refused for now.
- Free RAM for the build. `quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0` needs about 1.8 GiB. The build uses what is available when it starts, less 512 MiB left to the rest of the system, and stops with an error before touching the disk if that is not enough.
- A Kairos image for the host's architecture that ships `kairos-agent`.
- A cloud-config that lets you log in to the installed system, for example a user with an SSH key.

## Usage

```bash
cat > config.yaml <<'EOF'
#cloud-config
users:
  - name: kairos
    groups: [admin]
    ssh_authorized_keys:
      - ssh-ed25519 AAAA... you@example.com
EOF

sudo ./boot-to-kairos \
  --image quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0 \
  --disk /dev/sda \
  --cloud-config config.yaml
```

`--disk` also takes a link like `/dev/disk/by-id/...`. Without `--yes` it asks you to type the disk path before it starts, and for a link that is the kernel name it resolves to, like `/dev/sda`.

## Tested

- Ubuntu 24.04 cloud image on QEMU with OVMF: UEFI, Secure Boot off, a 20 GiB virtio disk and an active swap file on the root filesystem. Target was Hadron v0.5.1 with Kairos v4.3.0. Kairos came up in active boot on the first reboot and accepted the SSH key from the cloud-config.

## Limitations

- The cloud-config's install-time stages run inside the build with the host's real devices visible. A stage that acts on the target disk acts on the running system, before anything is quiesced.
- No UEFI boot entry is created. Once the old system's entry stops resolving, the firmware has to fall back to `\EFI\BOOT\BOOTX64.EFI` on the disk. OVMF does that, some firmware may not.
- Secure Boot is not tested. The installed system boots the shim and GRUB from the image, so it depends on that image and on the keys your firmware trusts.
- Legacy BIOS is not supported yet.
- `--disk` must be a physical disk. An LVM volume, an md array or a loop device is refused: the firmware cannot boot from a disk image inside one.
- Some layouts are refused before anything is downloaded: any ZFS mount, because sysfs does not tell which disks a pool is on; a target disk under an md array, bcache or any device-mapper target other than linear, striped, crypt and multipath (LVM cache and thin pools, snapshots, RAID, integrity, VDO), because those may write to it on their own whatever is frozen; a filesystem on the target disk that is mounted only inside a container or another mount namespace; a process, such as a virtual machine, that has a device of the target disk open for writing; and any host partition already carrying a name or filesystem label kairos-agent will use (efi, oem, recovery, state, persistent, COS_*, and whatever the cloud-config's `install` section or the host's kernel command line adds), because the agent finds the partitions it formats and mounts by those, not on the disk it was given. Only namespaces that have a running process are seen; one kept open without a process, as snapd does, is not. A swap file whose size does not match what the kernel reports for it, which a swap header smaller than the file or a filesystem block smaller than a page can cause, is refused as possibly not the active one; recreate it with `mkswap` to proceed. A configuration the agent would fetch or merge from elsewhere, `config_url` in the cloud-config or `kairos.config`, `kairos.config_url`, `cos.setup` or `config_url` on the kernel command line, is refused too, as it cannot be checked: put it in the cloud-config itself.
