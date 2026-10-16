# boot-to-kairos

boot-to-kairos turns a running Linux machine into [Kairos](https://kairos.io) from userspace. You don't need a rescue system or a custom ISO. The idea comes from [boot-to-talos](https://github.com/cozystack/boot-to-talos).

This is early work, tested on one setup only (see below). It erases the target disk.

## How it works

1. It pulls the Kairos OCI image and unpacks it into a tmpfs.
2. It attaches a sparse file the size of the target disk as a loop device and runs the image's own `kairos-agent manual-install` on it, from a chroot of the image. Commands the agent would run against the whole host, `blkdeactivate` and a reboot or poweroff asked for in the config, are replaced with ones that do nothing. You get what that image's installer would give you: active, passive and recovery systems, and a persistent partition over the rest of the disk.
3. Until this point the running system is not touched, with one exception: the agent runs `udevadm trigger`, which replays device events host-wide, so udev rules on the host run again and may, for example, activate an LVM volume group left inactive. Everything above runs in a mount namespace of its own, so nothing it mounts reaches the rest of the system, and all of it goes away once the installer and whatever it started have exited, however they exit.
4. It turns off the swap on the target disk, partitions and files alike, and freezes every filesystem on it, so nothing writes to the disk anymore. A filesystem that cannot be frozen, like the vfat ESP, is remounted read-only instead. If any of this fails, or the first write attempt fails before its first byte, what was done is undone and nothing is written.
5. It copies the file over the disk. Data is copied and holes are zeroed. Then it reads the disk back, bypassing the page cache, and writes again any page that differs. If that fails, it tries the whole write again, three attempts in all. The machine sits frozen while the whole disk is written and read back, which on a large HDD takes a long time. Do not reset it.
6. It flushes the filesystems on other disks, each on its own so the old ones on the target disk stay untouched.
7. It writes a UEFI boot entry for Kairos, puts it in the boot order where the old system stood (see below), and reboots into Kairos.

## UEFI boot entry

Once the disk is written and verified, a boot entry named `Kairos` is written to the firmware's NVRAM through efivarfs. It loads `\EFI\BOOT\BOOTX64.EFI` (`BOOTAA64.EFI` on arm64, `BOOTRISCV64.EFI` on riscv64), the shim the image installs, from the new EFI system partition, which it names by the partition GUID in the new partition table. If an identical entry exists, it is reused.

Entries that point at a partition of the replaced disk are removed, together with a `BootNext` that names one: after the write those partitions are gone. A partition is recognised by its GPT partition GUID, or by the disk signature on an MBR disk, both read before the disk is overwritten. Another disk cloned from the target without new GUIDs or signature looks the same, and its entries go too; the firmware cannot tell such disks apart either. If the NVRAM is full, the old entries are removed first to make room.

In `BootOrder` the new entry takes the place of whichever comes first, an old entry or the reused one, so the firmware does not have to fall back to the disk's default loader on its own, and a machine set to boot from the network first, as provisioning systems do, still does when the old system had an entry of its own. Only when `BootOrder` named none of them does the new entry go first. Entries for other disks, network boot and the firmware's own entries keep their order.

Nothing in NVRAM changes unless the disk was written and read back without error. The build does not see the firmware's variables at all: inside its chroot efivarfs, and the older sysfs interface at `/sys/firmware/efi/vars` that kernels before 6.0 also offer, are covered by an empty read-only tmpfs, so a boot entry written by kairos-agent or a cloud-config stage fails instead of reaching NVRAM before the disk is verified. A stage that mounts efivarfs or sysfs again on its own is not stopped. If writing the entry fails after that, the error is logged, the machine still reboots, and the firmware has to fall back to `\EFI\BOOT\BOOTX64.EFI` on the disk, as OVMF does and some firmware may not. Without efivarfs mounted read-write at `/sys/firmware/efi/efivars` no entry is written, and a warning says so before the disk is touched.

## Requirements

- Root on a UEFI machine. Legacy BIOS is refused for now.
- Free RAM for the build. `quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0` needs about 1.8 GiB. The build uses what is available when it starts, less 512 MiB left to the rest of the system, and stops with an error before touching the disk if that is not enough.
- A Kairos image for the host's architecture that ships `kairos-agent`.
- A cloud-config that lets you log in to the installed system, for example a user with an SSH key.

## Install

Each release has static binaries for linux/amd64 and linux/arm64 and a `SHA256SUMS` file. Replace `vX.Y.Z` with the release you want:

```bash
VERSION=vX.Y.Z
ARCH=amd64 # or arm64
curl --fail --location --remote-name-all \
  "https://github.com/lexfrei/boot-to-kairos/releases/download/$VERSION/boot-to-kairos-linux-$ARCH" \
  "https://github.com/lexfrei/boot-to-kairos/releases/download/$VERSION/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
chmod +x "boot-to-kairos-linux-$ARCH"
mv "boot-to-kairos-linux-$ARCH" boot-to-kairos
./boot-to-kairos --version
```

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

## Network

Kairos brings every Ethernet NIC up with DHCP by default. A machine reachable only at a static address, or only through a bond, a VLAN or a bridge, would not come back on the network after the reboot, so boot-to-kairos carries the running system's network configuration over, unless you pass `--keep-network=false`.

It reads the configuration from the kernel, not from the old system's configuration files: addresses, routes, MTUs, bonds, VLANs and bridges, and the nameservers and search domains from `/etc/resolv.conf` (or, behind systemd-resolved's local stub, from the upstream list resolved keeps in `/run/systemd/resolve/resolv.conf`). It adds a stage to the cloud-config that writes systemd-networkd files on every boot, as Kairos writes its own default configuration, so the configuration survives upgrades. NICs are found by their burnt-in MAC address, so it does not matter that Kairos names them differently.

- An address without a lifetime is written as static, unless a DHCP client owns it. An address with a lifetime came from DHCP or SLAAC. So did an IPv4 address that a lease records: networkd's lease in `/run/systemd/netif/leases`, or, while a DHCP client is running, an unexpired NetworkManager, dhclient or dhcpcd lease under `/var/lib` for that very address. A lease file left from before the address was made static therefore does not count once its client is gone. A dhclient, dhcpcd or udhcpc running for a NIC with no lease to read owns all of the NIC's IPv4 addresses. A NIC with a lease keeps DHCP for IPv4, and router advertisements still configure IPv6. A client started without naming the NIC and without a lease file is not detected, and its addresses are written as static.
- Routes the system's network configuration set up (`proto boot` and `proto static`) in the main table are carried, source-specific ones with their source. On the carried interfaces, routes from a routing daemon, routes in other tables and routes of types other than unicast are not, and the installer names them; policy routing rules are not carried either. A default route from a routing daemon refuses the install, as without the daemon the installed system would be reachable from its own subnets only: configure such a host's network in the cloud-config. A prefix route that NetworkManager installs beside its addresses comes back with its metric. A `proto boot` route through the gateway of a DHCP lease, which dhclient-script and udhcpc install that way, is left to DHCP; where a DHCP client runs for an interface with no lease to read, so is every `proto boot` IPv4 route through a gateway on it, hand-added ones included, as the two look the same.
- A NIC that only uses DHCP, at the default MTU, outside any bond, VLAN or bridge, is left to Kairos's default configuration.
- Bonds, VLANs and bridges are recreated with their MAC addresses and with every parameter that differs from the kernel's default. A parameter systemd-networkd cannot set refuses the install, with its name, rather than being dropped.
- Interfaces with no NIC under them, such as container bridges, VPN tunnels or a bridge's tap ports, are left out.
- Team devices, Open vSwitch, VRFs, macvlan, ipvlan, other tunnel devices bound to a NIC, Wi-Fi, and NICs that are not Ethernet are refused when a NIC is at or under them: nothing is written, and the error names the interface. So are multipath routes and routes over nexthop objects that the network configuration set up, bridges with VLAN filtering, VLAN priority maps and two NICs with the same MAC address.
- A virtual function its driver pairs with a NIC, as on Azure, is left to that driver: the NIC's file matches its driver as well as its MAC address, which the two share. Where the driver does not tell them apart either, as with virtio's net_failover, the install is refused.

If the cloud-config configures the network itself, writing files under `/etc/systemd/network/`, `/run/systemd/network/`, `/etc/systemd/resolved.conf*` or `/etc/resolv.conf`, setting `dns` in a stage, or passing `ip=` in `install.grub_options`, nothing is carried and the cloud-config's configuration applies alone. networkd uses the first file matching a NIC, so a carried file could silently override part of yours. What a stage's `commands` do is not checked.

## Tested

- Ubuntu 24.04 cloud image on QEMU with OVMF: UEFI, Secure Boot off, a 20 GiB virtio disk and an active swap file on the root filesystem. Target was Hadron v0.5.1 with Kairos v4.3.0. Kairos came up in active boot on the first reboot and accepted the SSH key from the cloud-config.
- The same, with the network carried over and DHCP off: one NIC at a static address, renamed `lan0` on Ubuntu, with an extra route, MTU 1400, a nameserver and a search domain; and an active-backup bond of two NICs at a static address. SSH reached the VM only at that static address, and Kairos came back there, the NIC found by its MAC under its new name, the bond with its mode, primary port and MII interval, and the routes, MTU and DNS in place.

## Limitations

- The cloud-config's install-time stages run inside the build with the host's real devices visible. A stage that acts on the target disk acts on the running system, before anything is quiesced.
- Secure Boot is not tested. The installed system boots the shim and GRUB from the image, so it depends on that image and on the keys your firmware trusts.
- Legacy BIOS is not supported yet.
- `--disk` must be a physical disk. An LVM volume, an md array or a loop device is refused: the firmware cannot boot from a disk image inside one.
- Some layouts are refused before anything is downloaded: any ZFS mount, because sysfs does not tell which disks a pool is on; a target disk under an md array, bcache or any device-mapper target other than linear, striped, crypt and multipath (LVM cache and thin pools, snapshots, RAID, integrity, VDO), because those may write to it on their own whatever is frozen; a filesystem on the target disk that is mounted only inside a container or another mount namespace; a process, such as a virtual machine, that has a device of the target disk open for writing; and any host partition already carrying a name or filesystem label kairos-agent will use (efi, oem, recovery, state, persistent, COS_*, and whatever the cloud-config's `install` section or the host's kernel command line adds), because the agent finds the partitions it formats and mounts by those, not on the disk it was given. Only namespaces that have a running process are seen; one kept open without a process, as snapd does, is not. A swap file whose size does not match what the kernel reports for it, which a swap header smaller than the file or a filesystem block smaller than a page can cause, is refused as possibly not the active one; recreate it with `mkswap` to proceed. A configuration the agent would fetch or merge from elsewhere, `config_url` in the cloud-config or `kairos.config`, `kairos.config_url`, `cos.setup` or `config_url` on the kernel command line, is refused too, as it cannot be checked: put it in the cloud-config itself.

## CI

Every push and pull request is built, vetted, linted with golangci-lint and the repository's `.golangci.yml`, and tested with `-race`. The tests that need root, which attach loop devices and create device-mapper devices, run through `sudo` on the throwaway GitHub-hosted runner, and the job fails if any test is skipped. An end-to-end job boots a throwaway Ubuntu UEFI VM with an active swap file on the runner's KVM, replaces it with Kairos and passes only if the machine comes back in active boot with the cloud-config's SSH key. Once all of that passes, the same run builds the release binaries and checks that they are static and report their version. On a pushed `v*` tag it then publishes them as a GitHub release, so nothing is published that the run did not test.
