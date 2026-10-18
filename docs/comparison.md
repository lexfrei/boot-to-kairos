# How it differs from existing tools

These tools differ in what the machine has to run first: a rescue system, a provisioning environment such as MAAS's, live media, the target system itself, or the Linux it already runs. The tables follow each tool's own documentation or source and leave out what those do not describe.

## Kairos's own paths

| Path | What it does | What the machine needs |
| --- | --- | --- |
| [kairos-init](https://github.com/kairos-io/kairos/tree/master/kairos-init), the [Kairos Factory](https://kairos.io/docs/reference/kairos-factory/) | Turns a distribution's container image into a Kairos image inside a Dockerfile. | Nothing: it runs at build time and installs no machine. |
| [AuroraBoot](https://kairos.io/docs/reference/auroraboot/) | Builds ISO, RAW and cloud images from a Kairos image and serves them for netboot. | To boot that media, or to netboot from the same network segment as the host running AuroraBoot. |
| Kairos ISO: [web installer](https://kairos.io/quickstart/), [interactive install](https://kairos.io/docs/installation/interactive/) | Installs from the booted live ISO. | To boot the ISO: a console, virtual media or a USB stick. |
| [Manual install](https://kairos.io/docs/installation/manual/) | Runs `kairos-agent manual-install` with a cloud-config. The page does not say what system it runs from. | A system that has `kairos-agent`. |
| [MAAS](https://kairos.io/docs/installation/maas/), cloud images such as [AWS](https://kairos.io/docs/installation/aws/) | MAAS writes an AuroraBoot raw image to the disk from its ephemeral environment. On AWS an instance is created from a Kairos AMI. | A machine that MAAS manages, or a new cloud instance. |
| [Takeover](https://kairos.io/docs/installation/takeover/) | Runs `kairos-agent manual-install` from the Kairos image in a privileged Docker container. | The documented steps boot the provider's rescue system, install Docker in it, and switch the boot back to the disk afterwards. |
| [`kairos-agent upgrade`](https://kairos.io/docs/upgrade/manual/) | Upgrades the active Kairos system to another image. | Kairos, installed and running. |

None of these pages describes installing over a non-Kairos system from that system itself. The takeover page does not mention network or SSH users: its login comes from the cloud-config.

## Other ecosystems

| Tool | What it does | What it carries over |
| --- | --- | --- |
| [boot-to-talos](https://github.com/cozystack/boot-to-talos) | From a running Linux, copies a Talos disk image over the disk, built by the Talos installer or given as a RAW image, with an `fsync` after each chunk, and reboots through sysrq. Its boot mode kexecs the Talos kernel instead. It warns when Secure Boot is on; install needs Secure Boot off. | The default-route interface's address, netmask and gateway as kernel `ip=` and `vlan=` arguments. |
| [nixos-infect](https://github.com/elitak/nixos-infect) | From a running Linux, installs NixOS over the root filesystem and reboots. Its README says a failure leaves the system in an inconsistent state. | The hostname, SSH authorized keys as root's, the SSH host keys and `/etc/resolv.conf`. With `doNetConf=y`, which the script sets itself for some providers, also a generated network configuration ([script](https://github.com/elitak/nixos-infect/blob/master/nixos-infect)). |
| [nixos-anywhere](https://github.com/nix-community/nixos-anywhere) | Connects over SSH from a machine with Nix, kexecs the target into a NixOS installer, partitions with disko and installs. | What the Nix configuration declares, and the SSH host keys with [`--copy-host-keys`](https://github.com/nix-community/nixos-anywhere/blob/main/docs/cli.md). |

## What boot-to-kairos does

It runs on the Linux the machine already runs, so SSH is enough and no console, live media, rescue system, kexec or second machine is needed. The exception is Secure Boot with an image the firmware does not trust: turning Secure Boot off takes the firmware setup, a console or a BMC. It writes a whole disk image, so everything on the target disk is erased.

- The network configuration of the running system is carried over: addresses, routes, MTUs, bonds, VLANs, bridges and DNS ([Network](network.md)).
- SSH users and their keys, the SSH host keys and the hostname are carried over ([Identity](identity.md)).
- Before the disk is touched it checks the image signature, the firmware mode, the EFI system partition the firmware has to read, and on Secure Boot whether the firmware trusts the image's boot chain ([UEFI and BIOS](uefi-and-bios.md)).
- The disk is read back after the write, and the UEFI boot entry is written only after that read-back passes ([How it works](how-it-works.md)).
- `--dry-run` runs every check and the full build, prints the plan and stops before the point of no return ([Dry run](dry-run-and-json-output.md)).
