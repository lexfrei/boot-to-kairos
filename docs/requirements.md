# Requirements

- Root on a UEFI machine, or on an x86-64 machine with legacy BIOS. Kairos is installed for the mode the system booted in. A UEFI machine booted in BIOS compatibility mode gets a legacy BIOS install and must stay in that mode. For Secure Boot see [UEFI and BIOS](uefi-and-bios.md#secure-boot).
- A Kairos image for the host's architecture that ships `kairos-agent`.
- A way to log in afterwards: SSH logins carried over from this system (see [Identity](identity.md)), or a cloud-config that sets one up.
- Enough free RAM, as below. A [work dir](workdir.md) on another disk needs less.

## Memory

The build may use the memory available when it starts, less 512 MiB left to the rest of the system. If that is not enough, it stops with `not-enough-memory` before touching the disk.

For `quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0` that is about 2.6 GiB. It adds up from the unpacked image, about 330 MiB plus 256 MiB headroom, the 1483 MiB disk image, the 64 MiB the build must leave free in the tmpfs (see [Work dir](workdir.md#free-space)) and the 512 MiB reserve. Installing it on a 6 GiB VM, Shmem peaked at 1.77 GiB for the whole build and at 377 MiB while unpacking. The arm64 image of the same release makes a 1624 MiB disk image.

Layers count against the same budget. Each one stays in the tmpfs as stored, compressed or not, until it is unpacked. A layer that would not fit beside what is already unpacked is refused before it is downloaded, and the unpacked image may then grow only into what the layer leaves. Some images are refused before anything is downloaded: those that would be refused this way even if no layer unpacked to more than its stored size and none replaced or deleted what an earlier one unpacked.

With `--workdir` only the unpacked image stays in RAM, with the same 256 MiB headroom. On the same VM Shmem peaked at 329 MiB, so about 1.1 GiB available is enough.
