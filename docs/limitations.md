# Limitations

This page lists the disk and host layouts that are refused. Limits that belong to one topic are on that topic's page, linked at the end.

`--disk` must be a physical disk. An LVM volume, an md array or a loop device is refused, because the firmware cannot boot from a disk image inside one.

These layouts are refused before anything is downloaded:

- any ZFS mount, because sysfs does not tell which disks a pool is on;
- a target disk under an md array, bcache, or a device-mapper target other than linear, striped, crypt and multipath, such as LVM cache and thin pools, snapshots, RAID, integrity and VDO. Those may write to it on their own, whatever is frozen;
- a filesystem on the target disk that is mounted only inside a container or another mount namespace, with class `disk-in-use`;
- a process, such as a virtual machine, that has a device of the target disk open for writing, with class `disk-in-use`;
- a swap file whose size does not match what the kernel reports for it, with class `disk-in-use`;
- a host partition that carries a name or filesystem label kairos-agent may use, with class `label-clash`.

Only mount namespaces that have a running process are seen. One kept open without a process, as snapd does, is not.

A swap file size mismatch can come from a swap header smaller than the file, or from a filesystem block smaller than a page. Recreate the swap file with `mkswap` to proceed.

The names kairos-agent may use are efi, oem, recovery, state, persistent, COS_*, and whatever the cloud-config's `install` section names. The agent finds the partitions it formats and mounts by those names, not on the disk it was given.

Other limits:

- [Legacy BIOS sector sizes, 4096-byte sectors on UEFI, and the gaps of the Secure Boot check](uefi-and-bios.md)
- [Refused work dirs](workdir.md#refused-work-dirs)
- [Refused network setups](network.md#refusals)
- [Install-time stages and refused cloud-configs](cloud-config.md)
- [Image formats](image-and-signature.md#sources)
- [Users and keys that are not carried](identity.md)
