# Work dir

A machine without enough RAM can build the disk image on another disk. `--workdir DIR` names an existing directory there. The build creates `DIR/boot-to-kairos` and keeps the disk image and each layer, until it is unpacked, in it. It removes that directory when it stops, whether it refused, failed or wrote the disk. After a write it does so before flushing the other disks.

A write that fails after touching the disk keeps the disk image, and the error says where it is. Writing it over the disk from rescue media finishes the install. The unpacked image stays in a tmpfs at `/run/boot-to-kairos`, and the lock stays at `/run/boot-to-kairos.lock`, with or without the flag. For `quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0` the disk image took 1483 MiB of `DIR`.

## Refused work dirs

The disk image is read from `DIR` while the target disk is frozen and written over. So `DIR` is refused with `bad-workdir`, before anything is downloaded, when:

- it is on the target disk: on one of its partitions, or on LVM, dm-crypt, md or btrfs with a device on it;
- its filesystem is served by a FUSE daemon, such as sshfs, but also ntfs-3g and exfat-fuse on a local disk;
- it is not on a local block device, as with NFS, CIFS, tmpfs and overlay, even with a reliable network;
- it is on a block device that may read over the network: nbd, rbd, iSCSI, ATA over Ethernet, DRBD, and NVMe whose controllers are not all PCIe;
- its devices include a loop device backed by a file, even a file on another disk, as where that file lives cannot be told;
- it does not keep sparse files, as vfat and exfat do not, or cannot hold a file the size of the disk;
- `DIR/boot-to-kairos` already exists. A run that did not finish left it, and it holds only that run's disk image and layers: remove it.

A SAN disk reached over Fibre Channel or SAS looks like a local SCSI disk and is accepted. A broken link to it during the write leaves the disk half written.

## Free space

The free space of `DIR` is checked before each layer is staged. Once the image is unpacked, it is checked again against an estimate of the disk image. The estimate is the active, passive and recovery images, each the unpacked image plus 100 MiB, then a journal of 1/128 of the persistent partition, between 64 MiB and 1 GiB, and 256 MiB for the rest.

A full `DIR` may not fail the agent, because the loop device writes the disk image back on its own. So a build that leaves less than 64 MiB free stops before the disk is touched. In `DIR` the class is `not-enough-space`. In the tmpfs, without `--workdir`, it is `not-enough-memory`.
