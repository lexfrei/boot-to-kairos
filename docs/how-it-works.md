# How it works

The installer builds a complete Kairos disk image first and touches the target disk itself only at the end. The cloud-config's [install-time stages](cloud-config.md#install-time-stages) are an exception.

1. It verifies the image's signature before downloading any layer (see [Image and signature](image-and-signature.md)). Each layer is staged in a tmpfs or in [`--workdir`](workdir.md), checked against its digest, and only then unpacked.
2. It attaches a sparse file the size of the target disk as a loop device. Then it runs the image's own `kairos-agent manual-install` on it, chrooted into the image. `blkdeactivate` and any reboot or poweroff the config asks for are replaced with no-ops. The agent sees a blank kernel command line. The result is what that installer gives: active, passive and recovery systems, and a persistent partition over the rest of the disk.
3. Up to here the running system is not touched, with one exception. The agent runs `udevadm trigger`, which replays device events host-wide, so host udev rules run again and may, for example, activate an inactive LVM volume group. Everything runs in its own mount namespace, so nothing it mounts reaches the rest of the system. The namespace goes away once the installer and whatever it started have exited, however they exit.
4. It turns off swap on the target disk, partitions and files alike, and freezes every filesystem on it. A filesystem that cannot be frozen, like the vfat ESP, is remounted read-only. If any of this fails, or the first write fails before its first byte, what was done is undone and nothing is written. If the undo fails, it stops with a message that a filesystem may still be frozen and that you should reboot.
5. It writes the file over the disk, zeroing holes, and reads it back bypassing the page cache. Any page that differs is written again. A failed attempt is retried, three attempts in all. The machine stays frozen the whole time, which on a large HDD takes long. Do not reset it.
6. It flushes the filesystems on the other disks, each on its own, so the old ones on the target stay untouched.
7. On UEFI it writes a [boot entry](uefi-and-bios.md) and reboots.

It reboots through the firmware, not kexec. That way the first boot proves the firmware boots the disk the same way every later boot will. The price is one POST.
