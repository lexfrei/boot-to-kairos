# Identity

Kairos builds its users from the image on every boot, generates new SSH host keys on the first boot, and names itself `kairos-` plus four characters of its machine ID. So the install carries over who can log in over SSH, the SSH host keys and the hostname, unless you pass `--keep-identity=false`.

## Users

- A user is carried when its account is in `/etc/passwd`, its shell is not `nologin` or `false`, and it has keys in the files the host's sshd reads. Those files come from `AuthorizedKeysFile` in `sshd -T`, or are `.ssh/authorized_keys` and `.ssh/authorized_keys2` when that cannot be read.
- `Match` blocks are not evaluated. A file that only a `Match` block names is not read, and a `ForceCommand` or `ChrootDirectory` that a `Match` block sets does not come along.
- Keys from an `AuthorizedKeysCommand` are not carried, and the plan says so. Accounts that only LDAP or another NSS source knows are not seen.
- Each user comes back under the same name, with its key lines as they are, options included. Its password is locked, since passwords are not carried. Its shell is `/bin/bash`, and a user with a restricted shell such as `git-shell` or `rbash` is not carried at all.
- A user joins Kairos's `admin` group, whose members may use sudo without a password, when it was in `sudo`, `admin` or `wheel`, or when sudoers let it run a shell as root. Its other groups are not carried.
- To give a user a password, configure it in the cloud-config. Its keys then come from the cloud-config alone.
- The carried keys are added again on every boot. To revoke one, remove it from `/oem/90_custom.yaml`, not only from `~/.ssh/authorized_keys`.
- Kairos's sshd allows two authentication attempts per connection. A client that offers several keys before the right one gets "Too many authentication failures". Point it at the key with `-i` and `IdentitiesOnly yes`.

Root needs special handling, because Kairos's sshd refuses root logins. When no carried admin user can log in, root's keys go to the image's `kairos` user, in `admin`. The same key then works under another login name. When a carried admin user can log in, root's keys are not carried. A key with a forced command, like the "login as ubuntu" lines of cloud images, never moves. A host user named `kairos` is carried only when it could use sudo, as Kairos's `kairos` is always in `admin`.

Some keys and names are left out, and the plan names each one:

- key types Kairos's sshd does not accept: DSA and unknown types;
- lines Kairos would fetch as a URL;
- anything containing `{{` or `}}`, which yip renders as a template;
- names that are not lowercase POSIX user names, or that the image uses for a user or a group, `admin` included.

Names that an image other than Hadron uses are found once the build has unpacked it. The build then stops with `account-clash`.

Without `--cloud-config`, the install goes ahead only when a carried admin user has a key without a forced command. Otherwise it refuses with `no-login` before anything is built.

## Host keys and hostname

- The host keys are the ones the host's sshd uses (`HostKey`): RSA, ECDSA and ed25519, each with its `.pub`. Each is written at boot only where Kairos has no key of its type yet, so a key rotated later stays.
- Kairos's sshd offers only ed25519 and RSA host keys. A client that knows the host by its ECDSA key alone refuses the new system, and the installer warns about it.
- The fingerprints in the plan are read from the `.pub` files, which are not checked against the private keys.
- No host key is carried when a debug log would print it. That is `debug` in the cloud-config, or `debug`, `rd.kairos.debug` or `rd.immucore.debug` in its `install.grub_options`. This system's own kernel command line does not count.
- The hostname is the kernel's, unless it is empty or `localhost`.

The private host keys end up in two places. One is `/oem/90_custom.yaml` on the OEM partition, mode 0640, owner root, group `admin`. The other is `/etc/ssh` on the persistent partition, mode 0600. Neither is encrypted unless the cloud-config has Kairos encrypt those partitions. The plan, the JSON output and the log show fingerprints only. Booting the installed system with `rd.kairos.debug` added by hand writes the keys to its logs, as kairos-agent then logs its whole configuration.

## What the cloud-config overrides

What the cloud-config sets itself wins. A user it names in `users`, or in a stage's `users` or `authorized_keys`, is not carried. The hostname is not carried when it sets `hostname` or writes `/etc/hostname`. No host key is carried when it writes a file under `/etc/ssh/ssh_host_`.
