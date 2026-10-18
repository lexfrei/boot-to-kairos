# Dry run and JSON output

## Dry run

`--dry-run` does everything up to the point of no return and then stops without asking. That covers every check and refusal, the network capture, the memory checks, the image download, the full build of the disk image and the resolution of what the quiesce would stop. It prints the plan and leaves the disk, its swap, its filesystems and NVRAM alone. The exception is whatever the cloud-config's [install-time stages](cloud-config.md#install-time-stages) do. The agent's `udevadm trigger` also runs, as in a real run.

The plan shows each decision in the order the install made it:

- the progress endpoint, the image and the work dir;
- the network it would carry over, or why it carries none;
- the hostname, the SSH host keys by fingerprint, and the SSH users carried and left out;
- whether the cloud datasources are off;
- the target disk with its size and sector size;
- where the image came from, the digest of the manifest picked for this architecture, and the number and stored size of its layers;
- the signature it verified, or that it verified none;
- whether Secure Boot is on, and if so who signed each boot file and what trusts it, or why that could not be checked;
- how much of the disk image the build filled;
- the firmware mode, and the boot entry it would write or, on legacy BIOS, that there is none;
- the swap it would turn off and the filesystems it would freeze or remount read-only.

A passing dry run does not promise a passing real run. Three steps cannot be tried without the real install. Turning off swap pulls its pages back into the memory the build filled. A freeze or read-only remount can fail. A first write can fail before writing anything. The real run handles those as [How it works](how-it-works.md) step 4 describes.

## JSON output

With `--output json`, stdout carries one JSON object and nothing else. Logs and the confirmation prompt go to stderr. A dry run prints the object at the end. A real run prints it right before the point of no return, or at the refusal if it stops earlier, and its `passed` covers the checks up to that point. Past the point of no return stdout may be a file on the frozen disk. From there on only stderr, the kernel log (`/dev/kmsg`) and the [progress endpoint](progress-report.md) get output.

```json
{"dryRun":true,"passed":true,"plan":[{"name":"image","value":"quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0"},{"name":"swap to turn off","values":["/swap.img"]}],"refusal":null}
```

`plan` lists the items in the order of the text output. An item has `value`, or `values` when it is a list. `refusal` is `null` when every check passed, and otherwise has a `class` and a `message`.

Some errors happen before the installer starts and print no object: flags it cannot parse, not running as root, and a failure to set up its mount namespace.

## Refusal classes

| Class | Refused for |
| --- | --- |
| `usage` | a flag that is missing, invalid or conflicts with another |
| `not-whole-disk` | `--disk` that is a partition, a virtual block device or not a block device |
| `bad-config` | the [cloud-config](cloud-config.md#refused-cloud-configs) |
| `bios-unsupported` | [legacy BIOS](uefi-and-bios.md#legacy-bios) off x86-64, or legacy BIOS on a disk without 512-byte sectors |
| `label-clash` | a host partition named like one kairos-agent uses ([Limitations](limitations.md)) |
| `aborted` | a confirmation that was not given |
| `not-enough-memory` | too little [RAM](requirements.md#memory) |
| `not-enough-space` | a [`--workdir`](workdir.md#free-space) that is too full |
| `bad-workdir` | a [`--workdir`](workdir.md#refused-work-dirs) that is refused |
| `secure-boot` | a [boot chain](uefi-and-bios.md#secure-boot) Secure Boot would refuse, or Secure Boot lists that cannot be read or parsed |
| `already-running` | another instance holding `/run/boot-to-kairos.lock` |
| `disk-in-use` | a use of the target disk the quiesce cannot stop ([Limitations](limitations.md)) |
| `network-unsupported` | a [network](network.md#refusals) that cannot be carried over |
| `no-login` | no way to log in to the installed system ([Identity](identity.md#users)) |
| `account-clash` | a carried user whose name the image uses ([Identity](identity.md#users)) |
| `interrupted` | a run stopped by SIGINT, SIGTERM or SIGHUP |
| `bad-image` | an [image](image-and-signature.md#checks) with none for this architecture, a digest mismatch, a descriptor naming a sha512 digest, more than one candidate in a layout, a legacy `docker save` archive or a redirect to plain http; or an [EFI system partition UEFI cannot read](uefi-and-bios.md#4096-byte-sectors-on-uefi) |
| `no-signature` | an [image without a signature](image-and-signature.md#signature) |
| `bad-signature` | a signature that does not verify or is not by the expected signer |
| `error` | anything else |

## Exit status

The exit status is the same in both output modes:

- 0: a dry run passed;
- 1: a dry run refused, or a real run refused or failed (a real run that succeeds reboots and never exits);
- 2: flags it cannot parse;
- 128 plus the signal number: the installer was killed by a signal.
