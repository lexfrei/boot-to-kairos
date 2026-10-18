# boot-to-kairos

[![CI](https://github.com/lexfrei/boot-to-kairos/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/lexfrei/boot-to-kairos/actions/workflows/ci.yaml?query=branch%3Amain)
[![Release](https://img.shields.io/github/v/release/lexfrei/boot-to-kairos)](https://github.com/lexfrei/boot-to-kairos/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/lexfrei/boot-to-kairos)](go.mod)
[![License](https://img.shields.io/github/license/lexfrei/boot-to-kairos)](LICENSE)

boot-to-kairos turns a running Linux machine into [Kairos](https://kairos.io) from userspace. You don't need a rescue system or a custom ISO. The idea comes from [boot-to-talos](https://github.com/cozystack/boot-to-talos).

This is early work, tested on a few setups only (see [Tested](docs/tested.md)). It erases the target disk.

## How it differs from existing tools

Kairos's own install paths boot its live ISO, run from a rescue system with Docker or from MAAS's ephemeral environment, start a cloud instance from a Kairos image, or upgrade a Kairos that already runs. kairos-init builds the image, and AuroraBoot turns it into boot media or serves it for netboot. boot-to-kairos starts from the Linux the machine already runs, over SSH, and carries its network configuration, SSH users, host keys and hostname over. It checks the signature, the firmware and the Secure Boot trust before the disk is touched, and `--dry-run` stops right before that point. [boot-to-talos](https://github.com/cozystack/boot-to-talos) installs Talos from a running Linux too, carrying the default-route interface's address and gateway as kernel `ip=` arguments. For NixOS, [nixos-infect](https://github.com/elitak/nixos-infect) installs over the running system's root filesystem and [nixos-anywhere](https://github.com/nix-community/nixos-anywhere) kexecs into an installer over SSH. Sources and details: [Comparison](docs/comparison.md).

## How it works

1. It verifies the image's cosign signature, then downloads the image and unpacks it into a tmpfs, checking every layer's digest.
2. It builds a disk image the size of the target disk with the image's own `kairos-agent manual-install`, in a mount namespace of its own.
3. Up to here the running system is untouched, except for the agent's host-wide `udevadm trigger`.
4. It turns off swap and freezes the filesystems on the target disk. If that fails, what was done is undone and nothing is written.
5. It writes the disk image over the disk and reads it back, in up to three attempts.
6. It flushes the other disks, writes a boot entry on UEFI, and reboots through the firmware into Kairos.

Details: [How it works](docs/how-it-works.md).

## Requirements

- Root, on UEFI or on x86-64 with legacy BIOS. Kairos is installed for the mode the system booted in.
- A Kairos image for the host's architecture that ships `kairos-agent`.
- About 2.6 GiB of available RAM for `quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0`, or about 1.1 GiB with `--workdir` on another disk.
- With Secure Boot on, an image whose boot chain the firmware trusts. That Hadron image is refused.
- A way to log in afterwards: SSH logins carried over from this system, or a cloud-config that sets one up.

Details: [Requirements](docs/requirements.md), [UEFI and BIOS](docs/uefi-and-bios.md).

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
    lock_passwd: true
    ssh_authorized_keys:
      - ssh-ed25519 AAAA... you@example.com
EOF

sudo ./boot-to-kairos \
  --image quay.io/kairos/hadron:v0.5.1-core-amd64-generic-v4.3.0 \
  --disk /dev/sda \
  --cloud-config config.yaml
```

On arm64 use `quay.io/kairos/hadron:v0.5.1-core-arm64-generic-v4.3.0`. Add `--dry-run` to run every check and the full build, then stop before the disk, swap, filesystems and NVRAM are touched. The cloud-config's install-time stages still run, and a passing dry run does not promise a passing real run (see [Dry run](docs/dry-run-and-json-output.md)).

`--disk` also takes a link like `/dev/disk/by-id/...`. Without `--yes` it asks you to type the disk path, for a link the kernel name it resolves to, like `/dev/sda`. A second instance refuses while one holds `/run/boot-to-kairos.lock`.

| Flag | Meaning |
| --- | --- |
| `--image REF` | Kairos image: a registry reference, `oci:DIR` or `oci-archive:FILE` ([Image and signature](docs/image-and-signature.md)) |
| `--disk DEV` | whole disk to replace; all data on it is erased |
| `--cloud-config FILE` | cloud-config for the installed system; optional while an admin login is carried over ([Cloud-config](docs/cloud-config.md)) |
| `--yes` | do not ask for confirmation |
| `--dry-run` | check and build everything, print the plan, stop before the point of no return ([Dry run](docs/dry-run-and-json-output.md)) |
| `--output text\|json` | `json` prints one JSON object with the plan and any refusal on stdout |
| `--workdir DIR` | build the disk image in a directory on another disk instead of RAM ([Work dir](docs/workdir.md)) |
| `--keep-network=false` | do not carry addresses, routes, DNS, bonds, VLANs and bridges over ([Network](docs/network.md)) |
| `--keep-identity=false` | do not carry SSH users and keys, host keys and hostname over ([Identity](docs/identity.md)) |
| `--report-url URL` | POST progress to an http or https endpoint until the reboot ([Progress report](docs/progress-report.md)) |
| `--report-ca FILE` | PEM CA certificates to trust for an https `--report-url` |
| `--verify-signature=false` | install without verifying the image's signature |
| `--signature-identity REGEX` | accept a signer other than Kairos whose certificate identity matches; needs `--signature-issuer` |
| `--signature-issuer URL` | OIDC issuer the signing certificate must name; needs `--signature-identity` |
| `--trusted-root FILE` | Sigstore `trusted_root.json`, for a machine that cannot reach Sigstore's TUF repository |
| `--insecure-registry` | allow plain http to a registry that is not at a loopback address |
| `--version` | print the version and exit |

## Documentation

- [How it works](docs/how-it-works.md): the install step by step, and what happens on failure at each step.
- [Requirements](docs/requirements.md): firmware, image and login requirements, and the memory budget.
- [UEFI and BIOS](docs/uefi-and-bios.md): the boot entry, legacy BIOS, sector sizes and the Secure Boot check.
- [Image and signature](docs/image-and-signature.md): image sources, digest checks, downloads and signature verification.
- [Network](docs/network.md): what network configuration is carried over and what is refused.
- [Identity](docs/identity.md): which SSH users, keys, host keys and hostname are carried over.
- [Cloud-config](docs/cloud-config.md): passwords, cloud datasources, install-time stages and refused cloud-configs.
- [Work dir](docs/workdir.md): building on another disk, refused work dirs and free space.
- [Dry run and JSON output](docs/dry-run-and-json-output.md): the plan, the JSON object, refusal classes and exit status.
- [Progress report](docs/progress-report.md): the report format, phases and delivery.
- [Limitations](docs/limitations.md): disk and host layouts that are refused.
- [Tested](docs/tested.md): configurations tested and their outcomes.
- [CI and releases](docs/ci-and-releases.md): what CI checks and how releases are published.
- [Comparison](docs/comparison.md): how Kairos's own installers, boot-to-talos, nixos-infect and nixos-anywhere differ, with sources.

## License

Apache-2.0, see [LICENSE](LICENSE).
