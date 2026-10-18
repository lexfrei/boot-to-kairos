# Cloud-config

`--cloud-config` gives the configuration for the installed system. The file must start with `#cloud-config`. It is optional while an admin login is carried over (see [Identity](identity.md)). What it sets takes precedence over the carried [network](network.md#when-the-cloud-config-configures-the-network) and [identity](identity.md#what-the-cloud-config-overrides).

## Passwords

A user the cloud-config creates without `passwd` or `lock_passwd: true` gets an empty password. The console accepts it, as the image's PAM allows empty passwords, while sshd does not. The image's `kairos` user keeps its locked password.

## Cloud datasources

The image looks for user-data the way cloud-init does, on every boot until it finds some. It checks a NoCloud seed (`cidata`), a config drive, and the metadata services of the major clouds and of MAAS. What it finds goes to `/oem/95_userdata` and is applied on every boot after. On a cloud VM or a provisioned machine, that is the user-data written for the replaced system, and it can create users with an empty password.

So the install creates `/oem/95_userdata` empty, which stops the image from looking. To keep the lookup, declare a stage with a `datasource` and the providers you want, or a stage that writes under `/oem/95_userdata`. The plan says which applies.

## Install-time stages

The cloud-config's install-time stages run inside the build with the host's real devices visible. A stage that acts on the target disk acts on the running system, before anything is quiesced. This happens in a dry run too.

## Refused cloud-configs

These are refused with `bad-config` before anything is downloaded:

- a cloud-config that does not parse or is not a mapping;
- content in more than one YAML document, as the agent reads only the first;
- `install.firmware` set to a mode other than the one the system booted in, as the installed system would not boot;
- `install` spelled any other way, a dotted `install.` key at the top level, or a key under `install` that is not lowercase or holds a dot;
- a `config_url`, which the agent would fetch and merge, and which cannot be checked (put that configuration in the cloud-config itself).

The `install` rule exists because the agent adds an `install` section of its own and reads the result through a parser that nests dotted keys. When two keys differ only in case, that parser keeps one of them at random.

Partition names in the `install` section also count for the [label clash check](limitations.md).
