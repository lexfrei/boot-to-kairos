# CI and releases

Every push and pull request is built, vetted, linted with golangci-lint and the repository's `.golangci.yml`, and tested with `-race`. It is also built and vetted for macOS, so a Linux-only import cannot break development there unnoticed. The tests that need root attach loop devices and create device-mapper devices. They run through `sudo` on the throwaway GitHub-hosted runner, and the job fails if any test is skipped.

An end-to-end job boots a throwaway Ubuntu VM with an active swap file on the runner's KVM, once with UEFI and once with legacy BIOS. First a dry run must pass and leave the start, the end and the partition table of the disk as they were. Then the job replaces the VM with Kairos, without carrying the identity over. It passes only if the machine comes back in active boot with the cloud-config's SSH key, and has applied none of the user-data on the VM's still attached NoCloud seed.

The identity carry-over is not booted in CI. The VM's own user would come back with it and hide an account the seed made. The runs under [Tested](tested.md) cover it. CI has no arm64 runner.

Once all of that passes, the same run builds the release binaries and checks that they are static and report their version. On a pushed `v*` tag it then publishes them as a GitHub release, so nothing is published that the run did not test.
