#!/usr/bin/env bash
# Boots a throwaway Ubuntu UEFI VM, runs boot-to-kairos in it against its own
# disk, and checks that the machine comes back as Kairos in active boot.
# Usage: run.sh <boot-to-kairos binary> <Kairos image>
set -euo pipefail

bin=$(realpath "$1")
image=$2
work=${WORK:-$PWD/e2e-work}
mkdir -p "$work"
cd "$work"

opts=(-i id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=6)
vm() { ssh -n "${opts[@]}" -p 2222 "$@"; }
put() { scp -q "${opts[@]}" -P 2222 "$1" "ubuntu@127.0.0.1:$2"; }

wait_ssh() {
	local user=$1 tries=$2
	for _ in $(seq "$tries"); do
		vm "$user@127.0.0.1" true 2>/dev/null && return 0
		sleep 5
	done
	echo "no ssh as $user" >&2
	return 1
}

ssh-keygen -q -t ed25519 -N '' -C btk-e2e -f id_ed25519
curl --fail --silent --show-error --location --output noble.img \
	https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
qemu-img create -q -f qcow2 -b noble.img -F qcow2 disk.qcow2 20G
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
cat >user-data <<EOC
#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat id_ed25519.pub)
EOC
printf 'instance-id: btk-e2e\nlocal-hostname: btk-e2e\n' >meta-data
cloud-localds seed.img user-data meta-data

qemu-system-x86_64 -enable-kvm -machine q35 -cpu host -smp 4 -m 6144 \
	-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
	-drive if=pflash,format=raw,file=vars.fd \
	-drive file=disk.qcow2,if=virtio,format=qcow2,discard=unmap,detect-zeroes=unmap \
	-drive file=seed.img,if=virtio,format=raw \
	-netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
	-serial file:serial.log -display none -daemonize -pidfile qemu.pid
wait_ssh ubuntu 60

put "$bin" boot-to-kairos
cat >cfg.yaml <<EOC
#cloud-config
users:
  - name: kairos
    groups: [admin]
    ssh_authorized_keys:
      - $(cat id_ed25519.pub)
EOC
put cfg.yaml cfg.yaml
vm ubuntu@127.0.0.1 'sudo fallocate -l 512M /swap.img && sudo chmod 600 /swap.img && sudo mkswap -q /swap.img && sudo swapon /swap.img'

# ssh exits 255 when the reboot drops the connection; any other non-zero
# status is the installer failing before it got there.
rc=0
vm ubuntu@127.0.0.1 "sudo ./boot-to-kairos --image $(printf %q "$image") --disk /dev/vda --cloud-config cfg.yaml --yes" || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 255 ]; then
	echo "boot-to-kairos exited with $rc" >&2
	exit 1
fi

wait_ssh kairos 120
vm kairos@127.0.0.1 'grep -E "^KAIROS_(FLAVOR|VERSION)=" /etc/kairos-release'
vm kairos@127.0.0.1 'lsblk -o NAME,SIZE,LABEL /dev/vda'
state=$(vm kairos@127.0.0.1 'kairos-agent state get boot')
echo "boot state: $state"
test "$state" = active_boot
