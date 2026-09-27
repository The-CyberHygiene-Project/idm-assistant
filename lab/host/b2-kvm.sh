#!/usr/bin/env bash
# b2: KVM/libvirt from the DVD.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
run "install virtualization packages" dnf -y install qemu-kvm libvirt virt-install qemu-img libvirt-client policycoreutils-python-utils
run "enable modular libvirt daemons" systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket
run "stop the default NAT network autostarting (lab uses br-lab only)" sh -c 'virsh net-autostart default --disable 2>/dev/null || true; virsh net-destroy default 2>/dev/null || true'
log "b2 done"
