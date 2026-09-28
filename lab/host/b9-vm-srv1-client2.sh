#!/usr/bin/env bash
# b9: srv1 (4 vCPU, 6 GB, 60 GB) and client2 (2 vCPU, 2 GB, 30 GB + 2 GB LUKS test disk + software TPM 2.0).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=vm-lib.sh
source "$(dirname "$0")/vm-lib.sh"; need_root
if ! rpm -q swtpm swtpm-tools >/dev/null 2>&1; then
  run "install swtpm (software TPM for VMs) from the DVD" dnf -y -q install swtpm swtpm-tools
fi
create_vm srv1 4 6144 60 /tmp/lab-host/srv1.ks
create_vm client2 2 2048 30 /tmp/lab-host/client2.ks \
  --tpm emulator,model=tpm-crb,version=2.0 \
  --disk path=/data/libvirt/images/client2-luks.qcow2,size=2,format=qcow2
log "b9 done"
