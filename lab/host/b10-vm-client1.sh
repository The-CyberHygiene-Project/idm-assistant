#!/usr/bin/env bash
# b10: client1 = UEFI + Secure Boot (MS keys enrolled) + vTPM, 4 GB, 2 vCPU, 512 GB thin (PARTITIONS_3, CHP kit).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=vm-lib.sh
source "$(dirname "$0")/vm-lib.sh"; need_root
# The kickstart holds the LUKS passphrase: shred it on ANY exit (a failed install used to leave it behind).
trap '[[ -e /tmp/lab-host/client1.ks ]] && shred -u /tmp/lab-host/client1.ks' EXIT
create_vm client1 2 4096 512 /tmp/lab-host/client1.ks \
  --machine q35 --features smm.state=on \
  --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes \
  --tpm emulator,model=tpm-crb,version=2.0 \
  --check disk_size=off   # 512 GB thin disk (PARTITIONS_3); actual use stays small
log "b10 done"
