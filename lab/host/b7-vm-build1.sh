#!/usr/bin/env bash
# b7: unattended install of build1 from the local DVD, then start it (snapshot "golden" is taken from the Mac after checks).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
KS=/tmp/lab-host/build1.ks; ISO=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso
DISK=/data/libvirt/images/build1.qcow2; LOG=/var/log/libvirt/qemu/build1-install.log
[[ -f $KS ]] || die "missing $KS (run via push.sh)"
if virsh dominfo build1 >/dev/null 2>&1; then log "build1 already exists"; exit 0; fi
(( CHECK )) && { log "[check] would: virt-install build1 (12 vCPU, 16 GB, 80 GB) from $ISO with $KS; serial log $LOG"; exit 0; }
run "install build1 (unattended; serial console logged to $LOG)" \
  virt-install --name build1 --memory 16384 --vcpus 12 --cpu host-passthrough \
    --osinfo detect=on,name=rhel9-unknown \
    --disk path="$DISK",size=80,format=qcow2 \
    --location "$ISO" --network bridge=br-lab \
    --initrd-inject "$KS" \
    --extra-args "inst.ks=file:/build1.ks fips=1 console=ttyS0,115200 inst.text" \
    --graphics none --serial file,path="$LOG" \
    --noautoconsole --noreboot --wait 90
state=$(virsh domstate build1)
[[ $state == "shut off" ]] || die "install did not finish in 90 min (state: $state); see $LOG"
grep -qiE 'kernel panic|traceback|an error occurred' "$LOG" && die "installer reported an error; see $LOG"
run "start build1" virsh start build1
log "b7 done: install finished, build1 starting"
