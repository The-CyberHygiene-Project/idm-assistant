#!/usr/bin/env bash
# create.sh (RUNS ON AERO, sudo): (re)build the chp-build RPM build VM from the Rocky 9.8 DVD (owner decision 4).
# Usage: sudo bash create.sh KS_FILE [--force]   (ks.cfg with @PUBKEY@ already replaced by the README's sed).
# Refuses if chp-build or its disk already exists; --force deletes both first (and says so). br-lab has no route out.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
ks=${1:?ks file}; name=chp-build; iso=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso
grep -q '@PUBKEY@' "$ks" && { echo "ks still has @PUBKEY@"; exit 1; }
log=/var/log/libvirt/qemu/$name-install.log; rm -f "$log"
img=/data/libvirt/images/$name.qcow2
if virsh dominfo "$name" >/dev/null 2>&1 || [[ -e $img ]]; then
  [[ ${2:-} == --force ]] || { echo "refusing: $name (domain and/or $img) already exists; re-run with --force to DELETE and rebuild it"; exit 1; }
  echo "--force: destroying domain $name (if any), undefining it with its NVRAM, and deleting $img"
fi
if virsh dominfo "$name" >/dev/null 2>&1; then virsh destroy "$name" >/dev/null 2>&1 || true; virsh undefine "$name" --nvram >/dev/null 2>&1 || true; fi
rm -f /data/libvirt/images/$name.qcow2
virt-install --name "$name" --memory 4096 --vcpus 2 --cpu host-passthrough --osinfo detect=on,name=rhel9-unknown \
  --disk path=/data/libvirt/images/$name.qcow2,size=60,format=qcow2 --network bridge=br-lab,mac=52:54:00:c4:05:60 \
  --location "$iso" --initrd-inject "$ks" --extra-args "inst.ks=file:/$(basename "$ks") inst.text console=ttyS0,115200" \
  --graphics none --serial "pty,log.file=$log" --noautoconsole --noreboot --wait 0
for _ in $(seq 180); do [[ $(virsh domstate "$name") == "shut off" ]] && break; sleep 10; done
[[ $(virsh domstate "$name") == "shut off" ]] || { echo "INSTALL DID NOT FINISH; see $log"; exit 1; }
virt-xml "$name" --remove-device --disk device=cdrom >/dev/null 2>&1 || true
virsh autostart "$name" >/dev/null; virsh start "$name" >/dev/null
echo "INSTALLED and started $name; ssh alias: chp-build (lab/build-vm/ssh_config), 192.168.100.60"
