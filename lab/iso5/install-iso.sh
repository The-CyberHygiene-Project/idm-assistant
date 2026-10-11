#!/usr/bin/env bash
# install-iso.sh NAME MAC ENTRY STICK_IMG NDISKS ISO [--expect-stop] (RUNS ON AERO, sudo): install one iso5-* VM by
# BOOTING THE ISO, the way a person would: wait for our menu on the serial console, choose ENTRY with the keyboard
# (virsh send-key), and let the kickstart run. Firmware as in lab/iso2/install.sh: q35, UEFI Secure Boot with enrolled
# keys, vTPM; the stick is a removable USB disk. Afterwards the stick and the ISO are detached ("removed").
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
name=$1 mac=$2 entry=$3 stick=$4 ndisks=$5 iso=$6 expect_stop=${7:-}
[[ $name == iso5-* ]] || { echo "refusing: only iso5-* lab VMs are managed here"; exit 1; }
log=/var/log/libvirt/qemu/$name-install.log
rm_vm() { virsh destroy "$1" >/dev/null 2>&1 || true; virsh undefine "$1" --nvram >/dev/null 2>&1 || true; rm -f /data/libvirt/images/"$1"-[0-9].qcow2; }
if virsh dominfo "$name" >/dev/null 2>&1; then rm_vm "$name"; fi
rm -f "$log"
disks=(); for i in $(seq 1 "$ndisks"); do disks+=(--disk "path=/data/libvirt/images/$name-$i.qcow2,size=120,format=qcow2"); done
virt-install --name "$name" --memory 4096 --vcpus 2 --cpu host-passthrough --osinfo detect=on,name=rhel9-unknown \
  --machine q35 --features smm.state=on \
  --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes \
  --tpm emulator,model=tpm-crb,version=2.0 --check disk_size=off \
  "${disks[@]}" --disk "path=$stick,format=raw,bus=usb,removable=on" --cdrom "$iso" \
  --network "bridge=br-lab,mac=$mac" --graphics none --serial "pty,log.file=$log" \
  --noautoconsole --noreboot --wait 0 >"/tmp/iso2/$name-virt-install.out" 2>&1
# Our menu on the serial console (OVMF mirrors grub there), then the keyboard: ENTRY x Down, Enter.
for _ in $(seq 60); do grep -q "Boot from the local disk" "$log" 2>/dev/null && break; sleep 2; done
grep -q "Boot from the local disk" "$log" || { echo "MENU NOT SEEN in $log"; exit 1; }
sleep 2
for _ in $(seq 1 "$entry"); do virsh send-key "$name" KEY_DOWN >/dev/null; sleep 0.3; done
virsh send-key "$name" KEY_ENTER >/dev/null
for _ in $(seq 60); do grep -q "inst.ks=hd:LABEL=CHP-LAB-EL9" "$log" 2>/dev/null && break; sleep 2; done
grep -o -m1 "inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/[a-z]*.ks" "$log" | sed 's/^/BOOTED: /' || { echo "ENTRY NOT BOOTED"; exit 1; }
if [[ $expect_stop == --expect-stop ]]; then
  for _ in $(seq 120); do grep -q "CHP: install stopped" "$log" 2>/dev/null && break; sleep 5; done
  grep -q "CHP: install stopped" "$log" && echo "STOPPED: $(grep -m1 -o 'chp-site: .*' "$log" | tr -d '\r')" || echo "NOT STOPPED"
  virsh destroy "$name" >/dev/null 2>&1 || true
  for i in $(seq 1 "$ndisks"); do
    d=/data/libvirt/images/$name-$i.qcow2
    sz=$(qemu-img info --output=json "$d" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
    f=$(qemu-io -r -f qcow2 -c "read -P 0 0 1M" -c "read -P 0 $((sz - 1048576)) 1M" "$d" 2>&1 | grep -c "Pattern verification failed" || true)
    echo "disk $i zero-check-failures=$f"
  done
  rm_vm "$name"; exit 0
fi
for _ in $(seq 540); do [[ $(virsh domstate "$name" 2>/dev/null) == "shut off" ]] && break; sleep 10; done   # <= 90 min
state=$(virsh domstate "$name" 2>/dev/null || echo missing)
[[ $state == "shut off" ]] || { virsh destroy "$name" >/dev/null 2>&1 || true; echo "INSTALL DID NOT FINISH (state $state); see $log"; exit 1; }
virt-xml "$name" --remove-device --disk "path=$stick" >/dev/null
virt-xml "$name" --remove-device --disk device=cdrom >/dev/null 2>&1 || true
virsh dumpxml "$name" | grep -q "device='cdrom'" && { echo "cdrom still attached"; exit 1; }
virsh start "$name" >/dev/null
echo "INSTALLED and started $name (stick + ISO detached)"
