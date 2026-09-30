#!/usr/bin/env bash
# install.sh (RUNS ON AERO, sudo): install one iso2-* test VM from the Rocky DVD + ROLE.ks + the OEMDRV stick image.
#   install.sh NAME MAC ROLE STICK_IMG NDISKS [--expect-stop]
# Files expected in /tmp/iso2: server.ks, client.ks, chp-site.pyz. Firmware as client1: q35, UEFI Secure Boot with
# enrolled keys, vTPM. The stick is a USB disk (removable). After a good install the stick is detached ("removed").
# --expect-stop: the install must STOP in %pre; waits up to 10 min for the CHP stop message, then reports whether every
# disk is still empty (qemu-img actual size < 2 MB) and removes the VM.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
name=$1 mac=$2 role=$3 stick=$4 ndisks=$5 expect_stop=${6:-}
[[ $name == iso2-* ]] || { echo "refusing: only iso2-* VMs are managed here"; exit 1; }
iso=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso; log=/var/log/libvirt/qemu/$name-install.log
# Remove a previous VM of this name and ONLY its own disks: --remove-all-storage would also delete the attached stick.
rm_vm() { virsh destroy "$1" >/dev/null 2>&1 || true; virsh undefine "$1" --nvram >/dev/null 2>&1 || true; rm -f /data/libvirt/images/"$1"-[0-9].qcow2; }
if virsh dominfo "$name" >/dev/null 2>&1; then rm_vm "$name"; fi
rm -f "$log"
disks=()
for i in $(seq 1 "$ndisks"); do disks+=(--disk "path=/data/libvirt/images/$name-$i.qcow2,size=120,format=qcow2"); done
wait_args=(--wait 90)
if [[ $expect_stop == --expect-stop ]]; then wait_args=(--wait 0); fi
virt-install --name "$name" --memory 4096 --vcpus 2 --cpu host-passthrough --osinfo detect=on,name=rhel9-unknown \
  --machine q35 --features smm.state=on \
  --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes \
  --tpm emulator,model=tpm-crb,version=2.0 --check disk_size=off \
  "${disks[@]}" --disk "path=$stick,format=raw,bus=usb,removable=on" \
  --location "$iso" --network "bridge=br-lab,mac=$mac" \
  --initrd-inject "/tmp/iso2/$role.ks" --initrd-inject /tmp/iso2/chp-site.pyz \
  --extra-args "inst.ks=file:/$role.ks chp.repo=http://192.168.100.1:8080/chp/0.2.0 fips=1 console=ttyS0,115200 inst.text" \
  --graphics none --serial "pty,log.file=$log" --noautoconsole --noreboot "${wait_args[@]}" >"/tmp/iso2/$name-virt-install.out" 2>&1 \
  || { echo "virt-install exited non-zero (checking the VM):"; tail -5 "/tmp/iso2/$name-virt-install.out"; }
if [[ $expect_stop == --expect-stop ]]; then
  for _ in $(seq 120); do if grep -q "CHP: install stopped" "$log" 2>/dev/null; then break; fi; sleep 5; done
  grep -q "CHP: install stopped" "$log" && echo "STOPPED: $(grep -m1 -o 'chp-site: .*' "$log" | tr -d '\r')" || echo "NOT STOPPED"
  virsh destroy "$name" >/dev/null 2>&1 || true
  # "untouched" = the first and the last MiB (MBR/GPT and the GPT backup) read back as zeros. (Counting allocated
  # extents does not work: libvirt preallocates qcow2 metadata, ~242 extents on a fresh 120 GB disk.)
  for i in $(seq 1 "$ndisks"); do
    d=/data/libvirt/images/$name-$i.qcow2
    sz=$(qemu-img info --output=json "$d" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
    f=$(qemu-io -r -f qcow2 -c "read -P 0 0 1M" -c "read -P 0 $((sz - 1048576)) 1M" "$d" 2>&1 | grep -c "Pattern verification failed" || true)
    echo "disk $i zero-check-failures=$f"
  done
  rm_vm "$name"
  exit 0
fi
state=$(virsh domstate "$name" 2>/dev/null || echo missing)
[[ $state == "shut off" ]] || { virsh destroy "$name" >/dev/null 2>&1 || true; echo "INSTALL DID NOT FINISH (state $state); see $log"; exit 1; }
virt-xml "$name" --remove-device --disk "path=$stick" >/dev/null
virsh start "$name" >/dev/null
echo "INSTALLED and started $name (stick detached)"
