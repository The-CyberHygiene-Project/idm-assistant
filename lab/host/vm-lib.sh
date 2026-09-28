# shellcheck shell=bash
# create_vm NAME VCPUS MEM_MB DISK_GB KS [extra virt-install args...]  (source lib.sh first)
create_vm() {
  local name=$1 vcpus=$2 mem=$3 disk=$4 ks=$5; shift 5
  local iso=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso img=/data/libvirt/images/$name.qcow2
  local logf=/var/log/libvirt/qemu/$name-install.log state
  [[ -f $ks ]] || die "missing $ks (run via push.sh)"
  if virsh dominfo "$name" >/dev/null 2>&1; then
    virsh snapshot-info "$name" golden >/dev/null 2>&1 \
      || die "$name exists but has no golden snapshot (half-built?); remove it: virsh undefine $name --remove-all-storage"
    log "$name already exists (golden snapshot present)"; return 0
  fi
  (( CHECK )) && { log "[check] would: virt-install $name ($vcpus vCPU, $mem MB, $disk GB) from $iso with $ks $*; serial log $logf"; return 0; }
  run "install $name (unattended; serial console logged to $logf)" \
    virt-install --name "$name" --memory "$mem" --vcpus "$vcpus" --cpu host-passthrough \
      --osinfo detect=on,name=rhel9-unknown \
      --disk path="$img",size="$disk",format=qcow2 \
      --location "$iso" --network bridge=br-lab \
      --initrd-inject "$ks" \
      --extra-args "inst.ks=file:/$(basename "$ks") fips=1 console=ttyS0,115200 inst.text" \
      --graphics none --serial pty,log.file="$logf" \
      --noautoconsole --noreboot --wait 90 "$@" \
    || log "virt-install exited non-zero (time limit or installer error); checking the VM"
  state=$(virsh domstate "$name" 2>/dev/null || echo missing)
  if [[ $state != "shut off" ]]; then
    virsh destroy "$name" >/dev/null 2>&1 || true
    die "$name install did not finish in 90 min (state: $state); see $logf. The stuck VM was stopped; remove it: virsh undefine $name --remove-all-storage"
  fi
  grep -qiE 'kernel panic|traceback|an error occurred' "$logf" && die "installer reported an error; see $logf"
  run "start $name" virsh start "$name"
}
