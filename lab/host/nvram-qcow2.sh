#!/usr/bin/env bash
# nvram-qcow2.sh VM: convert a UEFI VM's NVRAM (variable store) from raw to qcow2, keeping its contents (e.g. enrolled
# Secure Boot keys). libvirt refuses internal snapshots of pflash-firmware VMs unless the NVRAM is qcow2.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
vm="${1:?usage: nvram-qcow2.sh VM}"
x=$(mktemp); virsh dumpxml --inactive "$vm" > "$x"
if grep -q "<nvram[^>]*format='qcow2'" "$x"; then log "$vm NVRAM already qcow2"; rm -f "$x"; exit 0; fi
raw=$(sed -n "s|.*<nvram[^>]*>\(.*\)</nvram>.*|\1|p" "$x"); q="${raw%.fd}.qcow2"
[[ -f $raw ]] || die "NVRAM file not found: $raw"
if [[ $(virsh domstate "$vm") != "shut off" ]]; then
  run "shut down $vm" virsh shutdown "$vm"
  for _ in $(seq 60); do [[ $(virsh domstate "$vm") == "shut off" ]] && break; sleep 2; done
fi
[[ $(virsh domstate "$vm") == "shut off" ]] || die "$vm did not shut down"
run "convert NVRAM to qcow2" qemu-img convert -f raw -O qcow2 "$raw" "$q"
python3 - "$x" "$raw" "$q" <<'PY'
import sys; p, raw, q = sys.argv[1:]; s = open(p).read()
s = s.replace(f" format='raw'>{raw}</nvram>", f" format='qcow2'>{q}</nvram>")
open(p, 'w').write(s)
PY
grep -q "format='qcow2'>$q</nvram>" "$x" || die "could not rewrite the <nvram> element"
run "redefine $vm with qcow2 NVRAM" virsh define "$x"
rm -f "$x"
run "start $vm" virsh start "$vm"
