#!/usr/bin/env bash
# size-guard.sh NAME LIMIT_GB (RUNS ON AERO, as root): a runaway-allocation brake for a sparse-disk lab VM.
# Every 10 s it measures the ACTUAL allocation (du, not the virtual size) of /data/libvirt/images/NAME-*.qcow2.
# Over the limit: virsh destroy NAME, print "SIZE-GUARD STOP NAME <GB> GB" and the internal snapshots (they grow the
# file too), exit 1. Start it so it outlives the ssh session:  systemd-run --unit=size-guard-NAME size-guard.sh NAME 50
# Stop it with:  systemctl stop size-guard-NAME
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
name=${1:?NAME} limit=${2:?LIMIT_GB}
[[ $name == iso5-* ]] || { echo "refusing: only iso5-* lab VMs"; exit 1; }
[[ $limit =~ ^[0-9]+$ ]] || { echo "LIMIT_GB must be a whole number"; exit 1; }
while sleep 10; do
  shopt -s nullglob; imgs=(/data/libvirt/images/"$name"-*.qcow2); shopt -u nullglob
  (( ${#imgs[@]} )) || continue
  gb=$(du -B1G -c "${imgs[@]}" 2>/dev/null | tail -1 | cut -f1)
  if (( ${gb:-0} > limit )); then
    virsh destroy "$name" >/dev/null 2>&1 || true
    echo "SIZE-GUARD STOP $name $gb GB (limit $limit GB)"
    for i in "${imgs[@]}"; do echo "== $i"; qemu-img snapshot -l "$i" 2>&1 || true; done
    exit 1
  fi
done
