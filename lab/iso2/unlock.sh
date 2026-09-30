#!/usr/bin/env bash
# unlock.sh NAME STICK_IMG HOST (RUNS ON AERO, sudo): first boot of a fresh iso2 VM has no TPM binding yet (that is
# the role RPMs' first-boot unit, Plans 3/4), so answer the LUKS prompt with the passphrase from the stick's escrow.
# The passphrase goes stick -> pipe -> console helper; it is never printed or logged. Proves the escrow opens the disk.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
name=$1 stick=$2 host=$3 log=/var/log/libvirt/qemu/$1-install.log
for _ in $(seq 240); do
  if tail -c 400 "$log" | tr '\r' '\n' | grep -q "Please enter passphrase"; then break; fi; sleep 5
done
bash /tmp/iso2/stick.sh escrow "$stick" "$host.txt" | sed -n 's/^LUKS_PASSPHRASE=//p' | expect /tmp/iso2/luks-console-unlock.exp "$name"
