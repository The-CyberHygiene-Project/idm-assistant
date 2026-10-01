#!/usr/bin/env bash
# unlock.sh NAME STICK_IMG HOST (RUNS ON AERO, sudo): first boot of a fresh iso2 VM has no TPM binding yet (that is
# the role RPMs' first-boot unit, Plans 3/4), so answer the LUKS prompt with the passphrase from the stick's escrow.
# The passphrase goes stick -> pipe -> console helper; it is never printed or logged. Proves the escrow opens the disk.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
name=$1 stick=$2 host=$3 log=/var/log/libvirt/qemu/$1-install.log
# A prompt is PENDING when, since the last boot's "Linux version" line, "Please enter passphrase" has appeared and
# neither a login: prompt nor a successful unlock has. (Kernel messages keep printing after the prompt, so "the last
# console line is the prompt" does not work here.) Only then is the passphrase sent: never blind.
pending() { tr -d '\r' < "$log" | awk '/Linux version/{p=0; d=0} /Please enter passphrase/{p=1; d=0; next} p && /login:|Finished Cryptography Setup|Reached target.*Local Encrypted Volumes\./{d=1} END{exit !(p && !d)}'; }
unlocked() { tr -d '\r' < "$log" | awk '/Linux version/{p=0; d=0} /Please enter passphrase/{p=1; d=0; next} p && /login:|Finished Cryptography Setup|Reached target.*Local Encrypted Volumes\./{d=1} END{exit !(p && d)}'; }
if unlocked; then echo "already unlocked (passphrase sent earlier this boot)"; exit 0; fi
for _ in $(seq 240); do if pending; then break; fi; sleep 5; done
pending || { echo "no pending LUKS prompt; nothing sent"; exit 1; }
bash /tmp/iso2/stick.sh escrow "$stick" "$host.txt" | sed -n 's/^LUKS_PASSPHRASE=//p' | expect /tmp/iso2/luks-send.exp "$name"
