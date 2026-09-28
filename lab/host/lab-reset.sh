#!/usr/bin/env bash
# lab-reset.sh [VM...]: revert lab VMs (default: srv1 client2) to their golden snapshots. All-or-nothing check first.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
vms=(); for a in "$@"; do [[ $a == --check ]] || vms+=("$a"); done; (( ${#vms[@]} )) || vms=(srv1 client2)
for v in "${vms[@]}"; do virsh snapshot-info "$v" golden >/dev/null 2>&1 || die "$v has no golden snapshot; nothing reverted"; done
for v in "${vms[@]}"; do run "revert $v to golden" virsh snapshot-revert "$v" golden --running; done
log "lab reset done: ${vms[*]}"
