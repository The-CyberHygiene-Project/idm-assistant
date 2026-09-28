#!/usr/bin/env bash
# reset.sh [VM...]  (RUNS ON THE MAC): revert lab VMs to golden (lab/host/lab-reset.sh on aero), then step each VM's
# clock. A reverted VM resumes with the snapshot's clock; chrony would only slew, and TOTP (30 s) / TLS validity break.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; vms=("$@"); (( ${#vms[@]} )) || vms=(srv1 client2)
"$here/host/push.sh" lab-reset "${vms[@]}"
for v in "${vms[@]}"; do
  for _ in $(seq 30); do ssh -n -o ConnectTimeout=3 -o BatchMode=yes "$v" true 2>/dev/null && break; done
  # After a revert chrony still holds the snapshot's sample history, sees the jump as "too variable" (^~) and won't
  # use aero. Restarting chronyd clears that; the CUI config's `makestep 1.0 3` then steps on the first updates.
  ssh -n "$v" 'sudo systemctl restart chronyd; chronyc waitsync 30 0.5 >/dev/null 2>&1; echo "$(hostname -s): clock synced, now $(date -u +%T)"'
done
