#!/usr/bin/env bash
# reset.sh [VM...]  (RUNS ON THE MAC): revert lab VMs to golden (lab/host/lab-reset.sh on aero), then step each VM's
# clock. A reverted VM resumes with the snapshot's clock; chrony would only slew, and TOTP (30 s) / TLS validity break.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; vms=("$@"); (( ${#vms[@]} )) || vms=(srv1 client2)
"$here/host/push.sh" lab-reset "${vms[@]}"
# client1 is PAM-only (CHP kit: code + password, no keys). After a revert its clock is the snapshot's, and
# ~/.google_authenticator holds rate-limit timestamps from just before the snapshot: wait until the guest's clock is
# past that 30 s window, then log in with a code computed for the guest's clock (TOTP_OFFSET), then resync.
pam_only_resync() {
  local v=$1 snap start off
  snap=$(ssh -n aero "sudo virsh snapshot-dumpxml $v golden" | sed -n 's/.*<creationTime>\([0-9]*\)<.*/\1/p' | head -1)
  start=$(ssh -n aero "P=\$(pgrep -f 'guest=$v' | head -1); date -d \"\$(ps -o lstart= -p \$P)\" +%s" | tail -1)
  off=$(( snap - start ))
  until (( $(date +%s) + off >= snap + 35 )); do sleep 2; done
  # ONE login (every failed try counts toward the kit's faillock: 5 -> 15 min lock), which itself resyncs the clock.
  # shellcheck disable=SC2016  # $(date) must run on the VM, not here
  LOGIN_CMD='sudo systemctl restart chronyd; chronyc waitsync 30 0.5 >/dev/null; echo OUT: synced $(date -u +%T)' \
    TOTP_OFFSET=$off /usr/bin/expect "$here/client/ssh-login.exp" itadmin posix 192.168.100.12 ~/idm-lab-secrets/"$v"-itadmin.json \
    | grep -E '^(OUT|RESULT)' || true
}
for v in "${vms[@]}"; do
  if [[ $v == client1 ]]; then pam_only_resync "$v"; continue; fi   # PAM-only: no key login, clock resynced above
  for _ in $(seq 30); do ssh -n -o ConnectTimeout=3 -o BatchMode=yes "$v" true 2>/dev/null && break; done
  # After a revert chrony still holds the snapshot's sample history, sees the jump as "too variable" (^~) and won't
  # use aero. Restarting chronyd clears that; the CUI config's `makestep 1.0 3` then steps on the first updates.
  ssh -n "$v" 'sudo systemctl restart chronyd; chronyc waitsync 30 0.5 >/dev/null 2>&1; echo "$(hostname -s): clock synced, now $(date -u +%T)"'
done
# The restored Kanidm certificate is as old as the snapshot and may be expired (renewal refuses expired certs):
# issue a fresh one, then prove what is SERVED is fresh.
if [[ " ${vms[*]} " == *" srv1 "* ]]; then
  "$here/srv1/run.sh" 21-kanidm-cert srv1 --reissue >/dev/null
  "$here/srv1/check-served-cert.sh"
fi
