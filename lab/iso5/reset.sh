#!/usr/bin/env bash
# reset.sh [ignored...] (RUNS ON THE MAC; IDM_PROFILE=appliance reset, called by the engine before every scenario run):
# revert iso5-srv + iso5-cli2 to their golden snapshots, then make them usable again. Any failed step stops the reset
# (set -e) so no scenario ever runs on a host that is not at golden (Plan 5b Review Focus 5).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; F="$here/ssh_config"
S() { ssh -F "$F" -n -o ConnectTimeout=5 "$@"; }
ssh -n aero 'sudo virsh snapshot-revert iso5-srv golden --running && sudo virsh snapshot-revert iso5-cli2 golden --running'
for h in srv1 client2; do
  ok=no; for _ in $(seq 30); do if S "$h" true 2>/dev/null; then ok=yes; break; fi; sleep 2; done
  [[ $ok == yes ]] || { echo "reset: $h not reachable after the revert" >&2; exit 1; }
  # Row 18: a reverted clock is the snapshot's; chrony flags the jump as too variable until it is restarted.
  S "$h" 'sudo systemctl restart chronyd && chronyc waitsync 30 0.5 >/dev/null && echo "$(hostname -s): clock synced $(date -u +%T)"'
done
# The served Kanidm certificate is as old as the snapshot (24 h ACME certificates): issue a fresh one (row 26 path).
S srv1 'sudo /usr/libexec/chp/cert-renew-kanidm --issue'
# client2 must reach Kanidm over TLS with the pinned anchor before any scenario starts.
S client2 'u=$(sed -n "s/^uri = \"\(.*\)\"/\1/p" /etc/kanidm/config); for i in $(seq 30); do curl -fsS --max-time 5 "$u/status" >/dev/null 2>&1 && { echo "client2: Kanidm TLS ok"; exit 0; }; sleep 2; done; echo "client2: Kanidm TLS NOT ok" >&2; exit 1'
S client2 'sudo kanidm-unix cache-invalidate'
# Row 19: GA's reuse window and the restored rate-limit state pass before the first login.
sleep 31
echo "reset: golden, clocks synced, fresh certificate served"
