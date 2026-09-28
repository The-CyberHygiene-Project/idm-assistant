#!/usr/bin/env bash
# chp-prep-dirs.sh [HOST]  (RUNS ON THE MAC). LAB PREP, not part of the CHP kit: the kit's write_file() never creates
# the parent directory (finding K3), and on a fresh Rocky 9.8 install these don't exist, so harden aborts. Create
# exactly the missing ones, with stock ownership/modes, and restore their SELinux labels.
set -Eeuo pipefail
host="${1:-client1}"
ssh "$host" 'sudo bash -s' <<'REMOTE'
set -e
for spec in /etc/audit/rules.d:0750 /etc/fapolicyd/rules.d:0755 /etc/systemd/journald.conf.d:0755; do
  d=${spec%%:*}; m=${spec##*:}
  if [[ ! -d $d ]]; then install -d -o root -g root -m "$m" "$d"; restorecon "$d"; echo "created $d ($m)"; fi
done
REMOTE
