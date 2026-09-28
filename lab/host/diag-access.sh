#!/usr/bin/env bash
# diag-access.sh HOST...  (RUNS ON THE MAC): create the read-only `diag` account on each HOST: SSH key only, and a
# single-command sudo rule for /usr/local/sbin/idm-collect (spec §5.1). Installs the collector + its redaction rules.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; K=~/idm-lab-secrets/diag_ecdsa
[[ -f $K ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C 'idm-assistant diag' -f "$K"
for h in "$@"; do
  scp -q "$here/../collector/idm-collect" "$here/../collector/redact.sed" "$K.pub" "$h:/tmp/"
  ssh "$h" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
id diag >/dev/null 2>&1 || useradd -r -m -s /bin/bash -c "idm-assistant read-only collector" diag
install -d -o diag -g diag -m 0700 /home/diag/.ssh
install -o diag -g diag -m 0600 /tmp/diag_ecdsa.pub /home/diag/.ssh/authorized_keys
install -o root -g root -m 0755 /tmp/idm-collect /usr/local/sbin/idm-collect
install -o root -g root -m 0644 /tmp/redact.sed /usr/local/sbin/idm-collect.redact.sed
restorecon -R /usr/local/sbin /home/diag
install -d -o root -g root -m 0700 /etc/idm-collect
printf '%s\n' 'diag ALL=(root) NOPASSWD: /usr/local/sbin/idm-collect, /usr/local/sbin/idm-collect --user *' > /tmp/61-diag
visudo -cf /tmp/61-diag >/dev/null
install -o root -g root -m 0440 /tmp/61-diag /etc/sudoers.d/61-diag
rm -f /tmp/idm-collect /tmp/redact.sed /tmp/diag_ecdsa.pub /tmp/61-diag
echo "diag ready on $(hostname -s)"
REMOTE
done
