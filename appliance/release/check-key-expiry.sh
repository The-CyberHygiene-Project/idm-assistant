#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# check-key-expiry.sh [keys-dir]: refuse (exit 1) if any key pinned in trusted-keys.txt has expired or expires within
# 90 days (security bundle spec §6; Wazuh's key expires 2027-05-15). Run first by every release script.
set -uo pipefail
K=${1:-$(cd "$(dirname "$0")" && pwd)}; now=${CHP_NOW:-$(date -u +%s)}; bad=0
while read -r fpr label file; do
  [[ -z ${fpr:-} || $fpr == \#* ]] && continue
  exp=$(gpg --show-keys --with-colons "$K/$file" 2>/dev/null | awk -F: '/^pub/{print $7; exit}')
  [[ -z $exp ]] && continue                                        # no expiry date
  days=$(( (exp - now) / 86400 ))
  if (( exp <= now )); then echo "EXPIRED: $label key ($fpr) expired $((-days)) days ago"; bad=1
  elif (( days < 90 )); then echo "REFUSING: $label key ($fpr) expires in $days days (renew or re-pin before releasing)"; bad=1
  fi
done < "$K/trusted-keys.txt"
(( bad )) && exit 1
echo "KEYS OK: no pinned key expires within 90 days"
