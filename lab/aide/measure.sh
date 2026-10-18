#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# measure.sh start|actions|collect (RUNS ON THE MAC): spec §4.5 churn measurement on the upgraded iso5 hosts.
#   start    upgrade (prove-aide.sh upgrade) and record T0; the daily timer then runs by itself
#   actions  the deliberate actions, once, on day 1: PAM logins with GA (lab/iso5/prove.sh row36), an onboard and a
#            revoke (idm_admin session from the lab secret, via kanidm-login.exp), dnf reinstall of chp-site
#   collect  copy every check report since T0 to lab/aide/measure-<host>/ and list each reported path with a count
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; F="$top/lab/iso5/ssh_config"
H() { local h=$1; shift; ssh -F "$F" -n -o ConnectTimeout=10 "$h" "$@"; }
case ${1:-} in
  start) bash "$here/prove-aide.sh" upgrade && date -u +%s > "$here/.t0" && echo "T0 $(date -u)";;
  actions)
    bash "$top/lab/iso5/prove.sh" row36
    pw=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["idm_admin"] if "idm_admin" in d else d["password"])' ~/idm-lab-secrets/iso5-idm_admin.json)
    printf '%s\n' "$pw" | ssh -F "$F" srv1 'sudo HOME=/root /usr/libexec/chp/kanidm-login.exp idm_admin' >/dev/null
    H srv1 'sudo HOME=/root chp-site onboard lab09 --display "Lab 9" && sudo HOME=/root chp-site revoke lab09'
    H srv1 'sudo dnf -y -q --enablerepo=chp reinstall chp-site'
    echo "actions done $(date -u)" ;;
  collect)
    for h in srv1 client2; do
      d="$here/measure-$h"; mkdir -p "$d"
      H $h 'sudo bash -c "tar -C /var/log/aide -cf - ."' | tar -C "$d" -xf -
      echo "== $h: paths reported in daily checks (count of checks reporting each)"
      cat "$d"/check-*.log | python3 -c '
import sys; sys.path.insert(0, "'"$top"'/appliance/chp-site")
from chp_site.aide import parse_report
from collections import Counter
text = sys.stdin.read(); c = Counter()
for chunk in text.split("Start timestamp")[1:]:
    r = parse_report("Start timestamp" + chunk)
    for k, ps in r.items():
        for p in ps: c[(k, p)] += 1
for (k, p), n in sorted(c.items(), key=lambda x: (-x[1], x[0])): print(f"{n:3} {k:8} {p}")'
    done ;;
  *) echo "usage: measure.sh start|actions|collect"; exit 2 ;;
esac
