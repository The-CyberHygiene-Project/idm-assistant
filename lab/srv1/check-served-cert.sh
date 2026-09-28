#!/usr/bin/env bash
# check-served-cert.sh [MIN_HOURS]  (RUNS ON THE MAC): fail unless the certificate Kanidm is SERVING right now is valid
# for at least MIN_HOURS more (default 20; the lab CA issues 24 h certificates).
set -Eeuo pipefail
min="${1:-20}"
end=$(ssh -n srv1 'echo | openssl s_client -connect idm.kanidm.lab.test:443 2>/dev/null | openssl x509 -noout -enddate' | cut -d= -f2)
left=$(( ( $(date -j -f '%b %e %T %Y %Z' "$end" +%s) - $(date +%s) ) / 3600 ))
echo "served certificate expires $end (${left} h left)"
(( left >= min )) || { echo "SERVED CERT TOO OLD: ${left} h < ${min} h" >&2; exit 1; }
