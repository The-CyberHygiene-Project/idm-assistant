#!/bin/bash
# rs.sh STICK VM IP FIELD CMD_B64 (RUNS ON AERO, root): like prove.sh's Rt, plus a second secret: FIELD of the stick's
# KANIDM_ADMINS_JSON (escrow/<VM>-server.txt), available as "$CHP_SECRET" inside CMD. Secrets move over pipes only.
set -euo pipefail
STICK=$1 VM=$2 IP=$3 FIELD=$4 B=$5
root=$(bash /tmp/iso2/stick.sh escrow "$STICK" "$VM.txt" | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p')
sec=$(bash /tmp/iso2/stick.sh escrow "$STICK" "$VM-server.txt" | sed -n 's/^KANIDM_ADMINS_JSON=//p' \
      | python3 -c 'import base64,json,sys; print(json.loads(base64.b64decode(sys.stdin.read()))[sys.argv[1]])' "$FIELD")
printf '%s\n%s\n' "$root" "$sec" | expect /tmp/iso2/rootrun.exp "$IP" /tmp/iso2/iso2_chpadmin "$B"
