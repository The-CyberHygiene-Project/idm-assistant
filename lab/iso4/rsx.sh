#!/bin/bash
# rsx.sh STICK VM IP SECRET_FILE CMD_B64 (RUNS ON AERO, root): like rs.sh, but the second secret ("$CHP_SECRET" inside CMD)
# is line 1 of SECRET_FILE (a root-only lab file, e.g. the lab users' POSIX password). Secrets move over pipes only.
set -euo pipefail
STICK=$1 VM=$2 IP=$3 F=$4 B=$5
root=$(bash /tmp/iso2/stick.sh escrow "$STICK" "$VM.txt" | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p')
printf '%s\n%s\n' "$root" "$(head -1 "$F")" | expect /tmp/iso2/rootrun.exp "$IP" /tmp/iso2/iso2_chpadmin "$B"
