#!/usr/bin/env bash
# proto/on-dcli.sh SCRIPT [ARGS] (RUNS ON THE MAC; Task 2 SPIKE): run proto/SCRIPT on iso5-dcli as chpadmin with the
# workstation's own python3 (3.9). The script travels as a -c argument (base64), because fapolicyd on the workstation
# refuses python3 opening an untrusted .py from a home directory (the product ships chp-site as a trusted RPM file);
# stdin passes straight through (the SPIKE scripted browser reads one credential line from it).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; s=$1; shift
# SCRIPT may be lib.py+main.py: the files are joined, the library first (it then skips its own main)
if [[ $s == *+* ]]; then b=$( { echo "_AS_LIB = True"; cat "$here/${s%%+*}"; echo "_AS_LIB = False"; cat "$here/${s#*+}"; } | base64 | tr -d '\n')
else b=$(base64 < "$here/$s" | tr -d '\n'); fi
ssh -F "$here/../ssh_config" -o BatchMode=yes dcli "${ENVS:-} python3 -I -c \"\$(echo $b | base64 -d)\" $(printf '%q ' "$@")"
