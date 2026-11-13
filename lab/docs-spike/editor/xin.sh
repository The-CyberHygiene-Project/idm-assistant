#!/usr/bin/env bash
# editor/xin.sh ARGS... : drive the workstation display (see xinput.py) (RUNS ON THE MAC)
cd "$(dirname "$0")/.."; b=$(base64 < editor/xinput.py | tr -d '\n')
ssh -F ssh_config dcli "DISPLAY=:77 python3 -I -c \"\$(echo $b | base64 -d)\" $(printf '%q ' "$@")"
