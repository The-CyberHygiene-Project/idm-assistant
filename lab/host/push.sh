#!/usr/bin/env bash
# Copy the host-prep scripts to aero and run one step with sudo:  lab/host/push.sh b1-media --check
set -Eeuo pipefail
step="$1"; shift
here="$(cd "$(dirname "$0")" && pwd)"
ssh aero 'mkdir -p /tmp/lab-host'
scp -q "$here"/*.sh aero:/tmp/lab-host/
# shellcheck disable=SC2029  # step/args are meant to expand on the Mac
ssh aero "sudo bash /tmp/lab-host/${step}.sh $*"
