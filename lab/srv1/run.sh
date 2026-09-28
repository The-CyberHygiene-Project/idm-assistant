#!/usr/bin/env bash
# run.sh STEP [host]: copy lab/srv1 to the host (default srv1) and run STEP.sh there with sudo.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; step="${1:?usage: run.sh STEP [host]}"; host="${2:-srv1}"
rsync -a "$here/" "$host:/tmp/srv1/"   # no --delete: files staged separately (secrets) survive
# shellcheck disable=SC2029  # step expands on the Mac
ssh "$host" "sudo bash /tmp/srv1/$step.sh"
