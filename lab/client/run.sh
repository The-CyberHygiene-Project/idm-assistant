#!/usr/bin/env bash
# run.sh STEP [host]: copy lab/client to the host (default client2) and run STEP.sh there with sudo.
# No --delete: secrets staged separately into /tmp/client (token, CA keys) survive the copy.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; step="${1:?usage: run.sh STEP [host]}"; host="${2:-client2}"
rsync -a "$here/" "$host:/tmp/client/"
# shellcheck disable=SC2029  # step expands on the Mac
ssh -n "$host" "sudo bash /tmp/client/$step.sh"
