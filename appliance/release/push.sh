#!/usr/bin/env bash
# push.sh (RUNS ON THE MAC): copy the release tools and pinned keys to aero:/data/chp-release/tools/.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
shopt -s nullglob
scp -q "$here"/*.sh "$here"/RPM-GPG-KEY-* "$here"/trusted-keys.txt "$here"/PACKAGES*.txt aero:/data/chp-release/tools/
echo "pushed to aero:/data/chp-release/tools/"
