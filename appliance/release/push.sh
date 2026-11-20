#!/usr/bin/env bash
# push.sh (RUNS ON THE MAC): copy the release tools and pinned keys to aero:/data/chp-release/tools/.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
shopt -s nullglob
scp -q "$here"/*.sh "$here"/RPM-GPG-KEY-* "$here"/trusted-keys.txt "$here"/PACKAGES*.txt "$here"/MODULES*.txt \
  "$here"/VENDOR.txt aero:/data/chp-release/tools/
# vendor keys (stage-vendor.sh checks a vendor RPM against them before stripping the signature; never repo keys)
ssh aero mkdir -p /data/chp-release/tools/vendor-keys
scp -q "$here"/vendor-keys/* aero:/data/chp-release/tools/vendor-keys/
echo "pushed to aero:/data/chp-release/tools/"
