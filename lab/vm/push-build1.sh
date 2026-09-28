#!/usr/bin/env bash
# Copy the verified build inputs and the build scripts from the Mac to build1, then re-verify there.
# Extra input names (e.g. kanidm-1.11.2-fips-vendor.tar.gz) may be given as arguments.
set -Eeuo pipefail
# shellcheck source=subset.sh
source "$(dirname "$0")/subset.sh"
here="$(cd "$(dirname "$0")/.." && pwd)"; IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
want="rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz kanidm-1.11.2.tar.gz kanidm-1.11.2-vendor.tar.gz $*"
ssh build1 'mkdir -p ~/inputs ~/scripts'
for f in $want; do rsync -a "$IN/$f" build1:inputs/; done
# shellcheck disable=SC2086  # $want is a word list of input names
manifest_subset "$here/inputs/MANIFEST.txt" $want > /tmp/build1-manifest.txt
rsync -a /tmp/build1-manifest.txt build1:inputs/MANIFEST.txt
rsync -a "$here/inputs/verify.sh" build1:inputs/
for d in kanidm kanidm-rpm; do if [[ -d $here/$d ]]; then rsync -a "$here/$d" build1:scripts/; fi; done
# shellcheck disable=SC2029  # $want is meant to expand on the Mac
ssh build1 "IDM_INPUTS=~/inputs IDM_MANIFEST=~/inputs/MANIFEST.txt EXPECTED_OVERRIDE='$want' bash ~/inputs/verify.sh" \
  || { echo "inputs failed verification on build1"; exit 1; }
