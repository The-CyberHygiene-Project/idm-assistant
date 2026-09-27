#!/usr/bin/env bash
# Tests for input integrity (review findings 5 and 6). Uses the real downloaded Rocky files.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; D="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
fails=0; t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
# shellcheck source=gpgcheck.sh
source "$here/gpgcheck.sh"
ROCKY_FPR=21CB256AE16FC54C6E652949702D426D350D275D
gpg_sandbox
curl -fsSL https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9 | gpg --batch --import 2>/dev/null
tmp=$(mktemp -d)
cp "$D/Rocky-9.8-x86_64-dvd.iso.CHECKSUM" "$tmp/good"
sed 's/= d/= e/' "$tmp/good" > "$tmp/tampered"
t "good CHECKSUM verifies against the pinned Rocky key" \
  "verify_detached '$D/Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc' '$tmp/good' $ROCKY_FPR"
t "tampered CHECKSUM is rejected" \
  "! verify_detached '$D/Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc' '$tmp/tampered' $ROCKY_FPR"
t "a valid signature from a DIFFERENT pinned fingerprint is rejected" \
  "! verify_detached '$D/Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc' '$tmp/good' 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
grep -v '^kanidm-1.11.2-vendor' "$here/MANIFEST.txt" > "$tmp/short-manifest"
t "verify.sh fails when an expected input is missing from the manifest" \
  "! IDM_MANIFEST='$tmp/short-manifest' '$here/verify.sh' >/dev/null"
t "verify.sh passes on the full manifest" "'$here/verify.sh' >/dev/null"
rm -rf "$tmp"
exit $fails
