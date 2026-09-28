#!/usr/bin/env bash
# Re-verify every input against MANIFEST.txt (size + sha256). Run on the Mac, or on aero with
# IDM_INPUTS=/data/lab-inputs. Exit 1 on any mismatch or missing file.
set -Eeuo pipefail
D="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
MAN="${IDM_MANIFEST:-$(cd "$(dirname "$0")" && pwd)/MANIFEST.txt}"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }
bad=0
EXPECTED=(Rocky-9.8-x86_64-dvd.iso rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz step-ca-0.30.2-1.x86_64.rpm
          step-cli-0.31.0-1.x86_64.rpm kanidm-1.11.2.tar.gz kanidm-1.11.2-vendor.tar.gz)
# A machine that receives only some inputs (e.g. build1) names that subset here.
[[ -n ${EXPECTED_OVERRIDE:-} ]] && read -r -a EXPECTED <<<"$EXPECTED_OVERRIDE"
for n in "${EXPECTED[@]}"; do
  grep -q "^$n|" "$MAN" || { echo "NOTLISTED $n (manifest incomplete)"; bad=1; }
done
while IFS='|' read -r name ver bytes want _; do
  f="$D/$name"
  if [[ ! -f "$f" ]]; then echo "MISSING  $name"; bad=1; continue; fi
  [[ "$(size "$f")" == "$bytes" ]] || { echo "SIZE     $name"; bad=1; continue; }
  [[ "$(sha "$f")" == "$want" ]] || { echo "SHA256   $name"; bad=1; continue; }
  echo "OK       $name ($ver)"
done < "$MAN"
exit $bad
