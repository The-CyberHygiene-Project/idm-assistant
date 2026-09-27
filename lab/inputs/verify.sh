#!/usr/bin/env bash
# Re-verify every input against MANIFEST.txt (size + sha256). Run on the Mac, or on aero with
# IDM_INPUTS=/data/lab-inputs. Exit 1 on any mismatch or missing file.
set -Eeuo pipefail
D="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
MAN="${IDM_MANIFEST:-$(cd "$(dirname "$0")" && pwd)/MANIFEST.txt}"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }
bad=0
while IFS='|' read -r name ver bytes want _; do
  f="$D/$name"
  if [[ ! -f "$f" ]]; then echo "MISSING  $name"; bad=1; continue; fi
  [[ "$(size "$f")" == "$bytes" ]] || { echo "SIZE     $name"; bad=1; continue; }
  [[ "$(sha "$f")" == "$want" ]] || { echo "SHA256   $name"; bad=1; continue; }
  echo "OK       $name ($ver)"
done < "$MAN"
exit $bad
