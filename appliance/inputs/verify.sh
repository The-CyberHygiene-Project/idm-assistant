#!/usr/bin/env bash
# verify.sh <dir>: every file named in MANIFEST.txt exists in <dir> with the pinned size and sha256.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; D=${1:?dir}
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
bad=0
while IFS='|' read -r f _v _bytes want _src _how; do
  [[ -z $f || $f == \#* ]] && continue
  [[ -f $D/$f ]] || { echo "MISSING $f"; bad=1; continue; }
  [[ $(sha "$D/$f") == "$want" ]] && echo "OK      $f" || { echo "MISMATCH $f"; bad=1; }
done < "$here/MANIFEST.txt"
exit $bad

