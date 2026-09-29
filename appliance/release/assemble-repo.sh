#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# assemble-repo.sh <stage-dir> <built-dir> <third-party-dir>: copy the newest RPM of each PACKAGES.txt entry into
# stage-dir. PACKAGES.txt lines are "<name> ours" (taken ONLY from built-dir, our own builds) or "<name> <label>"
# (third-party, taken ONLY from third-party-dir, keeping its vendor signature). A package of ours is never picked up
# from the third-party dir, whatever its version. Fails if an entry has no RPM, or if stage-dir already exists.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; S=$1; BUILT=$2; THIRD=$3
[[ -e $S ]] && { echo "refusing: $S exists"; exit 1; }
mkdir -p "$S"
while read -r name src; do
  [[ -z $name || $name == \#* ]] && continue
  if [[ ${src:-} == ours ]]; then d=$BUILT; else d=$THIRD; fi
  best=$(for f in "$d"/*.rpm; do if [[ -f $f && $(rpm -qp --qf '%{NAME}' "$f" 2>/dev/null) == "$name" ]]; then echo "$f"; fi; done \
         | while read -r f; do printf '%s\t%s\n' "$(rpm -qp --qf '%{EPOCH}:%{VERSION}-%{RELEASE}' "$f" 2>/dev/null | sed 's/^(none)/0/')" "$f"; done \
         | sort -V | tail -1 | cut -f2)
  [[ -n $best ]] || { echo "MISSING package: $name"; exit 1; }
  cp -a "$best" "$S/"; echo "  $name ← $(basename "$best")"
done < "$here/PACKAGES.txt"

