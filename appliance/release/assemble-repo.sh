#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# assemble-repo.sh <stage-dir> <source-dir>...: copy the newest RPM of each PACKAGES.txt name into stage-dir.
# Fails if a name has no RPM, or if stage-dir already exists.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; S=$1; shift
[[ -e $S ]] && { echo "refusing: $S exists"; exit 1; }
mkdir -p "$S"
while read -r name; do
  [[ -z $name || $name == \#* ]] && continue
  best=$(for d in "$@"; do for f in "$d"/*.rpm; do if [[ -f $f && $(rpm -qp --qf '%{NAME}' "$f" 2>/dev/null) == "$name" ]]; then echo "$f"; fi; done; done \
         | while read -r f; do printf '%s\t%s\n' "$(rpm -qp --qf '%{EPOCH}:%{VERSION}-%{RELEASE}' "$f" 2>/dev/null | sed 's/^(none)/0/')" "$f"; done \
         | sort -V | tail -1 | cut -f2)
  [[ -n $best ]] || { echo "MISSING package: $name"; exit 1; }
  cp -a "$best" "$S/"; echo "  $name ← $(basename "$best")"
done < "$here/PACKAGES.txt"

