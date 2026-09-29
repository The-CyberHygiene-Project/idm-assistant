#!/usr/bin/env bash
# Runs ON build1: check the three RPMs of THIS spec's version-release (older RPMs in the directory are ignored).
#   expected-files.txt       every path that must be packaged somewhere (Review Focus #4)
#   expected-by-package.txt  "<pkg> <path>" = pkg must own path; "!<pkg> <path>" = pkg must NOT contain it
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; D="${1:-$HOME/rpmbuild/RPMS/x86_64}"
VR=$(rpmspec -q --qf '%{version}-%{release}\n' "$here/kanidm.spec" 2>/dev/null | head -1)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for p in server clients unixd; do
  f="$D/kanidm-$p-$VR.x86_64.rpm"; [[ -f $f ]] || { echo "MISSING package: $f"; exit 1; }
  rpm -qpl "$f" > "$tmp/$p"          # list once: grep -q on a pipe + pipefail gives false alarms
done
cat "$tmp/server" "$tmp/clients" "$tmp/unixd" > "$tmp/all"
bad=0
while read -r f; do
  [[ -z $f || $f == \#* ]] && continue
  grep -qxF "$f" "$tmp/all" || { echo "MISSING from RPMs: $f"; bad=1; }
done < "$here/expected-files.txt"
while read -r pkg f; do
  [[ -z $pkg || $pkg == \#* ]] && continue
  if [[ $pkg == !* ]]; then
    grep -qxF "$f" "$tmp/${pkg#!}" && { echo "WRONG PACKAGE: ${pkg#!} must not contain $f"; bad=1; }
  else
    grep -qxF "$f" "$tmp/$pkg" || { echo "NOT OWNED: $pkg must own $f"; bad=1; }
  fi
done < "$here/expected-by-package.txt"
(( bad == 0 )) || exit 1
echo "RPMS OK: all expected files packaged and owned ($VR)"
