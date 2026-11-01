#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-rpm.sh (RUNS ON THE MAC): build chp-yara-rules on aero into /data/chp-release/built/: unpack the pinned
# signature-base (lab/inputs/fetch-signature-base.sh), compile it with build-rules.py (aero's yarac = the shipped YARA),
# and package rules.yarc, SKIPPED.txt, COMMIT, LICENSE and NOTICE. Version = the commit date.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
f="$top/lab/inputs/fetch-signature-base.sh"
C=$(sed -n 's/^SIG_COMMIT=//p' "$f"); V=$(sed -n 's/^SIG_DATE=\([0-9.]*\).*/\1/p' "$f")
[[ $C =~ ^[0-9a-f]{40}$ && $V =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$ ]] || { echo "SIG_COMMIT/SIG_DATE not set in $f"; exit 1; }
ssh aero 'rm -rf /tmp/chpyr && mkdir -p /tmp/chpyr/SOURCES /tmp/chpyr/SPECS /tmp/chpyr/src /data/chp-release/built'
z=$(mktemp -d); trap 'rm -rf "$z"' EXIT                # aero's fapolicyd blocks opening an unsigned .py: ship a zipapp
mkdir "$z/app"; cp "$here/build-rules.py" "$z/app/__main__.py"; python3 -m zipapp "$z/app" -o "$z/build-rules.pyz"
scp -q "$z/build-rules.pyz" "$here/exclude.txt" "$here/NOTICE" aero:/tmp/chpyr/
scp -q "$here/chp-yara-rules.spec" aero:/tmp/chpyr/SPECS/
ssh aero bash -s "$C" "$V" <<'REMOTE'
set -Eeuo pipefail
C=$1 V=$2 S=/tmp/chpyr/SOURCES
tar -xzf "/data/lab-inputs/signature-base-$C.tar.gz" -C /tmp/chpyr/src --strip-components=1
python3 /tmp/chpyr/build-rules.pyz /tmp/chpyr/src/yara /tmp/chpyr/exclude.txt "$S"
cp /tmp/chpyr/src/LICENSE /tmp/chpyr/NOTICE "$S/"; echo "$C" > "$S/COMMIT"
E=$(rpm -q --qf '%{VERSION}-%{RELEASE}' yara)
rpmbuild -bb --define "_topdir /tmp/chpyr" --define "_sourcedir $S" --define "rules_version $V" --define "yara_evr $E" \
  /tmp/chpyr/SPECS/chp-yara-rules.spec >/tmp/chpyr/build.log 2>&1 || { tail -20 /tmp/chpyr/build.log; exit 1; }
cp /tmp/chpyr/RPMS/noarch/chp-yara-rules-*.rpm /data/chp-release/built/
rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE} requires: ' /tmp/chpyr/RPMS/noarch/chp-yara-rules-*.rpm; rpm -qpR /tmp/chpyr/RPMS/noarch/chp-yara-rules-*.rpm | grep yara
rm -rf /tmp/chpyr
REMOTE
