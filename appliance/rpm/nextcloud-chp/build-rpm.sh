#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-rpm.sh (RUNS ON THE MAC): build the nextcloud-chp noarch RPM on the build VM chp-build (owner decision 4:
# never on the Mac, never on aero, whose fapolicyd denies rpmbuild reading untrusted PHP) and copy it to
# aero:/data/chp-release/built/. UNSIGNED: signing stays appliance/release/sign-session.sh on aero.
# Inputs: ${IDM_INPUTS:-~/idm-lab-inputs}/nextcloud-chp, verified by fetch-inputs.sh; every file's sha256 is checked
# against MANIFEST.txt here and again on the VM before rpmbuild runs.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
I="${IDM_INPUTS:-$HOME/idm-lab-inputs}/nextcloud-chp"; F="$top/lab/build-vm/ssh_config"
B() { ssh -F "$F" -o BatchMode=yes chp-build "$@"; }
W='~/nc-chp'
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
grep -v '^#' "$here/MANIFEST.txt" | cut -d'|' -f1,4 | tr '|' ' ' > "$T/sums"
while read -r f s; do
  [[ $(shasum -a 256 "$I/$f" | cut -d' ' -f1) == "$s" ]] || { echo "MANIFEST mismatch on the Mac: $f"; exit 1; }
done < "$T/sums"
COPYFILE_DISABLE=1 tar --no-xattrs --uid 0 --gid 0 --uname root --gname root -czf "$T/chp_foldertag.tar.gz" \
  -C "$here" --exclude .DS_Store chp_foldertag
COPYFILE_DISABLE=1 tar --no-xattrs --uid 0 --gid 0 --uname root --gname root -czf "$T/chp_ledger.tar.gz" \
  -C "$here" --exclude .DS_Store chp_ledger
B "rm -rf $W/SPECS $W/BUILD $W/BUILDROOT $W/RPMS $W/SRPMS && mkdir -p $W/SOURCES $W/SPECS"
while read -r f s; do   # the large tarballs are copied only when the VM does not already hold the verified file
  B "cd nc-chp/SOURCES && echo '$s  $f' | sha256sum -c --status" 2>/dev/null || scp -q -F "$F" "$I/$f" "chp-build:nc-chp/SOURCES/$f"
done < "$T/sums"
scp -q -F "$F" "$T/chp_foldertag.tar.gz" "$T/chp_ledger.tar.gz" "$here/occ" "$top/LICENSE" chp-build:nc-chp/SOURCES/
scp -q -F "$F" "$here/nextcloud-chp.spec" chp-build:nc-chp/SPECS/
awk '{print $2"  "$1}' "$T/sums" | B 'cd nc-chp/SOURCES && sha256sum -c --quiet' || { echo "MANIFEST mismatch on chp-build"; exit 1; }
B "rpmbuild -bb --define \"_topdir \$HOME/nc-chp\" --define 'dist .el9' $W/SPECS/nextcloud-chp.spec > $W/build.log 2>&1 \
     || { tail -30 $W/build.log; exit 1; }
   f=\$(ls $W/RPMS/noarch/nextcloud-chp-*.rpm); echo \"\$(basename \$f) \$(stat -c %s \$f) bytes, \$(rpm -qlp \$f | wc -l) files\"
   rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} os=%{OS} payload=%{PAYLOADCOMPRESSOR} buildhost=%{BUILDHOST} license=%{LICENSE}\n' \$f
   sha256sum \$f | sed 's|/.*/||'"
n=$(B "basename \$(ls $W/RPMS/noarch/nextcloud-chp-*.rpm)")
ssh -F "$F" -o BatchMode=yes aero 'mkdir -p /data/chp-release/built'
scp -q -3 -F "$F" "chp-build:nc-chp/RPMS/noarch/$n" "aero:/data/chp-release/built/$n"
ssh -F "$F" -o BatchMode=yes aero "sha256sum /data/chp-release/built/$n"
