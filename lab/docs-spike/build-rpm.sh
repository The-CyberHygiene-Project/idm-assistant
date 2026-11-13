#!/usr/bin/env bash
# build-rpm.sh (RUNS ON THE MAC; Homebrew rpmbuild 6.1, v4 package format): build the SPIKE nextcloud-chp noarch RPM
# from the verified inputs (fetch-inputs.sh) and copy it to aero:/data/chp-release/built/spike/. UNSIGNED.
# Why not on aero like the other packages: aero runs fapolicyd, which denies any process reading UNTRUSTED PHP/JS files
# (70-trusted-lang.rules: deny_audit perm=any all : ftype=%languages), so rpmbuild's %install cp fails there.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; I="${IDM_INPUTS:-$HOME/idm-lab-inputs}/docs-spike"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; mkdir -p "$T"/{SOURCES,SPECS,BUILD,RPMS}
while IFS='|' read -r f _ _ s _; do [[ $f == \#* || -z $f ]] && continue
  [[ $(shasum -a 256 "$I/$f" | cut -d' ' -f1) == "$s" ]] || { echo "MANIFEST mismatch: $f"; exit 1; }
  cp "$I/$f" "$T/SOURCES/"; done < "$here/MANIFEST.txt"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$T/SOURCES/chp_foldertag.tar.gz" -C "$here" --exclude '.DS_Store' chp_foldertag
cp "$here"/pkg/* "$T/SOURCES/"; cp "$here/nextcloud.spec" "$T/SPECS/"
rpmbuild -bb --target noarch-linux --define "_topdir $T" --define '_rpmformat 4' --define '_binary_payload w9.zstdio' \
  --define '_prefix /usr' --define '_exec_prefix /usr' --define '_bindir /usr/bin' --define '_datadir /usr/share' \
  --define '_sysconfdir /etc' --define '_localstatedir /var' --define '_unitdir /usr/lib/systemd/system' \
  --define 'dist .el9' --define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
  "$T/SPECS/nextcloud.spec" > "$T/build.log" 2>&1 || { tail -30 "$T/build.log"; exit 1; }
f=$(ls "$T"/RPMS/nextcloud-chp-*.rpm); n=$(basename "$f")
echo "$n $(stat -f %z "$f") bytes, $(rpm -qlp "$f" 2>/dev/null | wc -l | tr -d ' ') files, os=$(rpm -qp --qf '%{OS} %{ARCH} %{PAYLOADCOMPRESSOR}' "$f" 2>/dev/null)"
shasum -a 256 "$f" | sed "s|$T/RPMS/||"
ssh aero 'mkdir -p /data/chp-release/built/spike'; scp -q "$f" aero:/data/chp-release/built/spike/
