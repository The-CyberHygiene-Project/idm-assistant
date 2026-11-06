#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# CHP_TEMPLATES_RELEASE=<folder> build-rpm.sh (RUNS ON THE MAC): build chp-templates' noarch RPM on aero from the SIGNED
# release (the folder holding chp-templates-$V.tar.gz, SHA256SUMS and SHA256SUMS.asc). The signature and the pinned
# sha256 are checked BEFORE anything is copied to aero.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
REL=${CHP_TEMPLATES_RELEASE:?set CHP_TEMPLATES_RELEASE to the signed release folder}
V=1.3.1
TAR=chp-templates-$V.tar.gz
SHA=73682cfc17b1707e68cda99770ffb9a873efaad04c08058d8169313018f5a5df   # templates-1.3.1 (For Jeff chp-templates/1.3.1/)
FPR=2DE0D71BF37D8F5E4201A590521276F43C908F8E
gpg --verify "$REL/SHA256SUMS.asc" "$REL/SHA256SUMS" 2>&1 | grep -q "Good signature" || { echo "refusing: bad signature"; exit 1; }
gpg --verify --status-fd 1 "$REL/SHA256SUMS.asc" "$REL/SHA256SUMS" 2>/dev/null | grep -q "VALIDSIG $FPR" || { echo "refusing: not signed by $FPR"; exit 1; }
(cd "$REL" && shasum -a 256 -c SHA256SUMS) >/dev/null || { echo "refusing: checksum"; exit 1; }
[[ $(shasum -a 256 "$REL/$TAR" | cut -d' ' -f1) == "$SHA" ]] || { echo "refusing: $TAR is not the pinned release"; exit 1; }
# The renderer as a zipapp (like chp-site.pyz): aero's fapolicyd blocks reading raw .py files, and rpmbuild reads all.
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
tar -xzf "$REL/$TAR" -C "$w"; src="$w/chp-templates-$V"
mkdir "$w/z"; cp "$src/render/chpfill.py" "$w/z/chpfill.py"
printf 'import sys\nimport chpfill\nsys.exit(chpfill.main())\n' > "$w/z/__main__.py"
python3 -m zipapp "$w/z" -o "$src/chpfill.pyz"
rm -rf "$src/render" "$src/tests" "$src/tools"
COPYFILE_DISABLE=1 tar --no-mac-metadata -C "$w" -czf "$w/chp-templates-$V-rpm.tar.gz" "chp-templates-$V"   # no ._* entries
ssh aero 'rm -rf /tmp/chpt && mkdir -p /tmp/chpt/SOURCES /tmp/chpt/SPECS /data/chp-release/built'
scp -q "$w/chp-templates-$V-rpm.tar.gz" aero:/tmp/chpt/SOURCES/
scp -q "$here/chp-templates.spec" aero:/tmp/chpt/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpt" /tmp/chpt/SPECS/chp-templates.spec >/tmp/chpt/build.log 2>&1 || { tail -20 /tmp/chpt/build.log; exit 1; }
          if rpm -qlp /tmp/chpt/RPMS/noarch/chp-templates-*.rpm | grep -q "/\._"; then echo "refusing: macOS ._ files in the RPM"; exit 1; fi
          cp /tmp/chpt/RPMS/noarch/chp-templates-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-templates-*.rpm | head -12 && rm -rf /tmp/chpt'
