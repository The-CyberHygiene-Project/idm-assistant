#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# release-iso.sh (RUNS ON THE MAC, YubiKey plugged in): release the TESTED ISO bytes (rc5, which passed gates 1-3) as
# 0.1.0 to the For Jeff share, with SHA256SUMS signed by the project key, the public key, NOTICE, VERIFY.md and the
# signed repo as a tarball (fixes without reinstalling, spec §8). Built in <target>.partial; renamed only when every
# check passed. Never rebuilds anything.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"
V=0.1.0 RC=0.1.0-rc5 REPO_V=0.6.3
ISO=cyberhygiene-lab-installer-el9.iso
ISO_SHA=efcba98a4268ec35ccef0b66b78122b3c78246424f76186cfa45a1ba80ff81b2     # rc5 = the bytes that were tested
FPR=2DE0D71BF37D8F5E4201A590521276F43C908F8E
SHARE="/Volumes/For Jeff"; T="$SHARE/cyberhygiene-lab-installer/$V"; P="$T.partial"
[[ -d $SHARE ]] || { echo "refusing: $SHARE is not mounted"; exit 1; }
[[ -e $T ]] && { echo "refusing: $T already exists"; exit 1; }
gpg --card-status >/dev/null 2>&1 || { echo "refusing: YubiKey not found (plug it in)"; exit 1; }
rm -rf "$P"; mkdir -p "$P"
echo "== ISO ($RC, about 15 GB) from aero"
ssh aero "cat /var/lib/libvirt/images/chp-iso/$RC/$ISO" > "$P/$ISO"
got=$(shasum -a 256 "$P/$ISO" | cut -d' ' -f1)
[[ $got == "$ISO_SHA" ]] || { echo "refusing: copied ISO sha256 $got is not the tested $ISO_SHA"; exit 1; }
echo "== signed repo $REPO_V as a tarball"
ssh aero "tar -C /data/chp-release/$REPO_V -czf - repo" > "$P/chp-repo-$REPO_V.tar.gz"
cp "$here/RPM-GPG-KEY-cyberhygiene" "$top/appliance/branding/NOTICE.txt" "$P/"
sed -e "s/@VERSION@/$V/g" -e "s/@REPO@/$REPO_V/g" "$here/VERIFY.md.in" > "$P/VERIFY.md"
(cd "$P" && shasum -a 256 "$ISO" "chp-repo-$REPO_V.tar.gz" RPM-GPG-KEY-cyberhygiene NOTICE.txt VERIFY.md > SHA256SUMS)
echo "== signing SHA256SUMS (PIN dialog, then touch the key)"
gpg --local-user "$FPR" --armor --detach-sign -o "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
echo "== checks"
gpg --verify "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
(cd "$P" && shasum -a 256 -c SHA256SUMS)
mv "$P" "$T"
echo "RELEASED: $T"; ls -l "$T"
