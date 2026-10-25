#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# V=… RC=… REPO_V=… ISO_SHA=… release-iso.sh (RUNS ON THE MAC, YubiKey plugged in): release the TESTED ISO bytes (the rc
# that passed gates 1-3) as V to the For Jeff share, with SHA256SUMS signed by the project key, the public key, NOTICE, VERIFY.md and the
# signed repo as a tarball (fixes without reinstalling, spec §8). Built in <target>.partial; renamed only when every
# check passed. Never rebuilds anything.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"
V=${V:?set V (e.g. 0.2.0)} RC=${RC:?set RC (the tested rc)} REPO_V=${REPO_V:?set REPO_V (its signed repo)}
ISO=cyberhygiene-lab-installer-el9.iso
ISO_SHA=${ISO_SHA:?set ISO_SHA (sha256 of the tested rc)}     # 0.1.0 = rc5 efcba98a…; 0.2.0 = rc2 1332d911…
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
extra=()
if [[ $V != 0.1.0 ]]; then   # spec §7: how a 0.1.0 site upgrades in place
  sed -e "s/@VERSION@/$V/g" -e "s/@REPO@/$REPO_V/g" "$here/UPGRADE-FROM-0.1.0.md.in" > "$P/UPGRADE-FROM-0.1.0.md"; extra=(UPGRADE-FROM-0.1.0.md)
fi
(cd "$P" && shasum -a 256 "$ISO" "chp-repo-$REPO_V.tar.gz" RPM-GPG-KEY-cyberhygiene NOTICE.txt VERIFY.md "${extra[@]}" > SHA256SUMS)
echo "== signing SHA256SUMS (PIN dialog, then touch the key)"; say "Release signing now. Watch for the PIN dialog." 2>/dev/null || true
gpg --local-user "$FPR" --armor --detach-sign -o "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
echo "== checks"
gpg --verify "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
(cd "$P" && shasum -a 256 -c SHA256SUMS)
mv "$P" "$T"
echo "RELEASED: $T"; ls -l "$T"
