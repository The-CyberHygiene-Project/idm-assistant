#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# V=… REPO_V=… release-repo.sh (RUNS ON THE MAC, YubiKey plugged in): publish a package-only UPDATE (no ISO) to the
# For Jeff share as V/ (e.g. 0.2.0-update1): the signed repo REPO_V as a tarball, the public key, NOTICE and
# UPDATE.md, with SHA256SUMS signed by the project key (spec §8: fixes without reinstalling). Built in <target>.partial;
# renamed only when every check passed. Never touches an existing folder; never rebuilds anything.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"
V=${V:?set V (the update folder name, e.g. 0.2.0-update1)} REPO_V=${REPO_V:?set REPO_V (the signed repo, e.g. 0.7.5)}
FPR=2DE0D71BF37D8F5E4201A590521276F43C908F8E
SHARE="/Volumes/For Jeff"; B="$SHARE/cyberhygiene-lab-installer"; T="$B/$V"; P="$T.partial"
[[ -d $SHARE ]] || { echo "refusing: $SHARE is not mounted"; exit 1; }
[[ -e $T ]] && { echo "refusing: $T already exists"; exit 1; }
gpg --card-status >/dev/null 2>&1 || { echo "refusing: YubiKey not found (plug it in)"; exit 1; }
rm -rf "$P"; mkdir -p "$P"
echo "== signed repo $REPO_V as a tarball (verified on aero first)"
ssh aero "bash /data/chp-release/tools/verify-repo.sh /data/chp-release/$REPO_V/repo /data/chp-release/tools" | grep -q "^REPO OK" \
  || { echo "refusing: repo $REPO_V does not verify on aero"; exit 1; }
ssh aero "tar -C /data/chp-release/$REPO_V -czf - repo" > "$P/chp-repo-$REPO_V.tar.gz"
cp "$here/RPM-GPG-KEY-cyberhygiene" "$top/appliance/branding/NOTICE.txt" "$P/"
sed -e "s/@VERSION@/$V/g" -e "s/@REPO@/$REPO_V/g" "$here/UPDATE.md.in" > "$P/UPDATE.md"
(cd "$P" && shasum -a 256 "chp-repo-$REPO_V.tar.gz" RPM-GPG-KEY-cyberhygiene NOTICE.txt UPDATE.md > SHA256SUMS)
echo "== signing SHA256SUMS (PIN dialog if not cached; then TOUCH the key when it flashes)"
gpg --local-user "$FPR" --armor --detach-sign -o "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
echo "== checks"
gpg --verify "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
(cd "$P" && shasum -a 256 -c SHA256SUMS)
mv "$P" "$T"
echo "RELEASED: $T"; ls -l "$T"
