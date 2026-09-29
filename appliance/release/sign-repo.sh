#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# sign-repo.sh <stage-dir> <out-dir> <signer-fpr> <keys-dir>: sign every UNSIGNED RPM of stage-dir with signer-fpr,
# keep signatures by pinned third-party keys (e.g. EPEL) as they are, REFUSE anything signed by an unpinned key,
# build repodata, sign repomd.xml, verify. Works in a temp copy next to out-dir; out-dir appears only when all of it
# passed (all-or-nothing: an unplugged YubiKey or a missed touch leaves nothing half-signed). stage-dir is unchanged.
set -Eeuo pipefail
S=$1; O=$2; FPR=$3; K=$4
here="$(cd "$(dirname "$0")" && pwd)"
[[ -e $O ]] && { echo "refusing: $O already exists"; exit 1; }
mkdir -p "$(dirname "$O")"
work=$(mktemp -d "$(dirname "$O")/.sign.XXXXXX"); db=$(mktemp -d)
trap 'rm -rf "$work" "$db"' EXIT
# rpm runs confined (SELinux rpm_t): it may only write rpm-labelled dirs, even a private --dbpath (denials are
# dontaudit-ed, so they look like plain EACCES/ENOENT). Label the private database directory rpm_var_lib_t.
chcon -t rpm_var_lib_t "$db" 2>/dev/null || true
rpm --dbpath "$db" --initdb
while read -r fpr _label file; do
  [[ -z ${fpr:-} || $fpr == \#* ]] && continue
  rpm --dbpath "$db" --import "$K/$file"
done < "$K/trusted-keys.txt"
shopt -s nullglob
rpms=("$S"/*.rpm); (( ${#rpms[@]} )) || { echo "no RPMs in $S"; exit 1; }
cp -a "${rpms[@]}" "$work/"
to_sign=()
for f in "$work"/*.rpm; do
  out=$(rpm --dbpath "$db" -Kv "$f" 2>&1 || true)
  if grep -q 'Signature, key ID' <<<"$out"; then
    grep -qE 'NOKEY|NOT OK|BAD' <<<"$out" && { echo "REFUSED: $(basename "$f") is signed by an unpinned key or is damaged"; exit 1; }
  else
    to_sign+=("$f")
  fi
done
if (( ${#to_sign[@]} )); then
  rpmsign --addsign --define "_gpg_name $FPR" --define "_gpg_digest_algo sha256" "${to_sign[@]}"
fi
createrepo_c --quiet "$work"
gpg --batch --yes --local-user "$FPR" --armor --detach-sign -o "$work/repodata/repomd.xml.asc" "$work/repodata/repomd.xml"
bash "$here/verify-repo.sh" "$work" "$K"
chmod 0755 "$work"
mv "$work" "$O"
trap 'rm -rf "$db"' EXIT
echo "SIGNED REPO: $O"

