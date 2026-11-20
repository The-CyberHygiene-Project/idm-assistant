#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# sign-repo.sh <stage-dir> <out-dir> <signer-fpr> <keys-dir>: sign every UNSIGNED RPM of stage-dir with signer-fpr, keep
# signatures by pinned third-party keys (e.g. EPEL) as they are, REFUSE anything signed by an unpinned key (and any
# unsigned RPM that is neither ours nor a vendor RPM pinned in VENDOR.txt for re-signing), build
# repodata (make-repodata.sh: with the stage's modules.yaml, if any), sign repomd.xml, verify. Works in a temp copy next
# to out-dir; out-dir appears only when all of it passed (all-or-nothing: an unplugged YubiKey or a missed touch leaves
# nothing half-signed). stage-dir is unchanged.
set -Eeuo pipefail
S=$1; O=$2; FPR=$3; K=$4
here="$(cd "$(dirname "$0")" && pwd)"
VT=${CHP_VENDOR_TXT:-$here/VENDOR.txt}         # vendor RPMs carried re-signed (stage-vendor.sh)
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
[[ -f $S/modules.yaml ]] && cp -a "$S/modules.yaml" "$work/"   # module metadata (stage-modules.sh), if any
to_sign=()
for f in "$work"/*.rpm; do
  out=$(rpm --dbpath "$db" -Kv "$f" 2>&1 || true)
  if grep -q 'Signature, key ID' <<<"$out"; then
    grep -qE 'NOKEY|NOT OK|BAD' <<<"$out" && { echo "REFUSED: $(basename "$f") is signed by an unpinned key or is damaged"; exit 1; }
  else
    # only OUR builds get our signature: a stray lab/upstream RPM must never be blessed with the project key...
    vr=$(rpm -qp --qf '%{VENDOR}|%{RELEASE}' "$f" 2>/dev/null)
    if [[ ! ( ${vr%%|*} == "The CyberHygiene Project" && ${vr#*|} == *.chp* ) ]]; then
      # ...except a vendor RPM the repo carries RE-SIGNED: its name and header sha256 (%{SHA256HEADER}, unchanged by
      # stage-vendor.sh's --delsign) on a VENDOR.txt line, and its digests intact
      nh=$(rpm -qp --nosignature --qf '%{NAME} %{SHA256HEADER}' "$f" 2>/dev/null || true)
      dg=$(rpm --dbpath "$db" -Kv --nosignature "$f" 2>&1 || true)
      if ! sed 's/#.*//' "$VT" | awk -v n="${nh% *}" -v h="${nh#* }" 'NF==6 && $1==n && $4==h {f=1} END {exit !f}' \
         || ! grep -q 'digest: OK' <<<"$dg" || grep -qE 'NOT OK|BAD' <<<"$dg"; then
        echo "REFUSED: $(basename "$f") is unsigned but not ours (vendor|release: $vr) and not a pinned vendor RPM ($VT); not signing it"
        exit 1
      fi
      echo "re-signing pinned vendor RPM: $(basename "$f") (${nh})"
    fi
    to_sign+=("$f")
  fi
done
if (( ${#to_sign[@]} )); then
  rpmsign --addsign --define "_gpg_name $FPR" --define "_gpg_digest_algo sha256" "${to_sign[@]}"
fi
bash "$here/make-repodata.sh" "$work"           # createrepo_c (+ modifyrepo_c for modules.yaml)
gpg --batch --yes --local-user "$FPR" --armor --detach-sign -o "$work/repodata/repomd.xml.asc" "$work/repodata/repomd.xml"
bash "$here/verify-repo.sh" "$work" "$K"
chmod 0755 "$work"
mv "$work" "$O"
trap 'rm -rf "$db"' EXIT
echo "SIGNED REPO: $O"

