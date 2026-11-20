#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# stage-vendor.sh <vendor.rpm> <vendor-key-file> <third-party-dir> (RUNS ON AERO): put a vendor RPM that the repo
# carries RE-SIGNED (VENDOR.txt) into the third-party dir, UNSIGNED, for sign-repo.sh to sign with the project key.
# Refuses (exit 1, nothing copied) unless ALL of these hold, in this order:
#   1. the file's sha256 is a VENDOR.txt pin (the vendor-signed file, exactly);
#   2. the key file holds exactly one primary key, with the fingerprint VENDOR.txt names for that line;
#   3. rpm verifies the vendor's signature with that key alone (a private rpm database), digests OK;
#   4. name, version-release and %{SHA256HEADER} are the pinned ones.
# Then the copy's signature is removed (rpmsign --delsign) and checked: unsigned, digests OK, header sha256
# unchanged. The download itself is not done here (a live step: Task 11). $CHP_VENDOR_TXT: another VENDOR.txt.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
F=$1; KEY=$2; OUT=$3; V=${CHP_VENDOR_TXT:-$here/VENDOR.txt}
die() { echo "refusing: $*"; exit 1; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
[[ -f $F ]] || die "$F is not a file"
[[ -d $OUT ]] || die "$OUT is not a folder"
got=$(sha "$F")
line=$(sed 's/#.*//' "$V" | awk -v s="$got" 'NF==6 && $3==s')
[[ $(grep -c . <<<"$line") == 1 ]] || die "$F (sha256 $got) is not a vendor file pinned in $V"
read -r name vr _ hdr fpr _src <<<"$line"
tmp=$(mktemp -d); db=$(mktemp -d); trap 'rm -rf "$tmp" "$db"' EXIT
export GNUPGHOME=$tmp/gnupg; mkdir -m 700 "$GNUPGHOME"
show=$(gpg --batch --with-colons --import-options show-only --import "$KEY" 2>/dev/null) || die "cannot read $KEY"
[[ $(grep -c '^pub' <<<"$show") == 1 ]] || die "$KEY must hold exactly one primary key"
kf=$(awk -F: '/^fpr/{print $10; exit}' <<<"$show")
[[ $kf == "$fpr" ]] || die "$KEY is ${kf:-unreadable}, $V pins $fpr for $name"
chcon -t rpm_var_lib_t "$db" 2>/dev/null || true      # rpm runs confined (rpm_t): see sign-repo.sh
rpm --dbpath "$db" --initdb
rpm --dbpath "$db" --import "$KEY"
out=$(rpm --dbpath "$db" -Kv "$F" 2>&1 || true)
kid=$(tr 'A-F' 'a-f' <<<"${fpr: -8}")
grep -qE "Signature, key ID $kid: OK" <<<"$out" || die "$F is not signed by $fpr: $(tr '\n' ' ' <<<"$out" | cut -c1-200)"
! grep -qE 'NOKEY|NOT OK|BAD' <<<"$out" || die "$F: rpm -Kv reports a problem: $(tr '\n' ' ' <<<"$out" | cut -c1-200)"
q() { rpm --dbpath "$db" -qp --nosignature --qf "$1" "$2" 2>/dev/null; }
[[ $(q '%{NAME}' "$F") == "$name" ]] || die "$F is $(q '%{NAME}' "$F"), not $name"
[[ $(q '%{VERSION}-%{RELEASE}' "$F") == "$vr" ]] || die "$F is $(q '%{VERSION}-%{RELEASE}' "$F"), not $vr"
[[ $(q '%{SHA256HEADER}' "$F") == "$hdr" ]] || die "$F's header sha256 is not the pinned $hdr"
dst=$OUT/$name-$vr.$(q '%{ARCH}' "$F").rpm
[[ ! -e $dst ]] || die "$dst exists"
cp "$F" "$tmp/x.rpm"
rpmsign --delsign "$tmp/x.rpm" >/dev/null
after=$(rpm --dbpath "$db" -Kv "$tmp/x.rpm" 2>&1 || true)
! grep -q 'Signature, key ID' <<<"$after" || die "the vendor signature is still there after rpmsign --delsign"
grep -q 'digest: OK' <<<"$after" && ! grep -qE 'NOT OK|BAD' <<<"$after" || die "digests not OK after --delsign"
[[ $(q '%{SHA256HEADER}' "$tmp/x.rpm") == "$hdr" ]] || die "the header sha256 changed with --delsign"
mv "$tmp/x.rpm" "$dst"
echo "STAGED (unsigned, for sign-repo.sh): $dst  [$name $vr, vendor signature by $fpr verified, header $hdr]"
