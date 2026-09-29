#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# verify-repo.sh <repo-dir> <keys-dir>: every RPM carries a V4 RSA/SHA256 header signature by a PINNED key
# (<keys-dir>/trusted-keys.txt: "<fpr> <label> <file>"), and repodata/repomd.xml.asc is valid and made by the
# 'cyberhygiene' key. Prints one line per problem; exit 1 on any.
set -Eeuo pipefail
R=$1; K=$2
tmp=$(mktemp -d); db=$(mktemp -d); trap 'rm -rf "$tmp" "$db"' EXIT
export GNUPGHOME=$tmp/gnupg; mkdir -m 700 "$GNUPGHOME"
# rpm runs confined (SELinux rpm_t): it may only write rpm-labelled dirs, even a private --dbpath (denials are
# dontaudit-ed, so they look like plain EACCES/ENOENT). Label the private database directory rpm_var_lib_t.
chcon -t rpm_var_lib_t "$db" 2>/dev/null || true   # its own dir: rpm_t cannot traverse user_tmp_t parents
rpm --dbpath "$db" --initdb
bad=0; say() { echo "$*"; bad=1; }
chp=""
while read -r fpr label file; do
  [[ -z ${fpr:-} || $fpr == \#* ]] && continue
  got=$(gpg --batch --with-colons --import-options show-only --import "$K/$file" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
  [[ $got == "$fpr" ]] || { echo "KEY MISMATCH: $file is ${got:-unreadable}, pinned $fpr"; exit 1; }
  gpg --batch --quiet --import "$K/$file" 2>/dev/null
  rpm --dbpath "$db" --import "$K/$file"
  [[ $label == cyberhygiene ]] && chp=$fpr
done < "$K/trusted-keys.txt"
[[ -n $chp ]] || { echo "NO cyberhygiene key pinned in $K/trusted-keys.txt"; exit 1; }
shopt -s nullglob; n=0
for f in "$R"/*.rpm; do
  n=$((n + 1))
  out=$(rpm --dbpath "$db" -Kv "$f" 2>&1 || true)
  if ! grep -q 'Header V4 RSA/SHA256 Signature, key ID [0-9a-f]*: OK' <<<"$out" || grep -qE 'NOKEY|NOT OK|BAD' <<<"$out"; then
    say "BAD SIGNATURE: $(basename "$f")"
  fi
done
(( n > 0 )) || say "no RPMs in $R"
if [[ ! -f $R/repodata/repomd.xml.asc ]]; then say "MISSING repomd.xml.asc"
elif ! gpg --batch --status-fd 1 --verify "$R/repodata/repomd.xml.asc" "$R/repodata/repomd.xml" 2>/dev/null \
       | grep -qE "^\[GNUPG:\] VALIDSIG .* $chp\$"; then
  say "BAD repomd signature (must be by $chp)"
fi
(( bad == 0 )) || exit 1
echo "REPO OK: $n packages, all signed by pinned keys; repomd.xml signed by $chp"

