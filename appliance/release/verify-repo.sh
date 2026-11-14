#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# verify-repo.sh <repo-dir> <keys-dir> [MODULES.txt]: every RPM carries a V4 RSA/SHA256 header signature by a PINNED
# key (<keys-dir>/trusted-keys.txt: "<fpr> <label> <file>"), and repodata/repomd.xml.asc is valid and made by the
# 'cyberhygiene' key. repomd.xml is what the signature covers, so everything else is checked against it: every
# repodata file's sha256 equals its repomd checksum; the *.rpm files in the repo are exactly the packages of
# primary.xml (none extra, none missing); the modules record (at most one) carries exactly the MODULES.txt streams
# (default: MODULES.txt next to this script, or $CHP_MODULES_TXT), its defaults only listed modules, and a repo with
# modular RPMs (".module+"/".module_" in the RPM RELEASE tag) has one. Prints one line per problem; exit 1 on any.
set -Eeuo pipefail
R=$1; K=$2
here="$(cd "$(dirname "$0")" && pwd)"
MT=${3:-${CHP_MODULES_TXT:-$here/MODULES.txt}}
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
  show=$(gpg --batch --with-colons --import-options show-only --import "$K/$file" 2>/dev/null)
  npub=$(grep -c '^pub' <<<"$show" || true)
  [[ $npub == 1 ]] || { echo "KEY FILE HOLDS $npub KEYS: $file (pin exactly one primary key per file)"; exit 1; }
  got=$(awk -F: '/^fpr/{print $10; exit}' <<<"$show")
  [[ $got == "$fpr" ]] || { echo "KEY MISMATCH: $file is ${got:-unreadable}, pinned $fpr"; exit 1; }
  gpg --batch --quiet --import "$K/$file" 2>/dev/null
  rpm --dbpath "$db" --import "$K/$file"
  [[ $label == cyberhygiene ]] && chp=$fpr
  ids="${ids:-} $(tr 'A-F' 'a-f' <<<"${fpr: -8}")"   # rpm prints the SHORT (8-hex) key ID; only pinned keys are in this db
done < "$K/trusted-keys.txt"
[[ -n $chp ]] || { echo "NO cyberhygiene key pinned in $K/trusted-keys.txt"; exit 1; }
shopt -s nullglob; n=0; nmod=0
for f in "$R"/*.rpm; do
  n=$((n + 1))
  rel=$(rpm -qp --nosignature --qf '%{RELEASE}' "$f" 2>/dev/null || true)
  if [[ $rel == *.module[+_]* ]]; then nmod=$((nmod + 1)); fi
  out=$(rpm --dbpath "$db" -Kv "$f" 2>&1 || true)
  kid=$(sed -n 's/.*Header V[34] RSA\/SHA256 Signature, key ID \([0-9a-f]*\): OK.*/\1/p' <<<"$out" | head -n 1)
  # rpm names the (sub)key that made the signature: it must be a pinned PRIMARY key, never a subkey
  if [[ -z $kid || " $ids " != *" $kid "* ]] || grep -qE 'NOKEY|NOT OK|BAD' <<<"$out"; then
    say "BAD SIGNATURE: $(basename "$f")"
  fi
done
(( n > 0 )) || say "no RPMs in $R"
unz() { case $(head -c 6 "$1" | od -An -tx1 | tr -d ' \n') in
          1f8b*) gzip -dc "$1" ;; fd377a585a00) xz -dc "$1" ;; 28b52ffd*) zstd -dcq "$1" ;; 425a68*) bzip2 -dc "$1" ;; *) cat "$1" ;;
        esac; }
RM=$R/repodata/repomd.xml
if [[ -f $RM ]]; then
  # one line per record: <type> <checksum-type> <checksum> <href> (createrepo_c/modifyrepo_c write one element per line)
  recs=$(awk '/<data type="/      { t = $0; sub(/.*<data type="/, "", t); sub(/".*/, "", t); ct = c = h = "" }
              /<checksum type="/  { ct = $0; sub(/.*<checksum type="/, "", ct); sub(/".*/, "", ct)
                                    c = $0; sub(/.*<checksum[^>]*>/, "", c); sub(/<.*/, "", c) }
              /<location href="/  { h = $0; sub(/.*<location href="/, "", h); sub(/".*/, "", h) }
              /<\/data>/          { print t, (ct == "" ? "-" : ct), (c == "" ? "-" : c), (h == "" ? "-" : h) }' "$RM")
  [[ -n $recs ]] || say "repomd.xml lists no metadata"
  while read -r typ ct sum href; do
    [[ -n ${typ:-} ]] || continue
    if [[ $ct != sha256 ]]; then say "repodata $typ: checksum type $ct, want sha256"; continue; fi
    if [[ $href != repodata/* || $href == *..* ]]; then say "repodata $typ: unexpected location $href"; continue; fi
    if [[ ! -f $R/$href ]]; then say "MISSING repodata file: $href ($typ)"; continue; fi
    [[ $(sha256sum "$R/$href" | cut -d' ' -f1) == "$sum" ]] || say "BAD repodata checksum: $typ ($href)"
  done <<<"$recs"
  # the RPM files == the packages primary.xml lists (an extra file is not what the signed metadata describes)
  ph=$(awk '$1 == "primary" { print $4 }' <<<"$recs")
  if [[ $(grep -c . <<<"$ph") != 1 || ! -f $R/$ph ]]; then say "repomd.xml: no single primary record"
  else
    unz "$R/$ph" | grep -o '<location href="[^"]*"' | sed 's/^<location href="//; s/"$//' | sort > "$tmp/listed" || true
    for f in "$R"/*.rpm; do basename "$f"; done | sort > "$tmp/have"
    while read -r x; do [[ -n $x ]] && say "EXTRA RPM not in primary.xml: $x"; done < <(comm -13 "$tmp/listed" "$tmp/have")
    while read -r x; do [[ -n $x ]] && say "MISSING RPM listed in primary.xml: $x"; done < <(comm -23 "$tmp/listed" "$tmp/have")
  fi
  # module streams: the modules record must carry exactly the MODULES.txt streams
  if [[ -r $MT ]]; then
    want=$(sed 's/#.*//' "$MT" | awk '$1=="vendor-sha256"{next} NF==2{print $1":"$2}' | sort -u)
  else say "cannot read MODULES.txt ($MT)"; want=""; fi
  mh=$(awk '$1 == "modules" { print $4 }' <<<"$recs")
  nm=$(grep -c . <<<"$mh" || true)
  if (( nm > 1 )); then say "repomd.xml has $nm modules records, expected at most 1"
  elif (( nm == 1 )); then
    if [[ -f $R/$mh ]]; then
      unz "$R/$mh" | awk '/^document: / { t = $2 } /^  name: / && t == "modulemd" { n = $2; gsub(/"/, "", n) }
                          /^  stream: / && t == "modulemd" { s = $2; gsub(/"/, "", s) }
                          /^  module: / && t == "modulemd-defaults" { d = $2; gsub(/"/, "", d) }
                          /^\.\.\.$/ { if (t == "modulemd") print "S " n ":" s; if (t == "modulemd-defaults") print "D " d; t = n = s = d = "" }' \
        > "$tmp/mods" || true
      got=$(awk '$1 == "S" { print $2 }' "$tmp/mods" | sort -u)
      if [[ $got != "$want" ]]; then
        say "MODULES MISMATCH: the modules record carries [$(tr '\n' ' ' <<<"$got")] but $MT lists [$(tr '\n' ' ' <<<"$want")]"
      fi
      while read -r d; do
        [[ -n $d ]] && ! grep -q "^$d:" <<<"$want" && say "MODULES MISMATCH: defaults for unlisted module $d"
      done < <(awk '$1 == "D" { print $2 }' "$tmp/mods")
    fi
  else
    (( nmod == 0 )) || say "MISSING modules metadata ($nmod modular RPMs)"
    [[ -z $want ]] || say "MISSING modules metadata ($MT lists $(tr '\n' ' ' <<<"$want"))"
  fi
else
  say "MISSING repodata/repomd.xml"
fi
if [[ ! -f $R/repodata/repomd.xml.asc ]]; then say "MISSING repomd.xml.asc"
elif ! gpg --batch --status-fd 1 --verify "$R/repodata/repomd.xml.asc" "$R/repodata/repomd.xml" 2>/dev/null \
       | grep -qE "^\[GNUPG:\] VALIDSIG .* $chp\$"; then
  say "BAD repomd signature (must be by $chp)"
fi
(( bad == 0 )) || exit 1
echo "REPO OK: $n packages, all signed by pinned keys; repomd.xml signed by $chp"

