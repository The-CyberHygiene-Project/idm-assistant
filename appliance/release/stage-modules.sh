#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# stage-modules.sh <vendor-modules.yaml[.gz|.xz]> <MODULES.txt> <stage-dir>: write <stage-dir>/modules.yaml.
# The repo carries Rocky's modular RPMs (php:8.3, postgresql:16). Without module metadata `dnf module enable` finds
# nothing, so the repo carries the vendor's module documents for exactly those streams: the modulemd documents of the
# MODULES.txt streams ("<module> <stream>" lines), copied unchanged from the vendor metadata (Rocky's AppStream
# modules.yaml from the DVD), plus the vendor defaults of those modules cut down to the same streams. Refuses (exit 1,
# nothing written) when a listed stream is missing from the vendor metadata or has no RPM in the stage, when a modular
# RPM in the stage (".module+" in its release) is not an artifact of a listed stream, or when modulemd-validator
# rejects the result. make-repodata.sh (sign-repo.sh) adds the file to repodata before repomd.xml is signed.
# Shell + awk on purpose: aero's fapolicyd refuses untrusted Python files.
set -Eeuo pipefail
SRC=$1; LIST=$2; S=$3; OUT=$S/modules.yaml
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
die() { echo "refusing: $*"; exit 1; }
want=$(sed 's/#.*//' "$LIST" | awk 'NF==2{print $1":"$2} NF!=2 && NF{print "BAD:"$0}')
if grep -q '^BAD:' <<<"$want"; then die "bad line in $LIST: $(grep -m1 '^BAD:' <<<"$want" | cut -c5-)"; fi
shopt -s nullglob
for f in "$S"/*.rpm; do
  r=$(rpm -qp --nosignature --qf '%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}' "$f" 2>/dev/null | sed 's/-(none):/-0:/')
  if [[ $r == *.module+* ]]; then echo "$r"; fi
done | sort -u > "$tmp/modular"
if [[ -z $want ]]; then
  [[ ! -s $tmp/modular ]] || die "modular RPMs in the stage but no streams in $LIST: $(tr '\n' ' ' < "$tmp/modular")"
  exit 0
fi
case $(head -c 6 "$SRC" | od -An -tx1 | tr -d ' \n') in
  1f8b*) dec=(gzip -dc) ;; fd377a585a00) dec=(xz -dc) ;; *) dec=(cat) ;;
esac
# One pass over the vendor documents (separated by "---" / "..."). Keeps a wanted stream's modulemd document whole and
# writes its artifacts as "<module>:<stream> <nevra>"; keeps a wanted module's defaults with only the wanted streams'
# profile lines and default-stream line.
"${dec[@]}" "$SRC" > "$tmp/vendor" || die "cannot read $SRC"
awk -v want="$want" -v out="$tmp/out" -v arts="$tmp/arts" '
  BEGIN { n = split(want, w, "\n"); for (i = 1; i <= n; i++) { W[w[i]] = 1; split(w[i], p, ":"); M[p[1]] = 1; MS[p[1] ":" p[2]] = 1 } }
  function key(s) { sub(/^ +/, "", s); sub(/:.*/, "", s); gsub(/"/, "", s); return s }
  function flush(   i, keep, ln, k) {
    if (nl) {
      keep = (type == "modulemd" && ((name ":" stream) in W)) || (type == "modulemd-defaults" && (dmod in M))
      if (keep) {
        print "---" > out
        for (i = 1; i <= nl; i++) {
          ln = L[i]
          if (type == "modulemd-defaults") {
            if (ln ~ /^    [^ :]+: \[/ && !((dmod ":" key(ln)) in MS)) continue
            if (ln ~ /^  stream: /) { k = ln; sub(/^  stream: /, "", k); gsub(/"/, "", k); if (!((dmod ":" k) in MS)) continue }
          }
          print ln > out
        }
        print "..." > out
        if (type == "modulemd") { print name ":" stream > (arts ".found"); for (i = 1; i <= na; i++) print name ":" stream " " A[i] > arts }
      }
    }
    nl = na = art = 0; type = name = stream = dmod = ""
  }
  /^---$/ || /^\.\.\.$/ { flush(); next }
  { L[++nl] = $0 }
  /^document: / { type = $2 }
  /^  name: /   { name = $2 }
  /^  stream: / { stream = $2; gsub(/"/, "", stream) }
  /^  module: / { dmod = $2 }
  /^  [^ ]/     { art = ($0 ~ /^  artifacts:$/) }
  art && /^    - / { a = $0; sub(/^    - /, "", a); A[++na] = a }
  END { flush() }
' "$tmp/vendor"
touch "$tmp/arts" "$tmp/arts.found" "$tmp/out"
stray=$(cut -d' ' -f2 "$tmp/arts" | sort -u | comm -13 - "$tmp/modular")
[[ -z $stray ]] || die "modular RPMs not in any listed stream: $(tr '\n' ' ' <<<"$stray")"
for ws in $want; do
  grep -qx "$ws" "$tmp/arts.found" || die "$ws is not in $SRC"
  awk -v ws="$ws" '$1==ws{print $2}' "$tmp/arts" | sort -u | comm -12 - "$tmp/modular" | grep -q . \
    || die "no RPM of $ws is in the stage"
done
modulemd-validator "$tmp/out" >/dev/null 2>&1 || die "modulemd-validator rejects the cut-down metadata"
cp "$tmp/out" "$OUT.tmp"; mv "$OUT.tmp" "$OUT"
echo "  modules.yaml: $(tr '\n' ' ' <<<"$want")($(wc -l < "$tmp/modular") modular RPMs in the stage, all artifacts of these streams)"
