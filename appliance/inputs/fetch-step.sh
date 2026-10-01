#!/usr/bin/env bash
# fetch-step.sh (RUNS ON THE MAC ONLY): step-ca + step-cli sources, the Go toolchain their go.mod asks for, and their
# vendored modules, all pinned in MANIFEST.txt. GitHub tag archives are unsigned: their sha256 is pinned on first
# fetch (the kanidm precedent in lab/inputs). Go toolchains are checked against go.dev's published sha256 (TLS).
# Vendoring checks every module against the source's go.sum ('go mod verify') before 'go mod vendor'.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; MAN="$HERE/MANIFEST.txt"
D="${IDM_INPUTS:-$HOME/idm-lab-inputs}/appliance"; mkdir -p "$D"; cd "$D"
CA_V=0.30.2; CLI_V=0.31.0
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
bytes() { stat -f %z "$1"; }
: > "$MAN.tmp"
rec() { echo "$1|$2|$(bytes "$1")|$(sha "$1")|$3|$4" >> "$MAN.tmp"; }
[[ -s step-ca-$CA_V.tar.gz ]]  || curl -fL --retry 3 -o step-ca-$CA_V.tar.gz  https://github.com/smallstep/certificates/archive/refs/tags/v$CA_V.tar.gz
[[ -s step-cli-$CLI_V.tar.gz ]] || curl -fL --retry 3 -o step-cli-$CLI_V.tar.gz https://github.com/smallstep/cli/archive/refs/tags/v$CLI_V.tar.gz
# Go: the newest stable patch release of the highest minor that either go.mod asks for ('go' or 'toolchain' line)
want=$( { tar -xzOf step-ca-$CA_V.tar.gz certificates-$CA_V/go.mod; tar -xzOf step-cli-$CLI_V.tar.gz cli-$CLI_V/go.mod; } \
        | awk '$1=="go"||$1=="toolchain"{v=$2; sub(/^go/,"",v); print v}' | sort -V | tail -1)
minor=$(cut -d. -f1,2 <<<"$want")
curl -fsSL 'https://go.dev/dl/?mode=json&include=all' > go-releases.json
cat > pick-go.py <<'PY'
import json, sys
minor = sys.argv[1]; rel = json.load(open("go-releases.json"))
def key(v): return tuple(int(x) for x in v[2:].split("."))
cands = [r for r in rel if r["stable"] and (r["version"] == "go" + minor or r["version"].startswith("go" + minor + "."))]
r = max(cands, key=lambda r: key(r["version"]))
f = {(x["os"], x["arch"], x["kind"]): x for x in r["files"]}
l, m = f[("linux", "amd64", "archive")], f[("darwin", "arm64", "archive")]
print(r["version"], l["filename"], l["sha256"], m["filename"], m["sha256"])
PY
read -r GOV LNX LNX_SHA MAC MAC_SHA <<<"$(python3 pick-go.py "$minor")"
[[ -n ${MAC_SHA:-} ]] || { echo "could not pick a Go release for $minor"; exit 1; }
echo "Go: go.mod wants >= $want → $GOV"
for pair in "$LNX $LNX_SHA" "$MAC $MAC_SHA"; do
  read -r f s <<<"$pair"
  [[ -s $f ]] || curl -fL --retry 3 -o "$f" "https://go.dev/dl/$f"
  [[ $(sha "$f") == "$s" ]] || { echo "Go sha256 mismatch: $f"; exit 1; }
done
rm -rf go-mac && mkdir go-mac && tar -xzf "$MAC" -C go-mac
export GOROOT=$PWD/go-mac/go PATH=$PWD/go-mac/go/bin:$PATH GOTOOLCHAIN=local GOFLAGS=-mod=mod
vend() {  # tarball topdir out
  rm -rf src && mkdir src && tar -xzf "$1" -C src
  ( cd "src/$2" && go mod download && go mod verify && go mod vendor )
  COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$3" -C "src/$2" vendor
  rm -rf src
}
[[ -s step-ca-$CA_V-vendor.tar.gz ]]  || vend step-ca-$CA_V.tar.gz  certificates-$CA_V step-ca-$CA_V-vendor.tar.gz
[[ -s step-cli-$CLI_V-vendor.tar.gz ]] || vend step-cli-$CLI_V.tar.gz cli-$CLI_V        step-cli-$CLI_V-vendor.tar.gz
rec step-ca-$CA_V.tar.gz $CA_V "github smallstep/certificates tag v$CA_V" "sha256 pinned on first fetch (tag archive unsigned)"
rec step-cli-$CLI_V.tar.gz $CLI_V "github smallstep/cli tag v$CLI_V" "sha256 pinned on first fetch (tag archive unsigned)"
rec "$LNX" "${GOV#go}" "https://go.dev/dl/$LNX" "sha256 == go.dev published sha256"
rec "$MAC" "${GOV#go}" "https://go.dev/dl/$MAC" "sha256 == go.dev published sha256 (vendoring only)"
rec step-ca-$CA_V-vendor.tar.gz $CA_V "go mod vendor ($GOV)" "module hashes enforced by go.sum (go mod verify)"
rec step-cli-$CLI_V-vendor.tar.gz $CLI_V "go mod vendor ($GOV)" "module hashes enforced by go.sum (go mod verify)"
rm -rf go-mac go-releases.json pick-go.py
mv "$MAN.tmp" "$MAN"; cat "$MAN"

