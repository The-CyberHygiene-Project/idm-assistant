#!/usr/bin/env bash
# Runs ON build1: build step-ca and step (cli) OFFLINE with the pinned Go toolchain. CGO off, vendored modules only,
# no toolchain switching. Go's FIPS 140-3 module is selected at build time: GOFIPS140=v1.0.0 (the frozen module
# snapshot) makes fips140=on the binary's default; the unit still sets GODEBUG=fips140=on explicitly (row 13).
set -Eeuo pipefail
IN=$HOME/inputs/appliance; W=$HOME/step-build; CA_V=0.30.2; CLI_V=0.31.0
GO_TGZ=$(ls "$IN"/go*.linux-amd64.tar.gz); [[ $(wc -l <<<"$GO_TGZ") -eq 1 ]] || { echo "want exactly one Go toolchain"; exit 1; }
rm -rf "$W"; mkdir -p "$W/src" "$W/out"
tar -xzf "$GO_TGZ" -C "$W"
export GOROOT=$W/go PATH=$W/go/bin:$PATH GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off GONOSUMDB='*' \
       CGO_ENABLED=0 GOCACHE=$W/cache GOPATH=$W/gopath GOFIPS140=${GOFIPS140:-v1.0.0}
go version | awk '{print $3}' > "$W/go-version.txt"
{ go version; echo "GOFIPS140=$GOFIPS140"; ls "$GOROOT/lib/fips140" 2>/dev/null; } | tee "$W/toolchain.txt"
bt=$(date -u +%Y-%m-%dT%H:%MZ)
build() {  # tarball topdir pkg out version
  tar -xzf "$IN/$1.tar.gz" -C "$W/src"; tar -xzf "$IN/$1-vendor.tar.gz" -C "$W/src/$2"
  ( cd "$W/src/$2" && go build -trimpath -ldflags "-s -w -X main.Version=$5 -X main.BuildTime=$bt" -o "$W/out/$4" "$3" )
  cp "$W/src/$2/LICENSE" "$W/out/LICENSE-$4"
}
build step-ca-$CA_V   certificates-$CA_V ./cmd/step-ca step-ca  $CA_V
build step-cli-$CLI_V cli-$CLI_V         ./cmd/step    step-cli $CLI_V
"$W/out/step-ca" version; "$W/out/step-cli" version
echo "BUILD OK"

