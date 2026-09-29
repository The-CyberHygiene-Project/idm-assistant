#!/usr/bin/env bash
# Runs ON build1: stage the built binaries + unit/sysusers/licences into tarballs, rpmbuild both specs, check.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; O=$HOME/step-build/out
rpmdev-setuptree
stage() {  # name version files...
  local n=$1 v=$2; shift 2; local S; S=$(mktemp -d)/staged; mkdir -p "$S"; cp "$@" "$S/"
  tar -czf ~/rpmbuild/SOURCES/$n-$v-staged.tar.gz -C "$(dirname "$S")" staged
}
stage step-ca 0.30.2 "$O/step-ca" "$O/LICENSE-step-ca" "$here/step-ca.service" "$here/step-ca.sysusers"
stage step-cli 0.31.0 "$O/step-cli" "$O/LICENSE-step-cli"
cp "$here"/step-ca.spec "$here"/step-cli.spec ~/rpmbuild/SPECS/
rpmbuild -bb ~/rpmbuild/SPECS/step-cli.spec >/dev/null
rpmbuild -bb ~/rpmbuild/SPECS/step-ca.spec >/dev/null
bash "$here/check-step.sh"

