#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# make-repodata.sh <dir>: build repodata for the RPMs in dir (createrepo_c). If dir/modules.yaml exists (written by
# stage-modules.sh: the vendor module documents of the streams the repo carries), add it as the "modules" metadata
# (modifyrepo_c) and remove the loose copy, so `dnf module enable` works from this repo alone. The file is moved out
# before createrepo_c, which would otherwise pick it up by itself (one explicit source of the modules record).
# Refuses modular RPMs (".module+" in the file name) without modules.yaml: dnf could not enable their streams.
# Signs nothing; sign-repo.sh signs repomd.xml afterwards, which covers the modules metadata by checksum.
set -Eeuo pipefail
R=$1
shopt -s nullglob
mod=("$R"/*.module+*.rpm)
if (( ${#mod[@]} )) && [[ ! -f $R/modules.yaml ]]; then
  echo "refusing: ${#mod[@]} modular RPM(s) in $R but no modules.yaml (run stage-modules.sh)"; exit 1
fi
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
if [[ -f $R/modules.yaml ]]; then mv "$R/modules.yaml" "$t/modules.yaml"; fi
createrepo_c --quiet "$R"
if [[ -f $t/modules.yaml ]]; then
  modifyrepo_c --mdtype=modules "$t/modules.yaml" "$R/repodata" >/dev/null
  n=$(grep -c '<data type="modules">' "$R/repodata/repomd.xml" || true)
  [[ $n == 1 ]] || { echo "refusing: repomd.xml has $n modules records, expected 1"; exit 1; }
fi
