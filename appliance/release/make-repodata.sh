#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# make-repodata.sh <dir>: build repodata for the RPMs in dir (createrepo_c). If dir/modules.yaml exists (written by
# stage-modules.sh: the vendor module documents of the streams the repo carries), add it as the "modules" metadata
# (modifyrepo_c) and remove the loose copy, so `dnf module enable` works from this repo alone. The file is moved out
# before createrepo_c, which would otherwise pick it up by itself (one explicit source of the modules record).
# Refuses modular RPMs (".module+"/".module_" in the RPM RELEASE tag, read with rpm -qp, not the file name) without
# modules.yaml: dnf could not enable their streams.
# Signs nothing; sign-repo.sh signs repomd.xml afterwards, which covers the modules metadata by checksum.
# RUN IT ON A COPY, never on the stage: it changes <dir> in place (writes repodata/, MOVES modules.yaml into it).
# sign-repo.sh runs it on its own temp work copy; a dry-run uses a temp copy of the stage.
set -Eeuo pipefail
R=$1
shopt -s nullglob
nmod=0
for f in "$R"/*.rpm; do
  rel=$(rpm -qp --nosignature --qf '%{RELEASE}' "$f" 2>/dev/null) || { echo "refusing: cannot read $f"; exit 1; }
  if [[ $rel == *.module[+_]* ]]; then nmod=$((nmod + 1)); fi
done
if (( nmod )) && [[ ! -f $R/modules.yaml ]]; then
  echo "refusing: $nmod modular RPM(s) in $R but no modules.yaml (run stage-modules.sh)"; exit 1
fi
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
if [[ -f $R/modules.yaml ]]; then mv "$R/modules.yaml" "$t/modules.yaml"; fi
createrepo_c --quiet "$R"
if [[ -f $t/modules.yaml ]]; then
  modifyrepo_c --mdtype=modules "$t/modules.yaml" "$R/repodata" >/dev/null
  n=$(grep -c '<data type="modules">' "$R/repodata/repomd.xml" || true)
  [[ $n == 1 ]] || { echo "refusing: repomd.xml has $n modules records, expected 1"; exit 1; }
fi
