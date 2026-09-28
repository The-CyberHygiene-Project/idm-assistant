#!/usr/bin/env bash
# Runs ON build1: stage the built outputs + upstream assets into a tarball, then rpmbuild.
set -Eeuo pipefail
W=$HOME/kanidm-build; R=$W/target/release; SRC=$W/src; here="$(cd "$(dirname "$0")" && pwd)"
rpmdev-setuptree
S=$(mktemp -d)/staged; mkdir -p "$S/bin" "$S/ui" "$S/units" "$S/examples"
cp "$R"/{kanidmd,kanidm,kanidm_unixd,kanidm_unixd_tasks,kanidm-unix,kanidm_ssh_authorizedkeys,kanidm_ssh_authorizedkeys_direct,libpam_kanidm.so,libnss_kanidm.so} "$S/bin/"
cp -a "$SRC/server/core/static/." "$S/ui/"
cp "$here"/units/*.service "$S/units/"
cp "$SRC/examples/server.toml" "$S/examples/"
cp "$SRC/examples/unixd-safe-default" "$S/examples/unixd"
cp "$SRC/examples/kanidm-safe-default" "$S/examples/kanidm"
tar -czf ~/rpmbuild/SOURCES/kanidm-1.11.2-staged.tar.gz -C "$(dirname "$S")" staged
cp "$here/kanidm.spec" ~/rpmbuild/SPECS/
rpmbuild -bb ~/rpmbuild/SPECS/kanidm.spec
cd ~/rpmbuild/RPMS/x86_64
# Review Focus #4: every path PAM, NSS, systemd and the release_linux profile expect must be in a package.
missing=0
listing=$(mktemp); rpm -qpl kanidm-*-1.11.2-*.rpm > "$listing"   # list once: grep -q on a pipe + pipefail = false alarms
while read -r f; do
  [[ -z $f || $f == \#* ]] && continue
  grep -qxF "$f" "$listing" || { echo "MISSING from RPMs: $f"; missing=1; }
done < "$here/expected-files.txt"
(( missing == 0 )) || exit 1
echo "RPMS OK: all expected files packaged"; ls -la
