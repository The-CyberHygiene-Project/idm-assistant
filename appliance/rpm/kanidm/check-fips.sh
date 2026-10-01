#!/usr/bin/env bash
# Runs ON build1: the TLS-carrying binaries in THIS spec's RPMs must contain the AWS-LC FIPS module (ISSO #14:
# server AND unixd). Extracts from the RPMs, not from the build tree: we check what ships.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; D="${1:-$HOME/rpmbuild/RPMS/x86_64}"
VR=$(rpmspec -q --qf '%{version}-%{release}\n' "$here/kanidm.spec" 2>/dev/null | head -1)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for p in server clients unixd; do ( cd "$tmp" && rpm2cpio "$D/kanidm-$p-$VR.x86_64.rpm" | cpio -idmu --quiet ); done
bad=0
for b in usr/sbin/kanidmd usr/bin/kanidm usr/sbin/kanidm_unixd usr/sbin/kanidm_ssh_authorizedkeys_direct; do   # every binary that does TLS via rustls
  strings "$tmp/$b" > "$tmp/strings.txt"     # never `strings | grep -q` under pipefail: SIGPIPE = false "NOT FIPS"
  if grep -q 'AWS-LC FIPS 4.2.0' "$tmp/strings.txt"; then echo "FIPS OK   $b"; else echo "NOT FIPS  $b"; bad=1; fi
done
(( bad == 0 )) || exit 1
echo "FIPS VARIANT OK ($VR)"

