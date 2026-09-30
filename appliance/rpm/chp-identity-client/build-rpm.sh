#!/usr/bin/env bash
# build-rpm.sh (RUNS ON THE MAC): compile the chp_kanidm policy and build chp-identity-client's noarch RPM on aero into
# /data/chp-release/built/.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
ssh aero 'rm -rf /tmp/chpc && mkdir -p /tmp/chpc/SOURCES /tmp/chpc/SPECS /tmp/chpc/se /data/chp-release/built'
scp -q "$here"/selinux/chp_kanidm.te "$here"/selinux/chp_kanidm.fc aero:/tmp/chpc/se/
ssh aero 'cd /tmp/chpc/se && checkmodule -M -m -o chp_kanidm.mod chp_kanidm.te && semodule_package -o /tmp/chpc/SOURCES/chp_kanidm.pp -m chp_kanidm.mod -f chp_kanidm.fc'
scp -q "$here"/client-enrol.sh "$here"/client-accounts.sh "$here"/diag-collect.sh "$here"/client-firstboot.sh \
  "$here"/chp-client-firstboot.service "$here"/unixd.toml.in "$here"/sshd-10-chp.conf "$here"/sshd-99-chp-exceptions.conf \
  "$here"/monitor.d/*.sh "$top/LICENSE" aero:/tmp/chpc/SOURCES/
scp -q "$here/chp-identity-client.spec" aero:/tmp/chpc/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpc" /tmp/chpc/SPECS/chp-identity-client.spec >/tmp/chpc/build.log 2>&1 || { tail -20 /tmp/chpc/build.log; exit 1; }
          cp /tmp/chpc/RPMS/noarch/chp-identity-client-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-identity-client-*.rpm && rm -rf /tmp/chpc'
