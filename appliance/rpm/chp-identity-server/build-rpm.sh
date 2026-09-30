#!/usr/bin/env bash
# build-rpm.sh (RUNS ON THE MAC): build chp-identity-server's noarch RPM on aero into /data/chp-release/built/.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
ssh aero 'rm -rf /tmp/chpi && mkdir -p /tmp/chpi/SOURCES /tmp/chpi/SPECS /data/chp-release/built'
scp -q "$here"/server-firstboot.sh "$here"/chp-server-firstboot.service "$here"/cert-renew-kanidm.sh "$here"/cert-renew-kanidm.service \
  "$here"/cert-renew-kanidm.timer "$here"/kanidmd-tls.conf "$here"/kanidm-login.exp "$here"/monitor.d/*.sh "$top/LICENSE" aero:/tmp/chpi/SOURCES/
scp -q "$here/chp-identity-server.spec" aero:/tmp/chpi/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpi" /tmp/chpi/SPECS/chp-identity-server.spec >/tmp/chpi/build.log 2>&1 || { tail -20 /tmp/chpi/build.log; exit 1; }
          cp /tmp/chpi/RPMS/noarch/chp-identity-server-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-identity-server-*.rpm && rm -rf /tmp/chpi'
