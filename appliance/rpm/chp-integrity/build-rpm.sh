#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-rpm.sh (RUNS ON THE MAC): build chp-integrity's noarch RPM on aero into /data/chp-release/built/.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
ssh aero 'rm -rf /tmp/chpi && mkdir -p /tmp/chpi/SOURCES /tmp/chpi/SPECS /data/chp-release/built'
scp -q "$here"/aide.conf "$here"/aide-check.sh "$here"/aide-baseline.sh "$here"/chp-aide-check.service \
  "$here"/chp-aide-check.timer "$here"/chp-aide-baseline.service "$here"/monitor.d/60-aide-result.sh \
  "$here"/monitor.d/61-aide-stale.sh "$here"/monitor.d/62-aide-pin.sh "$top/LICENSE" aero:/tmp/chpi/SOURCES/
scp -q "$here/chp-integrity.spec" aero:/tmp/chpi/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpi" /tmp/chpi/SPECS/chp-integrity.spec >/tmp/chpi/build.log 2>&1 || { tail -20 /tmp/chpi/build.log; exit 1; }
          cp /tmp/chpi/RPMS/noarch/chp-integrity-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-integrity-*.rpm && rm -rf /tmp/chpi'
