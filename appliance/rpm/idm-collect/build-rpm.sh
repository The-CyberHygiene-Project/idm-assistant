#!/usr/bin/env bash
# build-rpm.sh (RUNS ON THE MAC): build idm-collect's noarch RPM on aero into /data/chp-release/built/.
set -Eeuo pipefail
top="$(cd "$(dirname "$0")/../../.." && pwd)"
ssh aero 'rm -rf /tmp/idmc && mkdir -p /tmp/idmc/SOURCES /tmp/idmc/SPECS /data/chp-release/built'
scp -q "$top/collector/idm-collect" "$top/collector/redact.sed" "$top/LICENSE" aero:/tmp/idmc/SOURCES/
scp -q "$top/appliance/rpm/idm-collect/idm-collect.spec" aero:/tmp/idmc/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/idmc" /tmp/idmc/SPECS/idm-collect.spec >/tmp/idmc/build.log 2>&1 || { tail -20 /tmp/idmc/build.log; exit 1; }
          cp /tmp/idmc/RPMS/noarch/idm-collect-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/idm-collect-*.rpm && rm -rf /tmp/idmc'

