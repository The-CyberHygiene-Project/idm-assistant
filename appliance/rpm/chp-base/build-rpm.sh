#!/usr/bin/env bash
# build-rpm.sh (RUNS ON THE MAC): build chp-base's noarch RPM on aero into /data/chp-release/built/.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
ssh aero 'rm -rf /tmp/chpb && mkdir -p /tmp/chpb/SOURCES /tmp/chpb/SPECS /data/chp-release/built'
scp -q "$here"/firstboot-common.sh "$here"/monitor.sh "$here"/chp-firstboot-common.service "$here"/chp-monitor.service \
  "$here"/chp-monitor.timer "$here"/monitor.d/10-restorecon.sh "$here"/monitor.d/20-clock.sh "$top/LICENSE" aero:/tmp/chpb/SOURCES/
scp -q "$here/chp-base.spec" aero:/tmp/chpb/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpb" /tmp/chpb/SPECS/chp-base.spec >/tmp/chpb/build.log 2>&1 || { tail -20 /tmp/chpb/build.log; exit 1; }
          cp /tmp/chpb/RPMS/noarch/chp-base-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-base-*.rpm && rm -rf /tmp/chpb'
