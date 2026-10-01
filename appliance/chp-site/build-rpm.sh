#!/usr/bin/env bash
# build-rpm.sh (RUNS ON THE MAC): build the chp-site zipapp, then its noarch RPM on aero into /data/chp-release/built/.
set -Eeuo pipefail
top="$(cd "$(dirname "$0")/../.." && pwd)"
bash "$top/appliance/chp-site/build.sh" >/dev/null
ssh aero 'rm -rf /tmp/chps && mkdir -p /tmp/chps/SOURCES /tmp/chps/SPECS /data/chp-release/built'
scp -q "$top/appliance/chp-site/dist/chp-site.pyz" "$top/appliance/chp-site/chp.repo" \
  "$top/appliance/release/RPM-GPG-KEY-cyberhygiene" "$top/LICENSE" "$top/appliance/chp-site/chp-site.sh" aero:/tmp/chps/SOURCES/
scp -q "$top/appliance/chp-site/chp-site.spec" aero:/tmp/chps/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chps" /tmp/chps/SPECS/chp-site.spec >/tmp/chps/build.log 2>&1 || { tail -20 /tmp/chps/build.log; exit 1; }
          cp /tmp/chps/RPMS/noarch/chp-site-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-site-*.rpm && rm -rf /tmp/chps'
