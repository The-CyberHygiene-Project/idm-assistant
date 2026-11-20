#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-rpm.sh (RUNS ON THE MAC): build chp-onlyoffice's noarch RPM on aero into /data/chp-release/built/. No PHP or
# Python content, so it builds the normal way (as chp-documents does). The vendor RPM it requires is NOT built here:
# appliance/release/stage-vendor.sh checks and stages it (VENDOR.txt).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
ssh aero 'rm -rf /tmp/chpoo && mkdir -p /tmp/chpoo/SOURCES /tmp/chpoo/SPECS /data/chp-release/built'
scp -q "$here"/onlyoffice-ai-off.sh "$here"/DesktopEditors.conf "$here"/nft/chp-workstation-egress.nft \
  "$here"/chp-workstation-egress.service "$here"/chp-onlyoffice-sweep.service "$here"/chp-onlyoffice-sweep.timer \
  "$here"/logind-chp-docs.conf "$here"/50-chp-no-linger.rules "$here"/README.md "$top/LICENSE" aero:/tmp/chpoo/SOURCES/
scp -q "$here/chp-onlyoffice.spec" aero:/tmp/chpoo/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpoo" /tmp/chpoo/SPECS/chp-onlyoffice.spec >/tmp/chpoo/build.log 2>&1 || { tail -20 /tmp/chpoo/build.log; exit 1; }
          cp /tmp/chpoo/RPMS/noarch/chp-onlyoffice-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-onlyoffice-*.rpm
          rpm -qp --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" /data/chp-release/built/chp-onlyoffice-*.rpm
          rpm -qp --scripts --triggers /data/chp-release/built/chp-onlyoffice-*.rpm | grep -c onlyoffice-ai-off
          sha256sum /data/chp-release/built/chp-onlyoffice-*.rpm; rm -rf /tmp/chpoo'
