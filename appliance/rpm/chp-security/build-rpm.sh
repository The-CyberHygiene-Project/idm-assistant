#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-rpm.sh (RUNS ON THE MAC): build chp-security's noarch RPM on aero into /data/chp-release/built/.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
ssh aero 'rm -rf /tmp/chpsec && mkdir -p /tmp/chpsec/SOURCES /tmp/chpsec/SPECS /data/chp-release/built'
scp -q "$here"/monitor.d/70-wazuh-service.sh "$here"/monitor.d/71-wazuh-agents.sh "$here"/monitor.d/72-wazuh-disk.sh \
  "$here"/chp-wazuh-alerts.service "$here"/chp-wazuh-retention.service "$here"/chp-wazuh-retention.timer \
  "$here"/wazuh-retention.sh "$here"/wazuh-manager.override.conf "$here"/wazuh-agent.override.conf "$top/LICENSE" \
  aero:/tmp/chpsec/SOURCES/
scp -q "$here/chp-security.spec" aero:/tmp/chpsec/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpsec" /tmp/chpsec/SPECS/chp-security.spec >/tmp/chpsec/build.log 2>&1 || { tail -20 /tmp/chpsec/build.log; exit 1; }
          cp /tmp/chpsec/RPMS/noarch/chp-security-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-security-*.rpm && rm -rf /tmp/chpsec'
