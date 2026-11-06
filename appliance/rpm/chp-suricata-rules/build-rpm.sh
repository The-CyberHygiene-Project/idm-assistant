#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-rpm.sh (RUNS ON THE MAC): build chp-suricata-rules on aero into /data/chp-release/built/: unpack the pinned
# ET Open (lab/inputs/fetch-et-open.sh), merge it with build-rules.py and disable.conf, take reference.config from the
# pinned EPEL suricata RPM (ET Open ships none), refuse any ET Pro SID, prove the result with `suricata -T` (every rule
# must load), and package it. Version = ET_DATE.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
f="$top/lab/inputs/fetch-et-open.sh"
V=$(sed -n 's/^ET_DATE=\([0-9.]*\).*/\1/p' "$f"); H=$(sed -n 's/^ET_SHA256=//p' "$f")
[[ $V =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$ && $H =~ ^[0-9a-f]{64}$ ]] || { echo "ET_DATE/ET_SHA256 not set in $f"; exit 1; }
ssh aero 'rm -rf /tmp/chpsr && mkdir -p /tmp/chpsr/SOURCES /tmp/chpsr/SPECS /tmp/chpsr/src /tmp/chpsr/epel /tmp/chpsr/log /data/chp-release/built'
z=$(mktemp -d); trap 'rm -rf "$z"' EXIT                # aero's fapolicyd blocks opening an unsigned .py: ship a zipapp
mkdir "$z/app"; cp "$here/build-rules.py" "$z/app/__main__.py"; python3 -m zipapp "$z/app" -o "$z/build-rules.pyz"
scp -q "$z/build-rules.pyz" "$here/disable.conf" "$here/NOTICE" aero:/tmp/chpsr/
scp -q "$here/chp-suricata-rules.spec" aero:/tmp/chpsr/SPECS/
ssh aero bash -s "$V" "$H" <<'REMOTE'
set -Eeuo pipefail
V=$1 H=$2 S=/tmp/chpsr/SOURCES T=/data/lab-inputs/et-open-$1.tar.gz
echo "$H  $T" | sha256sum -c --quiet || { echo "ET Open tarball does not match the pinned sha256"; exit 1; }
tar -xzf "$T" -C /tmp/chpsr/src --strip-components=1
python3 /tmp/chpsr/build-rules.pyz /tmp/chpsr/src /tmp/chpsr/disable.conf "$S"
R=$(ls /data/lab-inputs/rpms/suricata-7.*.el9.x86_64.rpm | sort -V | tail -1)
rpm -K "$R" | grep -q 'digests signatures OK' || { echo "the pinned suricata RPM $R does not verify"; exit 1; }
SV=$(rpm -qp --qf '%{VERSION}' "$R"); AV=$(suricata -V | grep -o '[0-9]*\.[0-9]*\.[0-9]*' | head -1)
[[ ${AV%.*} == "${SV%.*}" ]] || { echo "aero's suricata $AV is not the shipped $SV series: install the pinned RPM on aero"; exit 1; }
(cd /tmp/chpsr/epel && rpm2cpio "$R" | cpio -id --quiet ./etc/suricata/reference.config)
cp /tmp/chpsr/epel/etc/suricata/reference.config /tmp/chpsr/src/LICENSE /tmp/chpsr/NOTICE "$S/"; echo "$V" > "$S/ET_DATE"
[[ -s $S/classification.config ]] || { echo "ET Open has no classification.config"; exit 1; }
pro=$(grep -v '^#' "$S/chp-suricata.rules" | grep -oE '\bsid *: *28[0-9]{5} *;' | head -3 || true)
[[ -z $pro ]] || { echo "ET Pro SIDs (2800000-2900000, other licence) in the merged rules: $pro"; exit 1; }
cat > /tmp/chpsr/test.yaml <<YAML
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
default-log-dir: /tmp/chpsr/log
default-rule-path: $S
rule-files:
  - chp-suricata.rules
classification-file: $S/classification.config
reference-config-file: $S/reference.config
threshold-file: /tmp/chpsr/threshold.config
logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
YAML
: > /tmp/chpsr/threshold.config
suricata -T -c /tmp/chpsr/test.yaml -l /tmp/chpsr/log >/tmp/chpsr/test.log 2>&1 || { tail -20 /tmp/chpsr/test.log; exit 1; }
grep -E 'rules successfully loaded, 0 rules failed' /tmp/chpsr/test.log || { grep -iE 'error|failed' /tmp/chpsr/test.log | head; echo "suricata -T: not every rule loaded"; exit 1; }
! grep -E '^(W|E):' /tmp/chpsr/test.log || { echo "suricata -T: warnings or errors above"; exit 1; }
echo "suricata -T OK with $(suricata -V | head -1)"
rpmbuild -bb --define "_topdir /tmp/chpsr" --define "_sourcedir $S" --define "rules_version $V" \
  /tmp/chpsr/SPECS/chp-suricata-rules.spec >/tmp/chpsr/build.log 2>&1 || { tail -20 /tmp/chpsr/build.log; exit 1; }
cp /tmp/chpsr/RPMS/noarch/chp-suricata-rules-*.rpm /data/chp-release/built/
rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE} requires: ' /tmp/chpsr/RPMS/noarch/chp-suricata-rules-*.rpm; rpm -qpR /tmp/chpsr/RPMS/noarch/chp-suricata-rules-*.rpm | grep suricata | paste -sd' '
rm -rf /tmp/chpsr
REMOTE
