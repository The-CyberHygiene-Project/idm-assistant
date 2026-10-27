#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 72-wazuh-disk (spec §5): the Wazuh data directory's file system is below 80% (it shares the root volume or /data).
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
d=$(sed -n 's/^DATA_DIR=//p' "$C" | head -1); d=${d:-/var/ossec}
pct=$(df --output=pcent "$d" 2>/dev/null | tail -1 | tr -dc '0-9')
case $pct in ''|*[!0-9]*) echo "ALERT Wazuh data directory $d: cannot read its disk use"; exit 0 ;; esac
if [ "$pct" -ge 80 ]; then echo "ALERT Wazuh data directory $d is $pct% full (limit 80%): check alert retention"
else echo "OK Wazuh data directory $d $pct% full"; fi
exit 0
