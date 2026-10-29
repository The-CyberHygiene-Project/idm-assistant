#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 70-wazuh-service (security bundle spec §5): the Wazuh services this host's role needs are running. Never repairs.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
role=$(sed -n 's/^ROLE=//p' "$C" | head -1)
if [ "$role" = server ]; then units="wazuh-manager chp-wazuh-alerts"; else units="wazuh-agent"; fi
bad=0
for u in $units; do
  systemctl is-active --quiet "$u" || { echo "ALERT Wazuh $u is not running: systemctl status $u"; bad=1; }
done
[ "$bad" -eq 0 ] && echo "OK Wazuh services running ($units)"
exit 0
