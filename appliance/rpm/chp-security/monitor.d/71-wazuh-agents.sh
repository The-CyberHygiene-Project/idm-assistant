#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 71-wazuh-agents (spec §5): on the server, every client agent is connected (Wazuh marks one Disconnected after 10 min).
# Backstop for the forwarder's immediate lifecycle alerts.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}; AC=${CHP_AGENT_CONTROL:-/var/ossec/bin/agent_control}
[ -f "$C" ] && [ "$(sed -n 's/^ROLE=//p' "$C" | head -1)" = server ] || { echo "OK agent check: not a Wazuh server"; exit 0; }
out=$("$AC" -l 2>&1) || { echo "ALERT Wazuh agent_control failed: $out"; exit 0; }
bad=0
while IFS= read -r ln; do
  case $ln in *"ID: 000,"*) continue ;; esac
  id=$(sed -n 's/.*ID: \([0-9]*\),.*/\1/p' <<<"$ln"); name=$(sed -n 's/.*Name: \([^,]*\),.*/\1/p' <<<"$ln")
  case $ln in
    *", Disconnected"*) echo "ALERT Wazuh agent $name ($id) is disconnected"; bad=1 ;;
    *", Never connected"*) echo "ALERT Wazuh agent $name ($id) has never connected"; bad=1 ;;
  esac
done <<<"$out"
[ "$bad" -eq 0 ] && echo "OK Wazuh agents connected"
exit 0
