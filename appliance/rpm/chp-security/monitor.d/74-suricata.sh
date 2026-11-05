#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 74-suricata (Suricata spec §5): the IDS is running, still capturing (stats.log written every 60 s), and the kernel is
# not dropping more than 1 % of the packets it hands to Suricata.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}; L=${CHP_SURICATA_LOG_DIR:-/var/log/suricata}
now=${CHP_NOW:-$(date +%s)}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
if ! systemctl is-active --quiet suricata; then
  echo "ALERT Suricata is not running (systemctl status suricata; journalctl -u suricata)"; exit 0
fi
S="$L/stats.log"
if [ ! -f "$S" ]; then
  echo "ALERT Suricata is running but has written no stats yet (check the capture interface: /var/log/suricata/suricata.log)"
  exit 0
fi
age=$(( (now - $(date -r "$S" +%s)) / 60 ))         # works with GNU and BSD date
if [ "$age" -gt 10 ]; then
  echo "ALERT Suricata is running but has written no stats for $age minutes (check the capture interface)"; exit 0
fi
# Counters are running totals and Suricata leaves zero counters out: take the last value of each, missing = 0.
read -r pk dr < <(tail -n 400 "$S" | awk -F'|' '
  $1 ~ /^capture\.kernel_packets[ \t]*$/ { p = $3 + 0 }
  $1 ~ /^capture\.kernel_drops[ \t]*$/   { d = $3 + 0 }
  END { printf "%d %d\n", p, d }')
if [ "${pk:-0}" -gt 0 ] && [ $(( dr * 100 )) -gt "$pk" ]; then
  pct=$(awk -v d="$dr" -v p="$pk" 'BEGIN { printf "%.1f", d * 100 / p }')
  echo "ALERT Suricata is dropping packets: $dr of $pk ($pct%) since it started (host too busy, or too much traffic)"
  exit 0
fi
echo "OK Suricata running, stats ${age} min old, ${pk:-0} packets, ${dr:-0} dropped"
exit 0
