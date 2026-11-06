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
  echo "ALERT Suricata is not running (after an upgrade: chp-site security enable; else systemctl status suricata)"; exit 0
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
# Counters are running totals per run, Suricata leaves zero counters out, and stats.log keeps earlier runs (final review
# I-1). So: split into blocks at "Date:" lines, keep only the current run (uptime rises), and judge the drops between the
# latest block and the newest one at least 15 minutes older (a past burst clears); a run younger than that is judged
# since it started. Fewer than 1000 packets in the window are not judged.
read -r dp dd mins < <(tail -n 4000 "$S" | awk -F'|' '
  /^Date:/ { n++; p[n] = 0; d[n] = 0; u = $0; sub(/.*uptime: /, "", u); gsub(/[^0-9 ]/, " ", u); split(u, x, " ")
             up[n] = x[1] * 86400 + x[2] * 3600 + x[3] * 60 + x[4]; next }
  n && $1 ~ /^capture\.kernel_packets[ \t]*$/ { p[n] = $3 + 0 }
  n && $1 ~ /^capture\.kernel_drops[ \t]*$/   { d[n] = $3 + 0 }
  END {
    if (!n) { print 0, 0, 0; exit }
    e = 0
    for (i = n - 1; i >= 1; i--) { if (up[i] >= up[n]) break; if (up[n] - up[i] >= 900) { e = i; break } }
    if (e) printf "%d %d %d\n", p[n] - p[e], d[n] - d[e], int((up[n] - up[e]) / 60)
    else   printf "%d %d -1\n", p[n], d[n]
  }')
if [ "${dp:-0}" -ge 1000 ] && [ $(( ${dd:-0} * 100 )) -gt "$dp" ]; then
  pct=$(awk -v d="$dd" -v p="$dp" 'BEGIN { printf "%.1f", d * 100 / p }')
  if [ "$mins" -lt 0 ]; then when="since it started"; else when="in the last $mins minutes"; fi
  echo "ALERT Suricata is dropping packets: $dd of $dp ($pct%) $when (host too busy, or too much traffic)"
  exit 0
fi
echo "OK Suricata running, stats ${age} min old, ${dd:-0} of ${dp:-0} packets dropped"
exit 0
