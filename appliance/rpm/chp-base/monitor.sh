#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# monitor.sh: run every executable check in /usr/lib/chp/monitor.d (sorted). A check prints "OK <text>" or
# "ALERT <text>" lines and exits 0; a check that exits non-zero is itself an alert. Every ALERT goes to the journal
# (auth.warning, tag chp-monitor) and to the site's ALERT_HOOK when one is configured. Exit 1 if anything alerted.
set -uo pipefail
dir=${CHP_MONITOR_DIR:-/usr/lib/chp/monitor.d}
hook=$(chp-site get ALERT_HOOK 2>/dev/null || true)
alerts=0
alert() {
  alerts=$((alerts + 1))
  logger -p auth.warning -t chp-monitor "$1"
  if [ -n "$hook" ] && [ -x "$hook" ]; then "$hook" "$1" || true; fi
}
for c in "$dir"/*; do
  [ -f "$c" ] && [ -x "$c" ] || continue
  name=$(basename "$c")
  out=$("$c" 2>&1); rc=$?
  while IFS= read -r line; do
    case $line in ALERT\ *) alert "${line#ALERT }" ;; esac
  done <<< "$out"
  if [ "$rc" -ne 0 ]; then alert "$name failed (exit $rc)"; fi
done
[ "$alerts" -eq 0 ]
