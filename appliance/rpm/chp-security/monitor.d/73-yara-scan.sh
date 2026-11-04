#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 73-yara-scan (YARA spec §5): the weekly full scan has completed within the last 8 days.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}; S=${CHP_YARA_STATE:-/var/lib/chp/yara}; now=${CHP_NOW:-$(date +%s)}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
limit=$((8 * 86400))
if [ -f "$S/last-full" ]; then
  last=$(tr -dc '0-9' < "$S/last-full")
  if [ -n "$last" ] && [ $((now - last)) -le $limit ]; then echo "OK weekly YARA scan completed $(( (now - last) / 86400 )) days ago"
  else echo "ALERT the weekly YARA scan has not completed in 8 days (systemctl status chp-yara-fullscan)"; fi
else
  since=$(date -r "$C" +%s)                      # works with GNU and BSD date
  if [ $((now - since)) -le $limit ]; then echo "OK first weekly YARA scan not due yet"
  else echo "ALERT the weekly YARA scan has never completed (after an upgrade: chp-site security enable; else systemctl status chp-yara-fullscan)"; fi
fi
# Final review I2: the 5-minute scan is the main path; a mark older than 30 minutes means it has stopped or keeps failing.
if [ -f "$S/last-recent" ]; then
  r=$(tr -dc '0-9' < "$S/last-recent")
  if [ -n "$r" ] && [ $((now - r)) -gt 1800 ]; then
    echo "ALERT the 5-minute YARA scan has not succeeded for $(( (now - r) / 60 )) minutes (journalctl -u chp-yara-recent)"
  fi
elif [ $((now - $(date -r "$C" +%s))) -gt 1800 ]; then
  echo "ALERT the 5-minute YARA scan has never succeeded (run chp-site security enable, then journalctl -u chp-yara-recent)"
fi
exit 0
