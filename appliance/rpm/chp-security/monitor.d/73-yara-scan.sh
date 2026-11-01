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
  else echo "ALERT the weekly YARA scan has never completed (systemctl status chp-yara-fullscan)"; fi
fi
exit 0
