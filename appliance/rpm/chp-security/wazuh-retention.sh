#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# wazuh-retention (spec §5): delete rotated Wazuh alert and archive logs older than RETENTION_DAYS (default 90).
set -u
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
days=$(sed -n 's/^RETENTION_DAYS=//p' "$C" 2>/dev/null | head -1); case $days in ''|*[!0-9]*) days=90 ;; esac
n=$(find /var/ossec/logs/alerts /var/ossec/logs/archives -type f -mtime +"$days" -print -delete 2>/dev/null | wc -l)
logger -t chp-wazuh "retention: removed $n alert/archive files older than $days days"
