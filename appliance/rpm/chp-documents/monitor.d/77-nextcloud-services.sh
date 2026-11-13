#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 77-nextcloud-services (Plan 2): httpd, php-fpm, postgresql and the NextCloud cron timer are active. Silent OK when
# documents are not enabled (/etc/chp/documents.conf absent). Alerts once per change, again after 24 h.
C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
[ -f "$C" ] || { echo "OK documents not enabled on this host"; exit 0; }
. "${CHP_DOCS_LIB:-/usr/lib/chp/chp-documents-lib.sh}"
docs_begin 77-services
for u in httpd php-fpm postgresql nextcloud-cron.timer; do
  systemctl is-active --quiet "$u" 2>/dev/null || { docs_due "$u" && docs_alert "NextCloud: $u is not active"; }
done
docs_end "NextCloud services (httpd, php-fpm, postgresql, cron timer) active"
exit 0
