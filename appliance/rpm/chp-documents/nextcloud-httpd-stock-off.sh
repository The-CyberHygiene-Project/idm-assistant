#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# nextcloud-httpd-stock-off (chp-documents): idempotently comment out httpd's stock listeners and sample sites so httpd
# listens on 8443 only (Kanidm owns :443) and serves no stock /cgi-bin/ ScriptAlias. Run by the httpd.service drop-in before every start, because a mod_ssl or
# httpd update may bring the stock files back. CHP_HTTPD_ROOT is for tests.
R=${CHP_HTTPD_ROOT:-/etc/httpd}
off() { [ -f "$1" ] && sed -i -e '/^[[:space:]]*[^#[:space:]]/s/^/#CHP-off /' "$1"; return 0; }
[ -f "$R/conf/httpd.conf" ] && sed -i -e 's/^[[:space:]]*Listen[[:space:]].*/#CHP-off &/' "$R/conf/httpd.conf"
[ -f "$R/conf/httpd.conf" ] && sed -i -e 's/^[[:space:]]*ScriptAlias[[:space:]].*/#CHP-off &/' "$R/conf/httpd.conf"   # stock /cgi-bin/
for f in ssl welcome userdir autoindex; do off "$R/conf.d/$f.conf"; done
exit 0
