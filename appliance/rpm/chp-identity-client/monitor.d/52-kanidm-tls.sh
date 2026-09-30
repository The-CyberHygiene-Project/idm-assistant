#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 52-kanidm-tls: Kanidm reachable over TLS verified by the site root, from THIS host (row 29: `kanidm-unix status` says
# online until a lookup needs the server, so it is not a health check).
M=/var/lib/chp/firstboot
if [ ! -e "$M/client.done" ]; then echo "OK Kanidm TLS (not enrolled yet)"; exit 0; fi
idm=$(chp-site get KANIDM_FQDN 2>/dev/null)
r=$(curl -fsS --max-time 10 --cacert /etc/pki/ca-trust/source/anchors/chp-root.crt "https://$idm/status" 2>&1)
if [ "$r" = true ]; then echo "OK Kanidm TLS reachable (https://$idm)"; else echo "ALERT Kanidm TLS not reachable from this host (https://$idm): $(printf '%s' "$r" | head -c 160)"; fi
