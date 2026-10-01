#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 30-kanidm-cert: the certificate Kanidm SERVES must be fetchable and valid for more than 4 hours (row 24). step-ca ACME
# certificates live 24 h and are renewed 8 h before expiry, so less than 4 h left means renewal is not working.
IDM=$(chp-site get KANIDM_FQDN 2>/dev/null); SIP=$(chp-site get SERVER_IP 2>/dev/null)
pem=$(timeout 10 openssl s_client -connect "$SIP:443" -servername "$IDM" </dev/null 2>/dev/null | sed -n '/BEGIN CERT/,/END CERT/p')
if [ -z "$pem" ]; then echo "ALERT cannot fetch the Kanidm certificate from $IDM"
elif ! printf '%s\n' "$pem" | openssl x509 -noout -checkend 14400 >/dev/null 2>&1; then
  echo "ALERT the Kanidm certificate expires within 4 hours (renewal not working?) ($(printf '%s\n' "$pem" | openssl x509 -noout -enddate))"
else echo "OK Kanidm certificate valid > 4 hours"; fi
