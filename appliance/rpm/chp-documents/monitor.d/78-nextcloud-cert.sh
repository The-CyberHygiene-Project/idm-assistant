#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 78-nextcloud-cert (Plan 2): the NextCloud TLS certificate (/etc/pki/nextcloud/chain.pem, renewed by
# chp-nextcloud-cert-renew.timer), judged against its own lifetime like chp-site review_rules.cert_state: a lifetime under
# 90 days alerts below 25 % left (healthy renewal happens at about 33 %; 25-30 % is only "in the renewal window"); 90 days
# or more alerts at 7 days left. Silent OK when documents are not enabled.
C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
[ -f "$C" ] || { echo "OK documents not enabled on this host"; exit 0; }
. "${CHP_DOCS_LIB:-/usr/lib/chp/chp-documents-lib.sh}"
P=${CHP_NC_CERT:-/etc/pki/nextcloud/chain.pem}
docs_begin 78-cert
dates=$(openssl x509 -in "$P" -noout -startdate -enddate 2>/dev/null)
res=$(printf '%s\n' "$dates" | python3 -c '
import sys, calendar, time
d = {}
for l in sys.stdin:
    k, _, v = l.strip().partition("=")
    if v:
        d[k] = calendar.timegm(time.strptime(" ".join(v.split()), "%b %d %H:%M:%S %Y GMT"))
nb, na, now = d["notBefore"], d["notAfter"], int(sys.argv[1])
life, left = na - nb, na - now
H, DAY = 3600, 86400
span = lambda s: "%d h" % (max(0, s) // H) if s < 2 * DAY else "%d days" % (s // DAY)
if left <= 0: print("ALERT expired %s ago" % span(-left))
elif life < 90 * DAY:
    t = "%s left of %s" % (span(left), span(life))
    print(("ALERT " + t) if left < life / 4 else ("OK " + t + (" (in the renewal window)" if left * 10 < life * 3 else "")))
else:
    t = "%d days left" % (left // DAY)
    print(("ALERT " if left <= 7 * DAY else "OK ") + t)
' "$docs_now" 2>/dev/null)
case $res in
  ALERT*) docs_due cert && docs_alert "NextCloud certificate: ${res#ALERT } (renewal not working?)" ;;
  OK*)    docs_end "NextCloud certificate: ${res#OK }"; exit 0 ;;
  *)      docs_due cert && docs_alert "NextCloud certificate $P is missing or unreadable" ;;
esac
docs_end "NextCloud certificate valid"
exit 0
