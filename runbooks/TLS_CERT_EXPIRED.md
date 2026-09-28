default_repair: kanidm-cert-renew
---
The certificate Kanidm serves has passed notAfter. Clients refuse TLS, unixd goes offline, logins fail. step-ca will not renew an expired certificate, so the repair re-issues it over ACME. Check the renewal timer too.
