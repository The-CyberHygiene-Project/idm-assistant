default_repair: kanidm-cert-renew
decisions:
user_sees: Nobody can log in with a directory account, anywhere.
means: The identity server's certificate has expired, so every machine refuses to talk to it.
evidence: The identity server's certificate is past its end date.
repair: Back up the current certificate and key, issue a new certificate from the project's certificate authority, and restart the identity server.
if_wrong: The identity server restarts, interrupting logins for a few seconds. If the certificate authority is unhealthy, the repair does not start.
rollback: The previous certificate and key are saved and put back, with a restart, if the check afterwards fails.
say_no_if: The site is moving the identity server to a different certificate authority.
---
The certificate Kanidm serves has passed notAfter. Clients refuse TLS, unixd goes offline, logins fail. step-ca will not renew an expired certificate, so the repair re-issues it over ACME. Check the renewal timer too.
