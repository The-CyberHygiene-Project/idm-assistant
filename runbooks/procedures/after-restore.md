# After restoring from a snapshot or image

A restored machine starts with the clock, the memory and the certificates it had when the image was taken. In a lab
test on 2026-10-04 a restored workstation and server were **14 hours behind**, while the time service still said
"synchronized" and no check noticed. Do these steps in order.

1. **Restart chronyd before anything else** (requirement row 18), on the server too. On a workstation the decision
   form's clock repair does it for you (TOTP_TIME_SKEW, "Restart the time service…"); on the server, run
   `systemctl restart chronyd` by hand. Then run a check: there must be no clock finding.
2. **Check the certificate.** An image older than about a day can carry an expired identity-server certificate
   (TLS_CERT_EXPIRED); its decision form offers a new one from the project's certificate authority.
3. **On machines with the authenticator, wait about a minute and do not retry failed logins** (requirement row 19).
   Codes from a wrong clock fail, and every failed try counts toward the lockout (ACCOUNT_LOCKED).
4. **Expect what a restore brings back.** People, groups and access changes made after the image was taken exist only
   on the identity server; a restored workstation catches up once it reaches the server.
