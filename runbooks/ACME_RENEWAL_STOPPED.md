default_repair: acme-timer-restore
decisions:
user_sees: Nothing yet: logins still work today.
means: The identity server's certificate will not renew itself; when it expires, every directory login fails.
evidence: The certificate-renewal timer on the identity server is not running.
repair: Turn the certificate-renewal timer back on; it checks the certificate every 15 minutes.
if_wrong: Little risk: the timer renews the certificate only when it is due. If it was paused on purpose, that pause ends.
rollback: The timer's previous on/off state is recorded and put back if the check afterwards fails.
say_no_if: Someone paused the timer deliberately, for planned work on the certificate authority.
---
cert-renew-kanidm.timer is not active, so the Kanidm certificate will not be renewed before it expires.
