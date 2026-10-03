default_repair: ssh-user-cert-reissue
decisions:
user_sees: One person's SSH certificate login is refused everywhere.
means: That person cannot log in remotely until they get a new certificate.
evidence: The newest SSH certificate issued to that person has expired.
repair: Sign the person's already-registered public key again with a short validity, and hand them the new certificate. No private key moves.
if_wrong: If the person should no longer have access, a new certificate gives it back until it expires.
rollback: The certificate authority's record of the previous certificate is put back; a certificate already handed out stays valid until it expires.
say_no_if: The person's access was ended on purpose, or their key was reported lost or stolen.
---
The newest SSH certificate the CA issued to this user has expired, so certificate logins are refused. The repair signs the user's registered public key again with a short validity; the user receives the new certificate. No private key ever moves.
