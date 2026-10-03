default_repair: client-ca-trust
decisions:
user_sees: Nobody can log in to this workstation with a directory account.
means: This workstation does not trust the identity server's certificate, so it refuses to connect.
evidence: The identity server's certificate does not lead back to a certificate authority this host trusts.
repair: Put the project's certificate authority back in this workstation's trusted list (only the copy whose fingerprint matches the pinned value), then restart the login service.
if_wrong: If the server's certificate came from a different authority, this does not fix it: the cause is on the server.
rollback: The previous trust file (or its absence) is saved and put back if the check afterwards fails.
say_no_if: The server's certificate was issued by another authority on purpose.
---
The Kanidm certificate does not chain to a root this host trusts. Usually the lab root is missing from the trust store; rarely the served certificate came from another CA. Clock problems are reported separately.
