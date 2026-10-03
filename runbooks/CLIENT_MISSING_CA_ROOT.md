default_repair: client-ca-trust
decisions:
user_sees: Nobody can log in to this workstation with a directory account.
means: All directory users are locked out of this machine; local administrator accounts still work.
evidence: The project's certificate authority is missing from this workstation's list of trusted certificates.
repair: Put the project's certificate authority back in this workstation's trusted list (only the copy whose fingerprint matches the pinned value), then restart the login service.
if_wrong: Little risk: only the pinned, known certificate can be installed. The login service restarts, which takes a few seconds.
rollback: The previous trust file (or its absence) is saved and put back if the check afterwards fails.
say_no_if: The site has moved to a new certificate authority that this tool does not know yet.
---
The step-ca root is not in this host's trust store. unixd uses that anchor file directly (ca_path), so without it unixd cannot reach Kanidm. The repair installs the root after checking its pinned fingerprint.
