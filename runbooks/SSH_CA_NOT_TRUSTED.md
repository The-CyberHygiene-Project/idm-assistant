default_repair: ssh-ca-trust-restore
decisions:
user_sees: Nobody's SSH certificate login to this workstation works; password logins still do.
means: People who log in remotely with certificates are locked out of this machine.
evidence: The SSH service here does not trust the project's SSH certificate authority (setting missing, empty, or a different key).
repair: Trust the project's SSH certificate authority again (only the key matching the pinned fingerprint), check the SSH settings are valid, then reload the SSH service.
if_wrong: If the SSH settings are broken in some other way, the validity check stops the reload; sessions already open stay open.
rollback: The previous SSH files (or their absence) are saved and put back if the check afterwards fails.
say_no_if: The site deliberately changed SSH certificate authorities and this tool's pinned key is the old one.
---
sshd on this client does not trust the lab SSH user CA (TrustedUserCAKeys missing, empty, or a different key), so every certificate login fails. The repair restores the setting with the CA key checked against its pinned fingerprint, and validates sshd's configuration before reloading.
