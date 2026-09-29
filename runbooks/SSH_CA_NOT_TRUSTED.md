default_repair: ssh-ca-trust-restore
---
sshd on this client does not trust the lab SSH user CA (TrustedUserCAKeys missing, empty, or a different key), so every certificate login fails. The repair restores the setting with the CA key checked against its pinned fingerprint, and validates sshd's configuration before reloading.
