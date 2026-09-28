default_repair: kanidm-cred-reset-token
---
Kanidm accounts log in to Linux with a separate POSIX (unix) password. A user with only a primary credential passes the web UI but is refused by PAM on every client. The user must set a unix password themselves with a credential-reset token; the tool never sets passwords.
