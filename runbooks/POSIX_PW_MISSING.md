default_repair: kanidm-cred-reset-token
decisions:
user_sees: A person can sign in to the identity web page but is refused on every Linux login.
means: That person cannot use any workstation or server until they set their Linux password.
evidence: The account has a web sign-in credential but no Linux (POSIX) password.
repair: Issue a one-hour reset token for that person; they set their own Linux password with it. This tool never sets passwords.
if_wrong: If the token reaches the wrong person, they could set the password and log in as that user within the hour.
rollback: Cannot be undone, but an unused token expires after one hour.
say_no_if: You cannot hand the token to that person directly and privately.
---
Kanidm accounts log in to Linux with a separate POSIX (unix) password. A user with only a primary credential passes the web UI but is refused by PAM on every client. The user must set a unix password themselves with a credential-reset token; the tool never sets passwords.
