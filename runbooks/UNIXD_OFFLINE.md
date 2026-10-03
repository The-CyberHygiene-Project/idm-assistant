default_repair: none
decisions:
user_sees: Directory logins may still work from cache, but changes do not arrive and new users cannot log in.
means: This workstation lost contact with the identity server and is working from old copies of accounts.
evidence: The login service reports the identity server as offline.
repair: No automatic repair. Find out why first: network path, name lookup, certificate trust, or the server itself.
if_wrong: Refreshing the cache while the server is unreachable does not help.
rollback: Nothing is changed by this tool.
say_no_if: Someone proposes refreshing or clearing the cache before the connection is restored.
---
unixd could not reach Kanidm on its last server request and is serving cached data only. Find out why first: network path, DNS, TLS trust, the server itself. Refreshing the cache while the server is unreachable does not help.
