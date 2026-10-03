default_repair: unixd-refresh
decisions: 28
user_sees: A person removed from a group can still use that group's access on this workstation.
means: Access that was taken away still works here until the cache is refreshed: a security exposure.
evidence: This workstation still lists group memberships the identity server has removed.
repair: Mark this workstation's account cache as out of date and re-read the person's account, so the removal takes effect now.
if_wrong: Little risk: it re-reads current data from the identity server. The repair refuses if the server is unreachable.
rollback: Cannot be undone, and does not need to be: it only re-reads current data.
say_no_if: The identity server is unreachable from this workstation: fix that first.
---
The workstation still shows group memberships the server has removed. ISSO decision #28: revoking access clears the cache on every workstation at once (one to three seconds), so a stale cache here means that clear did not reach this host (it was off, unreachable, or the fan-out failed). Invalidating this host's cache makes the change visible now; also find out why the fan-out missed it.
