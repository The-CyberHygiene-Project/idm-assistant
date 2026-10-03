default_repair: unixd-refresh
---
The workstation still shows group memberships the server has removed. ISSO decision #28: revoking access clears the cache on every workstation at once (one to three seconds), so a stale cache here means that clear did not reach this host (it was off, unreachable, or the fan-out failed). Invalidating this host's cache makes the change visible now; also find out why the fan-out missed it.
