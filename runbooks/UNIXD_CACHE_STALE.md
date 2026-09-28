default_repair: unixd-refresh
---
The client still shows group memberships the server has removed. unixd serves its cache until the entry times out (about two minutes in the lab), so a revoked group can keep working briefly. Invalidating the cache makes the change visible at once.
