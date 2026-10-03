default_repair: none
decisions: 45
user_sees: Directory logins fail on this machine, even though the identity server is running.
means: This machine is sending logins to the wrong address. That may be a mistake, or someone redirecting logins.
evidence: The identity server's name points to an address that is not the server's.
repair: No automatic repair. Treat it as a possible security incident: tell the ISSO, then find who changed the record (the hosts file on this machine, or the DNS server) and why.
if_wrong: "Correcting" the address before anyone looks destroys the evidence of how it changed.
rollback: Nothing is changed by this tool.
say_no_if: Someone proposes just changing the address back before the ISSO has seen it.
---
The identity server's name resolves to an address the server does not have, from the hosts file or from DNS as the evidence says. Logins are being sent elsewhere: a stale record, a mistake, or redirection. No repair exists (ISSO row 45): report it to the ISSO as a possible incident and keep the record as it is until it has been examined.
