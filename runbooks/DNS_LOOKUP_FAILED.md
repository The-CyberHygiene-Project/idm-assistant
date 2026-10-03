default_repair: none
decisions: 45
user_sees: Directory logins fail on this machine, or work only for people already cached here.
means: This machine can't find the identity server by name, so new logins and account changes stop working.
evidence: The identity server's name does not resolve on this machine.
repair: No automatic repair. Check, in order: the DNS server named in the evidence is running (on srv1 it is named), this machine points at the right DNS server, and the server's DNS record exists.
if_wrong: Adding the name to this machine's hosts file hides the real fault, and breaks again when the server moves.
rollback: Nothing is changed by this tool.
say_no_if: Someone proposes a hosts-file entry or a change on this workstation before the DNS server is checked.
---
The identity server's name does not resolve on this workstation, so unixd and the certificate check cannot reach Kanidm. The DNS server itself answers (or is up but refuses DNS), so this is a naming fault, not a network path fault. No repair exists (ISSO row 45): check that named runs on the DNS server, that /etc/resolv.conf names it, and that the record exists.
