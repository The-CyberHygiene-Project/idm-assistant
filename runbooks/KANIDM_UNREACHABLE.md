default_repair: none
decisions:
user_sees: Directory logins fail on this machine, or work only for people already cached here.
means: This machine cannot reach the identity server, so new logins and account changes stop working.
evidence: A secure connection to the identity server failed from this host.
repair: No automatic repair. Check, in order: the network path and firewall, the name lookup for the identity server, and whether the identity server is running.
if_wrong: Changing settings on this workstation does not help: the cause lies between it and the server, or on the server.
rollback: Nothing is changed by this tool.
say_no_if: Someone proposes a fix on this workstation before the connection to the server is checked.
---
This host cannot complete a TLS handshake with Kanidm. Check the network path (routes, firewall), DNS for idm.kanidm.lab.test, and whether kanidmd is running on srv1. This is not fixed by any client-side repair.
