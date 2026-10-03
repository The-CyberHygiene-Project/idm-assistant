default_repair: none
decisions:
user_sees: Nothing directly; the diagnostic report says some checks were skipped.
means: Certificate and trust problems on this host cannot be detected until it is fixed: silence does not mean healthy.
evidence: The collector's site settings file is missing, or holds a value it will not use.
repair: No automatic repair. Correct /etc/idm-collect/collect.conf from the site's recorded values (the identity server address and the trust file name).
if_wrong: A wrong server address points the checks at the wrong machine, so results can look healthy when they are not.
rollback: Nothing is changed by this tool.
say_no_if: You do not have the site's recorded values in front of you: never guess the identity server's address.
---
The collector's site config (/etc/idm-collect/collect.conf, written by the client role) is missing or has a value
it will not use: KANIDM_URL must be https://<lower-case host>[:port]; CA_ANCHOR must name a file in
/etc/pki/ca-trust/source/anchors/. Until it is fixed the TLS and trust checks are skipped, so their silence means
"not checked", not "healthy". Correct the file from the site's values (root, 0644); do not guess the Kanidm host.
