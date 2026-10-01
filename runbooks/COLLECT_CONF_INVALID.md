---
finding: COLLECT_CONF_INVALID
default_repair: none
---
The collector's site config (/etc/idm-collect/collect.conf, written by the client role) is missing or has a value
it will not use: KANIDM_URL must be https://<lower-case host>[:port]; CA_ANCHOR must name a file in
/etc/pki/ca-trust/source/anchors/. Until it is fixed the TLS and trust checks are skipped, so their silence means
"not checked", not "healthy". Correct the file from the site's values (root, 0644); do not guess the Kanidm host.
