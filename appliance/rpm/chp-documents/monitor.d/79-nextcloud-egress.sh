#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 79-nextcloud-egress (Plan 2): NextCloud's containment is what the SHIPPED files say, judged on every run (not against a
# snapshot of whatever happened to load): (1) the rendered /etc/chp/nextcloud-egress-addr.nft is exactly one valid line
# equal to SERVER_IP in documents.conf (nextcloud-egress-validate); (2) the EXPECTED table is built from the files in a
# throwaway network namespace (unshare -n, nft -f, nft list); (3) the live table inet chp_nextcloud_egress exists and
# equals it, counters removed. Deleting or editing the table, or changing the shipped file without reloading, alerts.
# Silent OK when documents are not enabled.
C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
[ -f "$C" ] || { echo "OK documents not enabled on this host"; exit 0; }
. "${CHP_DOCS_LIB:-/usr/lib/chp/chp-documents-lib.sh}"
F=${CHP_NC_NFT:-/etc/nftables/chp-nextcloud-egress.nft}
V=${CHP_NC_VALIDATE:-/usr/libexec/chp/nextcloud-egress-validate}
norm() { sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'; }
docs_begin 79-egress
if ! why=$("$V" 2>&1); then
  docs_flag addr "NextCloud egress address file invalid: $why"
fi
if ! exp=$(unshare -n sh -c "nft -f '$F' >/dev/null && nft list table inet chp_nextcloud_egress" 2>/dev/null); then
  docs_flag noexpected "NextCloud egress: cannot build the expected table from $F (file or address file broken?)"
elif ! live=$(nft list table inet chp_nextcloud_egress 2>/dev/null); then
  docs_flag missing "NextCloud egress table chp_nextcloud_egress is missing (NextCloud is not contained; restart chp-nextcloud-egress.service)"
elif [ "$(printf '%s\n' "$live" | norm)" != "$(printf '%s\n' "$exp" | norm)" ]; then
  docs_flag differs "NextCloud egress table chp_nextcloud_egress differs from the shipped rules (edited, or files changed and not reloaded?)"
fi
docs_end "NextCloud egress table present, matches the shipped rules, address file valid"
exit 0
