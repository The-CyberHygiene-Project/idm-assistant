#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 79-nextcloud-egress (Plan 2): the nft table inet chp_nextcloud_egress exists and its rule set is the one
# chp-nextcloud-egress.service loaded (shipped file + rendered address): the normalised listing (counters removed) is
# compared with the snapshot the unit wrote right after loading. Deleting or editing the table at run time is caught
# within one monitor run. Silent OK when documents are not enabled.
C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
[ -f "$C" ] || { echo "OK documents not enabled on this host"; exit 0; }
. "${CHP_DOCS_LIB:-/usr/lib/chp/chp-documents-lib.sh}"
G=${CHP_NC_GOLDEN:-/var/lib/chp/nextcloud-egress.golden}
docs_begin 79-egress
if ! live=$(nft list table inet chp_nextcloud_egress 2>/dev/null); then
  docs_due missing && docs_alert "NextCloud egress table chp_nextcloud_egress is missing (NextCloud is not contained; restart chp-nextcloud-egress.service)"
elif [ ! -s "$G" ]; then
  docs_due nosnap && docs_alert "NextCloud egress table has no load-time snapshot $G (was chp-nextcloud-egress.service started?)"
elif [ "$(printf '%s\n' "$live" | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/')" != "$(cat "$G")" ]; then
  docs_due differs && docs_alert "NextCloud egress table chp_nextcloud_egress differs from the loaded rule set (edited at run time?)"
fi
docs_end "NextCloud egress table present and unchanged"
exit 0
