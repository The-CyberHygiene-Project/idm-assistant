#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# nextcloud-egress-snapshot (chp-documents): right after chp-nextcloud-egress.service loads the shipped+rendered table,
# record its normalised listing (counters removed). Monitor check 79 compares the live table with this record, so a
# deleted or edited table is caught within one monitor run. Keep the sed identical to 79-nextcloud-egress.sh.
G=${CHP_NC_GOLDEN:-/var/lib/chp/nextcloud-egress.golden}
install -d -m 0700 "$(dirname "$G")"
nft list table inet chp_nextcloud_egress | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/' > "$G.tmp" && mv "$G.tmp" "$G"
chmod 0600 "$G"
