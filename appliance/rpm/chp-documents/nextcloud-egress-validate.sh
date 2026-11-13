#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# nextcloud-egress-validate (chp-documents): the rendered /etc/chp/nextcloud-egress-addr.nft is `include`d by nft, so it
# could hold any nft content. It must be EXACTLY one line, "define CHP_NC_SERVER_IP = <IPv4>", and the address must equal
# SERVER_IP in /etc/chp/documents.conf. Run before the egress unit loads the table (ExecStartPre) and by check 79.
# Prints the reason and exits 1 when invalid.
A=${CHP_NC_ADDR:-/etc/chp/nextcloud-egress-addr.nft}; C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
bad() { echo "$1"; exit 1; }
[ -f "$A" ] || bad "$A is missing"
[ "$(grep -c '' "$A")" = 1 ] || bad "$A must be exactly one line"
line=$(cat "$A")
re='^define CHP_NC_SERVER_IP = ([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
[[ $line =~ $re ]] || bad "$A is not 'define CHP_NC_SERVER_IP = <IPv4>'"
for o in 1 2 3 4; do [ "$((10#${BASH_REMATCH[$o]}))" -le 255 ] || bad "$A: address octet out of range"; done
ip=${line##* }
[ "$ip" != 0.0.0.0 ] || bad "$A: address is 0.0.0.0"
sip=$(sed -n 's/^SERVER_IP=//p' "$C" 2>/dev/null | head -1)
[ -n "$sip" ] || bad "SERVER_IP is not set in $C"
[ "$ip" = "$sip" ] || bad "$A says $ip but $C says SERVER_IP=$sip"
exit 0
