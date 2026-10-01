#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# client-accounts --role client|server: the forced-command accounts and sudo rules (ISSO #22, #28; chp_admins).
# Files are REPLACED on every run (never appended). Every sudoers file is checked with visudo before it is installed.
set -Eeuo pipefail
ROLE=${2:-client}
g() { chp-site get "$1"; }
sudoers() {   # sudoers NAME LINE: validate, then install 0440
  local t; t=$(mktemp); printf '%s\n' "$2" > "$t"; visudo -cf "$t" >/dev/null; install -o root -g root -m 0440 "$t" "/etc/sudoers.d/$1"; rm -f "$t"
}
keyfile() {   # keyfile USER LINE: authorized_keys holding exactly LINE
  local h; h=$(getent passwd "$1" | cut -d: -f6)
  install -d -o "$1" -g "$1" -m 0700 "$h/.ssh"
  printf '%s\n' "$2" > "$h/.ssh/authorized_keys"; chown "$1:$1" "$h/.ssh/authorized_keys"; chmod 0600 "$h/.ssh/authorized_keys"
  restorecon -R "$h/.ssh"
}
account() { id "$1" >/dev/null 2>&1 || useradd -r -m -s /bin/bash -c "$2" "$1"; passwd -l "$1" >/dev/null 2>&1 || true; }

sudoers 60-chp-admins "%chp_admins ALL=(ALL) ALL"

CIP=$(g COLLECTOR_IP); CKEY=$(g COLLECTOR_SSH_PUBKEY)
if [ -n "$CKEY" ]; then
  account diag "CHP read-only collector (forced command)"
  keyfile diag "from=\"$CIP\",command=\"/usr/libexec/chp/diag-collect\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $CKEY diag"
  sudoers 61-chp-diag "diag ALL=(root) NOPASSWD: /usr/sbin/idm-collect, /usr/sbin/idm-collect --user *"
fi

if [ "$ROLE" = client ]; then
  SIP=$(g SERVER_IP); KKEY=$(g CACHE_PUBKEY)
  account chpcache "CHP revoke fan-out (forced command)"
  keyfile chpcache "from=\"$SIP\",command=\"sudo -n /usr/sbin/kanidm-unix cache-invalidate\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $KKEY chpcache"
  sudoers 62-chp-cache "chpcache ALL=(root) NOPASSWD: /usr/sbin/kanidm-unix cache-invalidate"
fi
