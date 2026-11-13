#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# chp-fapolicyd-fsmark: apply the allow_filesystem_mark setting that the flag file asks for.
#   Flag: FSMARK=0|1 in /etc/chp/fapolicyd-fsmark.conf (shipped FSMARK=0 = OFF, nothing is touched).
#   FSMARK=1: set "allow_filesystem_mark = 1" in /etc/fapolicyd/fapolicyd.conf (idempotent), after a marker line
#             "# chp-managed: allow_filesystem_mark", then restart fapolicyd if the file changed and it is running.
#   FSMARK=0: only undoes OUR OWN change (marker present -> back to 0, marker removed); a setting nobody here made is left alone.
# fapolicyd 1.3 has no conf.d, so this edits fapolicyd.conf in place. That file is %config(noreplace) in the fapolicyd
# package, so an update keeps the edit (a new default lands as fapolicyd.conf.rpmnew); chp-base's %posttrans and the
# trial/ops procedure re-run this script, which is safe to repeat.
flag=${CHP_FSMARK_CONF:-/etc/chp/fapolicyd-fsmark.conf}
conf=${CHP_FAPOLICYD_CONF:-/etc/fapolicyd/fapolicyd.conf}
mark="# chp-managed: allow_filesystem_mark"
[ -f "$conf" ] || exit 0
want=$(sed -n 's/^[[:space:]]*FSMARK=\([01]\).*/\1/p' "$flag" 2>/dev/null | tail -n 1)
want=${want:-0}
cur=$(sed -n 's/^[[:space:]]*allow_filesystem_mark[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$conf" | tail -n 1)
ours=0; grep -qxF "$mark" "$conf" && ours=1
tmp=$conf.chp.$$
changed=0
if [ "$want" = 1 ]; then
  if [ "$cur" != 1 ] || [ "$ours" = 0 ]; then
    { grep -vxF "$mark" "$conf" | grep -v '^[[:space:]]*allow_filesystem_mark[[:space:]]*=' ; printf '%s\n%s\n' "$mark" "allow_filesystem_mark = 1"; } > "$tmp" \
      && cat "$tmp" > "$conf"; rm -f "$tmp"; changed=1
  fi
elif [ "$ours" = 1 ]; then
  { grep -vxF "$mark" "$conf" | grep -v '^[[:space:]]*allow_filesystem_mark[[:space:]]*=' ; echo "allow_filesystem_mark = 0"; } > "$tmp" \
    && cat "$tmp" > "$conf"; rm -f "$tmp"; changed=1
fi
if [ "$changed" = 1 ] && [ -z "${CHP_NO_RESTART:-}" ] && systemctl is-active --quiet fapolicyd 2>/dev/null; then
  systemctl restart fapolicyd
fi
exit 0
