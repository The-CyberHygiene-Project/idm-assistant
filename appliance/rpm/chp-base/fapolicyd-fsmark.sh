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
# trial/ops procedure re-run this script, which is safe to repeat. Inside the rpm transaction CHP_NO_RESTART=1 is set: the
# change is written, /var/lib/chp/fapolicyd-restart-pending is created and the restart is left to a post-transaction
# step (Task 9 / chp-site, or the operator). An admin-set allow_filesystem_mark = 1 without our marker is never taken over.
# With FSMARK=1 rpm -V and AIDE will show fapolicyd.conf as changed: expected, accept it with chp-site aide-accept.
flag=${CHP_FSMARK_CONF:-/etc/chp/fapolicyd-fsmark.conf}
conf=${CHP_FAPOLICYD_CONF:-/etc/fapolicyd/fapolicyd.conf}
mark="# chp-managed: allow_filesystem_mark"
[ -f "$conf" ] || exit 0
want=$(sed -n 's/^[[:space:]]*FSMARK=\([01]\).*/\1/p' "$flag" 2>/dev/null | tail -n 1)
want=${want:-0}
cur=$(sed -n 's/^[[:space:]]*allow_filesystem_mark[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$conf" | tail -n 1)
ours=0; grep -qxF "$mark" "$conf" && ours=1
tmp=$(dirname "$conf")/.fapolicyd.conf.chp.$$
trap 'rm -f "$tmp" 2>/dev/null' EXIT   # the temp file never outlives the run, whatever the exit (signals end in EXIT too)
trap 'exit 1' HUP INT TERM
pend=${CHP_FSMARK_PENDING:-/var/lib/chp/fapolicyd-restart-pending}
changed=0
# Seconds since the epoch at which fapolicyd last (re)started; empty when unknown ("n/a" when it never started).
# systemctl prints the timestamp in the local zone; TZ=UTC on both systemctl and date keeps the round trip zone-safe
# (no reliance on date parsing a local zone abbreviation). CHP_FAPOLICYD_START overrides (tests).
fstart() {
  [ -n "${CHP_FAPOLICYD_START:-}" ] && { echo "$CHP_FAPOLICYD_START"; return; }
  local t; t=$(TZ=UTC systemctl show fapolicyd -p ActiveEnterTimestamp --value 2>/dev/null)
  case $t in ''|n/a) return 0 ;; esac
  TZ=UTC date -d "$t" +%s 2>/dev/null
  return 0
}
isnum() { case $1 in ''|*[!0-9]*) return 1 ;; esac; return 0; }
# A pending marker is stale once the daemon has restarted after it was written: clear it. Both values must be numbers on
# their own (an empty start must not pass). Race: both have one-second resolution, so a restart in the same second as
# the marker write cannot be ordered; strictly later (-gt) is required, so that case keeps the marker and costs at most
# one extra restart, never a lost one. A restart by someone else between the write and this check still clears it,
# which is correct (the new conf is loaded).
if [ -f "$pend" ]; then
  mt=$(stat -c %Y "$pend" 2>/dev/null || stat -f %m "$pend" 2>/dev/null); st=$(fstart)
  if isnum "$mt" && isnum "$st" && [ "$st" -gt "$mt" ]; then rm -f "$pend"; fi
fi
# Atomic: build the new file beside the old one (same mode/owner/SELinux label), then mv over it. On any failure the
# old conf is untouched and nothing is recorded.
rewrite() {   # CONF without our marker/setting lines plus the given lines; changed=1 only if the mv succeeded
  if cp -p --preserve=context "$conf" "$tmp" 2>/dev/null || cp -p "$conf" "$tmp" 2>/dev/null; then
    if { grep -vxF "$mark" "$conf" | grep -v '^[[:space:]]*allow_filesystem_mark[[:space:]]*=' ; printf '%s\n' "$@"; } > "$tmp" 2>/dev/null; then
      chcon --reference="$conf" "$tmp" 2>/dev/null || :
      mv -f "$tmp" "$conf" 2>/dev/null && changed=1
    fi
  fi
  rm -f "$tmp" 2>/dev/null
  [ "$changed" = 1 ] || echo "chp-fapolicyd-fsmark: could not write $conf; left unchanged" >&2
}
if [ "$want" = 1 ]; then
  # An admin-set "allow_filesystem_mark = 1" (no marker of ours) is the admin's: do nothing.
  if [ "$cur" = 1 ] && [ "$ours" = 0 ]; then :
  elif [ "$cur" != 1 ] || [ "$ours" = 0 ]; then rewrite "$mark" "allow_filesystem_mark = 1"
  fi
elif [ "$ours" = 1 ]; then
  rewrite "allow_filesystem_mark = 0"
fi
if [ "$changed" = 1 ]; then
  if [ -n "${CHP_NO_RESTART:-}" ]; then
    # Inside an rpm transaction: no restart. Record that one is pending; chp-site / the operator applies it afterwards.
    mkdir -p "$(dirname "$pend")" 2>/dev/null && : > "$pend"
    echo "chp-fapolicyd-fsmark: fapolicyd.conf changed; restart pending ($pend): systemctl restart fapolicyd, then rm $pend"
  elif systemctl is-active --quiet fapolicyd 2>/dev/null; then
    systemctl restart fapolicyd && rm -f "$pend"
  fi
fi
exit 0
