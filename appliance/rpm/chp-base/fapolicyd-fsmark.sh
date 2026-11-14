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
#
# !! DO NOT USE FSMARK=1 WITH fapolicyd 1.4.3-3.el9 (Rocky 9.8). With allow_filesystem_mark = 1 that version exits about
# !! one second after start ("recvmesg failed", status=1/FAILURE): fapolicyd is then DOWN and nothing checks file
# !! execution (fail-open). Lab proof: lab/docs-proof/logs/13-fsmark-fapolicyd-failed.log (ISO 0.7.0 Plan 2 Task 9, D2).
# !! The same exit was later seen with allow_filesystem_mark = 0 too (3 of about 18 restarts on the lab, round 3, D6:
# !! lab/docs-proof/logs/28-fapolicyd-failed-after-enable.log): it is intermittent in 1.4.3-3, not caused by the setting.
# Safety net (Task 9b, 9d): after every restart this script performs, it checks that fapolicyd is still active at three
# samples over CHP_FSMARK_SETTLE seconds (default 5). If not, it reverts OUR marked change (allow_filesystem_mark = 0,
# marker removed), restarts fapolicyd again, logs at crit to the journal (logger -t chp-fapolicyd-fsmark), writes the
# status file /var/lib/chp/fapolicyd-fsmark-failed (check 80 ALERTs while it exists) and exits non-zero. While that file
# exists FSMARK=1 is refused (no crash loop on the next chp-base update). To clear it: set FSMARK=0 and run this script.
# With no change of ours to revert, a dead fapolicyd is restarted once more (warning in the journal if it comes back;
# recorded and non-zero if it does not).
# A restart done LATER for a pending marker (chp-site documents enable, or the operator) must be followed by
#   /usr/libexec/chp/fapolicyd-fsmark --verify
# which runs the same check and the same rollback (no change is made when fapolicyd is active).
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
failf=${CHP_FSMARK_FAILED:-/var/lib/chp/fapolicyd-fsmark-failed}
changed=0
say() {   # loud: stderr + the journal at crit
  echo "chp-fapolicyd-fsmark: $*" >&2
  logger -p daemon.crit -t chp-fapolicyd-fsmark -- "$*" 2>/dev/null || :
}
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
# fapolicyd active at three samples spread over CHP_FSMARK_SETTLE seconds (default 5: after 1, 3 and 5 s). The
# "recvmesg failed" exit comes about one second after the start, so a single early check can miss it (Task 9d, D6).
alive() {
  local s=${CHP_FSMARK_SETTLE:-5} i
  for i in 1 2 3; do
    sleep "$(( s * i / 3 - s * (i - 1) / 3 ))"
    systemctl is-active --quiet fapolicyd 2>/dev/null || return 1
  done
  return 0
}
warn() { echo "chp-fapolicyd-fsmark: $*" >&2; logger -p daemon.warning -t chp-fapolicyd-fsmark -- "$*" 2>/dev/null || :; }
# After a restart (ours, or with --verify one done by someone else): fapolicyd must still be active over the settle time.
# If not and the setting is OURS, revert it, restart again, record the failure and exit non-zero. Without our marker
# there is nothing of ours to revert: the crash is fapolicyd's own (seen with allow_filesystem_mark = 0 too, Task 9d),
# so fapolicyd is restarted ONCE more; back up = a warning in the journal and exit 0; still down = recorded, exit 1.
verify() {
  alive && return 0
  local now; now=$(date +%s)
  if grep -qxF "$mark" "$conf"; then
    changed=0; rewrite "allow_filesystem_mark = 0"
    systemctl restart fapolicyd 2>/dev/null
    if [ "$changed" = 1 ] && alive; then
      msg="fapolicyd was NOT active after a restart with allow_filesystem_mark = 1 (fapolicyd $(rpm -q fapolicyd 2>/dev/null)); REVERTED to allow_filesystem_mark = 0 and restarted: fapolicyd active again. FSMARK=1 is refused until FSMARK=0 is set and this script re-run"
    else
      msg="fapolicyd was NOT active after a restart with allow_filesystem_mark = 1; revert attempted (conf written: $changed) but fapolicyd is STILL NOT ACTIVE: nothing checks file execution (systemctl status fapolicyd; journalctl -u fapolicyd)"
    fi
  else
    systemctl restart fapolicyd 2>/dev/null
    if alive; then
      warn "fapolicyd was NOT active after a restart (allow_filesystem_mark is not ours; fapolicyd $(rpm -q fapolicyd 2>/dev/null), the known \"recvmesg failed\" exit); restarted again: fapolicyd active"
      return 0
    fi
    msg="fapolicyd is NOT active after a restart and STILL NOT ACTIVE after one more restart; allow_filesystem_mark is not ours to revert: nothing checks file execution (systemctl status fapolicyd; journalctl -u fapolicyd)"
  fi
  mkdir -p "$(dirname "$failf")" 2>/dev/null; printf '%s %s\n' "$now" "$msg" > "$failf" 2>/dev/null
  say "$msg"
  exit 1
}
if [ "${1:-}" = "--verify" ]; then verify; exit 0; fi
if [ "$want" = 1 ] && [ -f "$failf" ]; then
  say "FSMARK=1 refused: fapolicyd failed with allow_filesystem_mark = 1 before ($failf: $(cut -c1-200 "$failf" 2>/dev/null)). Set FSMARK=0 and run this script to clear it."
  exit 1
fi
[ "$want" = 0 ] && rm -f "$failf" 2>/dev/null   # FSMARK=0 + a run = the operator's acknowledgement
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
    verify
  fi
fi
exit 0
