#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 80-fapolicyd: fapolicyd must be running and enforcing. ALERT when fapolicyd.service is not active (failed, inactive,
# anything else) or when it runs in permissive mode (permissive = 1 in fapolicyd.conf: it logs but denies nothing).
# monitor.sh re-sends every ALERT line on every run, so this check keeps a state file (one line per alerted key,
# "<key> <epoch>", epoch = LAST field), as 76-disk-space does: a key alerts when it newly appears, or again 24 h after
# its last alert; a key that is fine is forgotten; a key still failing but not due prints "OK ... - still failing
# (alerted <time>)", never a false all-clear. chp-base cannot depend on chp-documents, so the helper is repeated here.
REPEAT=86400
sd=${CHP_STATE_DIR:-/var/lib/chp/monitor}
sf=$sd/80-fapolicyd.state
now=${CHP_NOW:-$(date +%s)}
conf=${CHP_FAPOLICYD_CONF:-/etc/fapolicyd/fapolicyd.conf}
mkdir -p "$sd" 2>/dev/null && chmod 0700 "$sd" 2>/dev/null
new=""; emitted=0; last=""
due() {
  local t
  t=$(awk -v k="$1" '{ e = $NF; sub(/ [^ ]*$/, ""); if ($0 == k) { print e; exit } }' "$sf" 2>/dev/null)
  case $t in ''|*[!0-9]*) new="$new$1 $now"$'\n'; return 0 ;; esac
  if [ "$now" -lt "$t" ] || [ $((now - t)) -ge $REPEAT ]; then new="$new$1 $now"$'\n'; return 0; fi
  last=$t; new="$new$1 $t"$'\n'; return 1
}
when() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$1"; }
flag() {
  if due "$1"; then echo "ALERT $2"
  else echo "OK $2 - still failing (alerted $(when "$last"))"; fi
  emitted=$((emitted + 1))
}

STUCK=1800
pend=${CHP_FSMARK_PENDING:-/var/lib/chp/fapolicyd-restart-pending}
# first-seen epoch of a transient state, kept in the state file (key "transient <state>") until the service is active
seen() { awk -v k="$1" '{ e = $NF; sub(/ [^ ]*$/, ""); if ($0 == k) { print e; exit } }' "$sf" 2>/dev/null; }

# A CHP host always runs fapolicyd, so a missing unit is an ALERT.
st=$(systemctl is-active fapolicyd 2>/dev/null); st=${st:-unknown}
case "$st" in
  active) ;;
  activating|reloading)
    t=$(seen "transient $st"); case $t in ''|*[!0-9]*|0) t=$now ;; esac
    [ "$now" -lt "$t" ] && t=$now
    new="${new}transient $st $t"$'\n'
    if [ $((now - t)) -ge $STUCK ]; then
      flag "stuck $st" "fapolicyd.service has been $st since $(when "$t"): it never reached active (systemctl status fapolicyd; journalctl -u fapolicyd)"
    else
      echo "OK fapolicyd is $st (transient, since $(when "$t"))"; emitted=$((emitted + 1))
    fi ;;
  *) flag "service $st" "fapolicyd.service is $st: nothing is checking file execution (systemctl status fapolicyd; journalctl -u fapolicyd)" ;;
esac
# Mode: the runtime "Permissive:" line of fapolicyd-cli --check-status wins (what the daemon is doing now); the conf
# file is the fallback. Neither readable: say so, never a false all-clear.
pm=""
if [ "$st" = active ]; then
  rt=$(fapolicyd-cli --check-status 2>/dev/null </dev/null | sed -n 's/^[Pp][Ee][Rr][Mm][Ii][Ss][Ss][Ii][Vv][Ee]:[[:space:]]*\([A-Za-z0-9]*\).*/\1/p' | head -n 1 | tr 'A-Z' 'a-z')
  case "$rt" in true|yes|1) pm=1 ;; false|no|0) pm=0 ;; esac
fi
if [ -z "$pm" ]; then
  pm=$(sed -n 's/^[[:space:]]*permissive[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$conf" 2>/dev/null | tail -n 1)
fi
if [ "$pm" = 1 ]; then
  flag "permissive" "fapolicyd is in permissive mode (Permissive: true / permissive = 1 in $conf): it logs but denies nothing"
elif [ "$pm" != 0 ] && [ "$st" = active ]; then
  flag "mode unknown" "cannot determine fapolicyd mode (no Permissive: line from fapolicyd-cli --check-status, no permissive= in $conf)"
fi
# A recorded allow_filesystem_mark change (pending marker) that the daemon has not picked up. Same rule as the fsmark
# helper (which clears the marker), so the two never disagree: applied only when the daemon started STRICTLY later than
# the marker was written (one-second resolution: the same second counts as not applied); the start is read with TZ=UTC
# (zone-safe); an unknown start ("", "n/a", unparsable) counts as not applied.
if [ -f "$pend" ]; then
  mt=$(stat -c %Y "$pend" 2>/dev/null || stat -f %m "$pend" 2>/dev/null)
  if [ -n "${CHP_FAPOLICYD_START:-}" ]; then ds=$CHP_FAPOLICYD_START
  else
    d=$(TZ=UTC systemctl show fapolicyd -p ActiveEnterTimestamp --value 2>/dev/null)
    case $d in ''|n/a) ds= ;; *) ds=$(TZ=UTC date -d "$d" +%s 2>/dev/null) ;; esac
  fi
  case "$mt" in ''|*[!0-9]*) mt=0 ;; esac
  case "$ds" in ''|*[!0-9]*) ds=0 ;; esac
  if [ "$ds" -le "$mt" ]; then
    flag "restart pending" "fapolicyd restart pending since $(when "$mt") (allow_filesystem_mark change not applied): systemctl restart fapolicyd"
  fi
fi
# The fsmark helper's failure record (Task 9b, D2): fapolicyd was not active after a restart with
# allow_filesystem_mark = 1; the helper reverted (or could not). ALERT until the operator sets FSMARK=0 and re-runs it.
failf=${CHP_FSMARK_FAILED:-/var/lib/chp/fapolicyd-fsmark-failed}
if [ -f "$failf" ]; then
  fm=$(head -n 1 "$failf" 2>/dev/null | cut -c1-400); ft=${fm%% *}; case $ft in ''|*[!0-9]*) ft=$now ;; esac
  flag "fsmark failed" "chp-fapolicyd-fsmark: fapolicyd failed after an allow_filesystem_mark change at $(when "$ft"): ${fm#* } (fix: FSMARK=0 in /etc/chp/fapolicyd-fsmark.conf, then /usr/libexec/chp/fapolicyd-fsmark)"
fi
mkdir -p "$sd" 2>/dev/null
printf '%s' "$new" > "$sf.tmp" 2>/dev/null && mv "$sf.tmp" "$sf"
[ "$emitted" -eq 0 ] && echo "OK fapolicyd active and enforcing"
exit 0
