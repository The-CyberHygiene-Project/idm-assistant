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

# A CHP host always runs fapolicyd, so a missing unit is an ALERT (only a missing unit AND cli AND conf is "absent").
st=$(systemctl is-active fapolicyd 2>/dev/null); st=${st:-unknown}
case "$st" in
  active) ;;
  activating|reloading) echo "OK fapolicyd is $st (transient)"; emitted=$((emitted + 1)) ;;   # re-checked next run
  *) flag "service $st" "fapolicyd.service is $st: nothing is checking file execution (systemctl status fapolicyd; journalctl -u fapolicyd)" ;;
esac
# Mode: the runtime "Permissive:" line of fapolicyd-cli --check-status wins (what the daemon is doing now); the conf
# file is the fallback. Neither readable: say so, never a false all-clear.
pm=""
if [ "$st" = active ]; then
  rt=$(fapolicyd-cli --check-status 2>/dev/null </dev/null | sed -n 's/^Permissive:[[:space:]]*\([A-Za-z0-9]*\).*/\1/p' | head -n 1)
  case "$rt" in true|1) pm=1 ;; false|0) pm=0 ;; esac
fi
if [ -z "$pm" ]; then
  pm=$(sed -n 's/^[[:space:]]*permissive[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$conf" 2>/dev/null | tail -n 1)
fi
if [ "$pm" = 1 ]; then
  flag "permissive" "fapolicyd is in permissive mode (Permissive: true / permissive = 1 in $conf): it logs but denies nothing"
elif [ "$pm" != 0 ] && [ "$st" = active ]; then
  flag "mode unknown" "cannot determine fapolicyd mode (no Permissive: line from fapolicyd-cli --check-status, no permissive= in $conf)"
fi
mkdir -p "$sd" 2>/dev/null
printf '%s' "$new" > "$sf.tmp" 2>/dev/null && mv "$sf.tmp" "$sf"
[ "$emitted" -eq 0 ] && echo "OK fapolicyd active and enforcing"
exit 0
