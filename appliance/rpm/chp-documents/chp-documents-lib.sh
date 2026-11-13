# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# chp-documents-lib.sh (sourced by monitor checks 77-79; not itself a check). monitor.sh re-sends every ALERT line on
# every run, so these checks keep a state file (one line per alerted key: "<key> <epoch>", epoch = LAST field), as
# 76-disk-space does: a key alerts when it newly appears, or again 24 h after its last alert; a key that is fine is
# forgotten. Usage: docs_begin NAME; docs_flag KEY TEXT (ALERT when due, else "OK TEXT - still failing (alerted <time>)",
# never a false all-clear); docs_end OKTEXT (prints OK only when nothing was flagged). State lives in /var/lib/chp/documents.
REPEAT=86400
docs_now=${CHP_NOW:-$(date +%s)}
docs_begin() {
  docs_sd=${CHP_DOCS_STATE:-/var/lib/chp/documents}; docs_sf=$docs_sd/$1.state
  mkdir -p "$docs_sd" 2>/dev/null && chmod 0700 "$docs_sd" 2>/dev/null
  docs_new=""; docs_emitted=0
}
docs_due() {
  local t
  t=$(awk -v k="$1" '{ e = $NF; sub(/ [^ ]*$/, ""); if ($0 == k) { print e; exit } }' "$docs_sf" 2>/dev/null)
  case $t in ''|*[!0-9]*) docs_new="$docs_new$1 $docs_now"$'\n'; return 0 ;; esac
  if [ "$docs_now" -lt "$t" ] || [ $((docs_now - t)) -ge $REPEAT ]; then docs_new="$docs_new$1 $docs_now"$'\n'; return 0; fi
  docs_last=$t; docs_new="$docs_new$1 $t"$'\n'; return 1
}
docs_when() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$1"; }
docs_flag() {
  if docs_due "$1"; then docs_alert "$2"
  else echo "OK $2 - still failing (alerted $(docs_when "$docs_last"))"; docs_emitted=$((docs_emitted + 1)); fi
}
docs_alert() { echo "ALERT $1"; docs_emitted=$((docs_emitted + 1)); }
docs_end() {
  mkdir -p "$docs_sd" 2>/dev/null
  printf '%s' "$docs_new" > "$docs_sf.tmp" 2>/dev/null && mv "$docs_sf.tmp" "$docs_sf"
  [ "$docs_emitted" -eq 0 ] && echo "OK $1"
  return 0
}
