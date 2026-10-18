#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# aide-check (chp-aide-check.service, daily; spec 2026-10-12 §5.2): compare the database with the recorded baseline
# hash, run `aide --check`, record the exit code and counts in last-result (atomically) and one journal line.
# AIDE exit: 0 clean; 1-7 = added(1)/removed(2)/changed(4) bits; >=14 AIDE error. Never rebuilds or replaces a database.
set -uo pipefail
S=${CHP_AIDE_STATE:-/var/lib/chp/aide}; DB=${CHP_AIDE_DB:-/var/lib/aide/aide.db.gz}
L=${CHP_AIDE_LOG:-/var/log/aide}; AIDE=${CHP_AIDE_BIN:-/usr/sbin/aide}
sha() { if command -v sha512sum >/dev/null 2>&1; then sha512sum "$1"; else shasum -a 512 "$1"; fi | cut -d' ' -f1; }
mkdir -p "$S" "$L" && chmod 0755 "$S" && chmod 0700 "$L" || exit 1
now=$(date -u +%s); t=$(date -u +%Y%m%dT%H%M%SZ); rep="$L/check-$t.log"
match=no-baseline
if [ -f "$DB" ] && [ -f "$S/baseline" ]; then
  want=$(sed -n 's/^DB_SHA512=//p' "$S/baseline" | head -1)
  if [ -n "$want" ] && [ "$want" = "$(sha "$DB")" ]; then match=yes; else match=no; fi
fi
"$AIDE" --check > "$rep" 2>&1; rc=$?
chmod 0600 "$rep"
count() { awk -v k="$1" '$0 ~ "^[ \t]*" k " entries:[ \t]+[0-9]+[ \t]*$" {print $NF; exit}' "$rep"; }
a=$(count Added); r=$(count Removed); c=$(count Changed)
tmp="$S/last-result.tmp"
printf 'TIME=%s\nEPOCH=%s\nEXIT=%s\nADDED=%s\nREMOVED=%s\nCHANGED=%s\nDB_MATCH=%s\nREPORT=%s\n' \
  "$t" "$now" "$rc" "${a:-0}" "${r:-0}" "${c:-0}" "$match" "$rep" > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$S/last-result" || exit 1
logger -p authpriv.notice -t chp-aide "check: exit $rc added=${a:-0} removed=${r:-0} changed=${c:-0} db_match=$match"
exit 0
