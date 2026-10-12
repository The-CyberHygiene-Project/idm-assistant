#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 60-aide-result (spec 2026-10-12 §5.3): the last daily AIDE check found changes, failed, or the database is not the
# recorded baseline; or there is no database at all. Never repairs; changes stop alerting only after chp-site aide-accept.
S=${CHP_AIDE_STATE:-/var/lib/chp/aide}; DB=${CHP_AIDE_DB:-/var/lib/aide/aide.db.gz}; f="$S/last-result"
if [ ! -f "$DB" ]; then echo "ALERT AIDE has no baseline database ($DB): check chp-aide-baseline.service"; exit 0; fi
if [ ! -f "$f" ]; then echo "OK AIDE baseline present; no daily check has run yet"; exit 0; fi
get() { sed -n "s/^$1=//p" "$f" | head -1; }
ex=$(get EXIT); a=$(get ADDED); r=$(get REMOVED); c=$(get CHANGED); m=$(get DB_MATCH); rep=$(get REPORT)
case $ex in ''|*[!0-9]*) echo "ALERT AIDE last result is unreadable ($f): run systemctl start chp-aide-check"; exit 0 ;; esac
[ "$m" = no ] && echo "ALERT AIDE database does not match the recorded baseline (replaced outside chp-site aide-accept?): investigate"
[ "$m" = no-baseline ] && echo "ALERT AIDE baseline record missing ($S/baseline)"
if [ "$ex" -ge 14 ]; then echo "ALERT AIDE check failed (exit $ex): see $rep"
elif [ "$ex" -ge 1 ]; then echo "ALERT AIDE found changes: ${a:-?} added, ${r:-?} removed, ${c:-?} changed ($rep): review, then chp-site aide-accept"
elif [ "$m" = yes ]; then echo "OK AIDE: no changes"; fi
exit 0
