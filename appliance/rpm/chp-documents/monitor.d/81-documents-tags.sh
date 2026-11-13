#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 81-documents-tags (Plan 2 Task 6): the result of the nightly `chp-site documents check` (chp-documents-check.timer):
# the tag check (SQL, outside chp_foldertag), the app's policy, team folders, the config.php trust entry and the share
# canary. Reads /var/lib/chp/documents/check.json; each failure in it alerts once (state file) and again after 24 h;
# no result, an unreadable one or one older than 26 h alerts. DEGRADED (database MD5, design §12) is shown, not
# alerted. Silent OK when documents are not enabled (or enable has not finished).
C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
[ -f "$C" ] || { echo "OK documents not enabled on this host"; exit 0; }
grep -qx 'ENABLED=yes' "$C" 2>/dev/null || { echo "OK documents enable has not finished on this host"; exit 0; }
. "${CHP_DOCS_LIB:-/usr/lib/chp/chp-documents-lib.sh}"
docs_begin 81-tags
R=${CHP_DOCS_CHECK:-$docs_sd/check.json}
# one line per item: "A<TAB>key<TAB>text", "D<TAB>text" (degraded), "S<TAB>hours" (stale), "W<TAB>time" (when);
# every field has control characters replaced (the result's text came from NextCloud names)
lines=$(python3 -c '
import json, sys
def c(x, n=400):
    s = "".join(" " if (ord(ch) < 32 or 127 <= ord(ch) <= 159 or ch in "\u2028\u2029") else ch for ch in str(x))
    return s.replace("`", "")[:n]
try:
    d = json.load(open(sys.argv[1]))
    ep = int(d["epoch"])
    al = d["alerts"]
    assert isinstance(al, list)
except Exception:
    print("X"); sys.exit(0)
now = int(sys.argv[2])
print("W\t" + c(d.get("time", ep), 40))
if now - ep > 26 * 3600:
    print("S\t%d" % ((now - ep) // 3600))
for a in al:
    if isinstance(a, dict):
        print("A\t" + c(a.get("key", "?"), 80).replace("\t", " ") + "\t" + c(a.get("text", "?")))
if d.get("degraded"):
    print("D\t" + c(d.get("md5", "DEGRADED: database MD5 unavailable")))
' "$R" "$docs_now" 2>/dev/null)
when=""
case $lines in ''|X) docs_flag noresult "NextCloud check: no result in $R (or unreadable): is chp-documents-check.timer running? run chp-site documents check" ;; esac
while IFS=$'\t' read -r kind a b; do
  case $kind in
    W) when=$a ;;
    S) docs_flag stale "NextCloud check: last result is $a h old (older than 26 h): is chp-documents-check.timer running?" ;;
    A) docs_flag "$a" "NextCloud check: $b" ;;
    D) echo "OK NextCloud $a (known, accepted; see the daily review)" ;;
  esac
done <<< "$lines"
docs_end "NextCloud check OK (tags, policy, share canary; last run ${when:-?})"
exit 0
