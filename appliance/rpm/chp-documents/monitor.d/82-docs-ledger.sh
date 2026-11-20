#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 82-docs-ledger (ISO 0.7.0 Plan 3 Task 9): the controlled-document workflow's root appender and its ledger.
#   (1) chp-docs-ledger.path is active (it starts the appender when chp_ledger spools a request; a failed or stopped
#       path unit means requests wait unprocessed: its OnFailure alert fires once, this check keeps it visible);
#   (2) chp-site doc-ledger verify exits 0 (the chain and the ledger.head witness);
#   (3) the quarantine is empty (each record was alerted when it was made, Wazuh 100645; it stays here until the ISSO
#       has looked and run chp-site doc-ledger purge-quarantine);
#   (4) no unfinished publish: the durable records /var/lib/chp-docs/unfinished/<request id> (written before a
#       publish's first write, removed at its clean end, kept on an undo that failed) and root's journal lines; each
#       stays until the ISSO resolves it (chp-site doc-ledger pending / resolve).
# verify and pending wait for the appender's lock (shared flock); exit 3 = it stayed busy: not checked this run.
# Each failure alerts once and again after 24 h (chp-documents-lib.sh). Silent OK when documents are not enabled.
C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
[ -f "$C" ] || { echo "OK documents not enabled on this host"; exit 0; }
grep -qx 'ENABLED=yes' "$C" 2>/dev/null || { echo "OK documents enable has not finished on this host"; exit 0; }
. "${CHP_DOCS_LIB:-/usr/lib/chp/chp-documents-lib.sh}"
Q=${CHP_DOCS_QUARANTINE:-/var/lib/chp-docs/quarantine}
SITE=${CHP_SITE:-chp-site}
# one line of untrusted text (ledger paths, journal fields): control characters and backticks out, at most 400 chars
clean() { tr -d '`' | tr '\000-\037\177' ' ' | cut -c1-400; }
docs_begin 82-ledger
# a busy run (the appender held the lock past the readers' 120 s wait) checks nothing: the state of the keys it did
# not check is carried over, so nothing re-alerts as new or is forgotten (round 2, b)
keep_prior() {
  local x
  x=$(awk -v re="$1" '{ k = $0; sub(/ [^ ]*$/, "", k); if (k ~ re) print }' "$docs_sf" 2>/dev/null)
  if [ -n "$x" ]; then docs_new="$docs_new$x"$'\n'; fi
}
BUSY_RUNS=${CHP_DOCS_BUSY_RUNS:-4}                   # 4 runs of the 15-min monitor = about an hour (see below)
busy=0

st=$(systemctl is-active chp-docs-ledger.path 2>/dev/null); st=${st:-unknown}
if [ "$st" != active ]; then
  docs_flag path "document ledger: chp-docs-ledger.path is $st: spooled document requests are not being processed (journalctl -u chp-docs-ledger; then systemctl reset-failed chp-docs-ledger.path; systemctl start chp-docs-ledger.path)"
fi

out=$("$SITE" doc-ledger verify 2>&1); rc=$?
if [ "$rc" -eq 3 ]; then
  echo "OK document ledger busy (a request held the lock): chain not checked this run"; docs_emitted=$((docs_emitted + 1))
  busy=1; keep_prior '^verify$'
elif [ "$rc" -ne 0 ]; then
  why=$(printf '%s\n' "$out" | grep -m1 '^PROBLEM' || printf '%s\n' "$out" | head -1)
  docs_flag verify "document ledger does not verify (exit $rc): $(printf '%s' "$why" | clean) (chp-site doc-ledger verify --stick; restore from the site stick's docs-ledger copy)"
fi

n=$(find "$Q" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
case $n in ''|*[!0-9]*) n=0 ;; esac
if [ "$n" -gt 0 ]; then
  docs_flag quarantine "document ledger: $n request(s) in quarantine ($Q): each was set aside as malformed; look at them, then chp-site doc-ledger purge-quarantine"
fi

out=$("$SITE" doc-ledger pending 2>&1); rc=$?
case $rc in
  0) ;;
  3) echo "OK document ledger busy (a request held the lock): unfinished publishes not checked this run"
     docs_emitted=$((docs_emitted + 1))                   # never the all-clear below for a run that did not check
     busy=1; keep_prior '^(pending:.*|pendingerr)$' ;;
  1) found=0
     while IFS= read -r ln; do
       case $ln in
         PENDING\ *) found=$((found + 1))
                     rid=$(printf '%s' "$ln" | awk '{print $3}' | tr -cd '0-9a-f' | cut -c1-32)
                     docs_flag "pending:${rid:-?}" "document ledger: $(printf '%s' "${ln#PENDING }" | clean)" ;;
       esac
     done <<< "$out"
     # exit 1 is also what a crash (a Python traceback) returns: no PENDING line is never an all-clear (round 2)
     [ "$found" -gt 0 ] || docs_flag pendingerr "document ledger: unfinished publishes could not be checked (exit 1 without a PENDING line: the command failed?): $(printf '%s\n' "$out" | tail -1 | clean)" ;;
  *) docs_flag pendingerr "document ledger: unfinished publishes could not be checked (exit $rc): $(printf '%s\n' "$out" | head -1 | clean)" ;;
esac

# The longest a single request holds the lock is about 15 min (a publish: at most 7 occ calls of 120 s); with the
# readers' 120 s wait one busy run is normal, BUSY_RUNS in a row (about an hour) means the appender holds it nearly
# all the time (a flood of requests, or a hang): that is alerted, and again every 24 h while it lasts.
bf=$docs_sd/82-ledger.busy
if [ "$busy" -eq 1 ]; then
  nb=$(cat "$bf" 2>/dev/null); case $nb in ''|*[!0-9]*) nb=0 ;; esac; nb=$((nb + 1))
  printf '%s\n' "$nb" > "$bf" 2>/dev/null
  if [ "$nb" -ge "$BUSY_RUNS" ]; then
    docs_flag busy "document ledger: the appender has held the ledger lock on $nb monitor runs in a row: the chain and the unfinished publishes are NOT being checked (a flood of requests or a hung appender? systemctl status chp-docs-ledger; journalctl -u chp-docs-ledger)"
  fi
else
  rm -f "$bf" 2>/dev/null
fi

docs_end "document ledger: path unit active, chain and head verify, quarantine empty, no unfinished publish"
exit 0
