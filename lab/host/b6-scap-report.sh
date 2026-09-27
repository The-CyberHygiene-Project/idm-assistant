#!/usr/bin/env bash
# b6: OpenSCAP CUI profile evaluation, REPORT ONLY (no remediation).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
DS=/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
OUT=/data/lab-inputs/reports; STAMP=$(date +%Y%m%d-%H%M)
run "make report dir" mkdir -p "$OUT"
# oscap exits 2 when any rule fails; that is a normal result here, not an error.
run "evaluate cui profile" sh -c "oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cui \
  --results $OUT/aero-cui-$STAMP.xml --report $OUT/aero-cui-$STAMP.html $DS >/dev/null 2>&1 || true"
run "hand the report to itadmin" chown -R itadmin: "$OUT"
log "report: $OUT/aero-cui-$STAMP.html"
