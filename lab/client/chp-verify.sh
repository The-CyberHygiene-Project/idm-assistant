#!/usr/bin/env bash
# chp-verify.sh [kit args]  (RUNS ON THE MAC). LAB WORKAROUND for kit finding K5: verify_crypto reads
# cry02-offhost-test.ledger with `grep -v '^#' | grep -v '^$'` WITHOUT `|| true` (line 1982; the other three ledger
# reads have it). Under set -e + pipefail a comments-only stub ledger (created by harden) aborts verify. We move the
# stub aside for the run so the kit takes its own "no ledger" path (no evidence is fabricated), then restore it.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; host="${CHP_HOST:-client1}"; L=/var/lib/chp-spec/cry02-offhost-test.ledger
moved=$(ssh -n "$host" "set -e; if sudo test -f $L && ! sudo grep -qv -e '^#' -e '^\$' $L; then sudo mv $L $L.lab-aside; echo yes; fi")
rc=0; CHP_SHIMS=1 "$here/chp-run.sh" verify "$@" || rc=$?
[[ $moved == yes ]] && ssh -n "$host" "sudo mv $L.lab-aside $L" && echo "restored the stub ledger (K5 workaround)"
exit "$rc"
