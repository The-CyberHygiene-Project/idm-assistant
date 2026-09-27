# Shared helpers for aero host-prep steps. Source it; do not execute.
# shellcheck shell=bash
set -Eeuo pipefail
CHECK=0
for a in "$@"; do [[ "$a" == "--check" ]] && CHECK=1; done
log()  { printf '%s  %s\n' "$(date +%T)" "$*"; }
die()  { log "FAIL: $*"; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "run with sudo"; }
run() {
  local desc="$1"; shift
  if (( CHECK )); then log "[check] would: $desc  ($*)"; else log "$desc"; "$@"; fi
}
