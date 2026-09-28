#!/usr/bin/env bash
# chp-run.sh CMD [args]  (RUNS ON THE MAC): run one CHP kit command on client1 from a FRESH COPY of the kit.
# The kit in ~/Desktop/chp-build is never modified: this refuses to run if it differs from lab/client/chp-kit.sha256.
# The copy gets the lab's PLACEHOLDERS (lab/client/chp-placeholders.lab.md) applied with the kit's own script.
# CHP_SHIMS=1 puts lab/client/chp-shims/ first on PATH for the kit (lab workarounds for kit defects; each logged).
# The command's output is logged on client1 and copied to lab/chp-logs/ only if the secrets scan passes.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; KIT=~/Desktop/chp-build; host="${CHP_HOST:-client1}"
cmd="${1:?usage: chp-run.sh CMD [args]}"; shift
( cd "$KIT" && shasum -a 256 -c --quiet "$here/chp-kit.sha256" ) || { echo "the CHP kit changed; refusing" >&2; exit 1; }
src="$KIT"; tag=""
# CHP_PATCHED=1: an EVALUATION COPY = the kit + lab/client/chp-proposed-fixes.patch, built in a temp dir on the Mac.
# The kit itself stays untouched (checked above); every log from such a run is prefixed "patched-".
if [[ ${CHP_PATCHED:-0} == 1 ]]; then
  src=$(mktemp -d); trap 'rm -rf "$src"' EXIT
  rsync -a --exclude '.DS_Store' "$KIT/" "$src/"
  patch -s -d "$src" -p1 < "$here/chp-proposed-fixes.patch"
  tag="patched-"
fi
ts=$(date -u +%Y%m%dT%H%M%SZ); log=/root/chp-run/logs/$tag$cmd-$ts.log
ssh -n "$host" 'set -e; rm -rf /tmp/chp-kit; mkdir -p /tmp/chp-kit'
rsync -a --exclude '.DS_Store' --exclude '2026-09-27_aero-Lab-and-Local-AI-Testing-Record.md' "$src/" "$host:/tmp/chp-kit/"
scp -q "$here/chp-placeholders.lab.md" "$host:/tmp/chp-kit/PLACEHOLDERS.md"
shim=""; if [[ ${CHP_SHIMS:-0} == 1 ]]; then rsync -a "$here/chp-shims/" "$host:/tmp/chp-shims/"; shim="PATH=/root/chp-shims:\$PATH"; fi
# shellcheck disable=SC2029  # cmd/args/log expand on the Mac by design
rc=0
# One root script over stdin (a `cd` in a plain ssh command runs as the login user and can't enter /root).
# shellcheck disable=SC2087  # cmd/args/log expand on the Mac by design
ssh "$host" "sudo bash -s" <<REMOTE || rc=$?
set -e
rm -rf /root/chp-run.new; cp -a /tmp/chp-kit /root/chp-run.new
mkdir -p /root/chp-run/logs; cp -a /root/chp-run/logs /root/chp-run.new/
rm -rf /root/chp-run; mv /root/chp-run.new /root/chp-run; cd /root/chp-run
if [[ -d /tmp/chp-shims ]]; then rm -rf /root/chp-shims; cp -a /tmp/chp-shims /root/chp-shims; chmod 700 /root/chp-shims; fi
./chp-apply-placeholders.sh PLACEHOLDERS.md chp-build.sh >/dev/null
# The kit's placeholder tool leaves chp-build.sh untouched and writes chp-build.<system-name>.sh; run that.
gen=\$(ls chp-build.*.sh | grep -vx chp-build.sh | head -1)
[[ -n \$gen ]] || { echo "chp-apply-placeholders.sh produced no customised script"; exit 1; }
set +e
[[ -n "$tag" ]] && echo "EVALUATION COPY: CHP kit + lab/client/chp-proposed-fixes.patch (NOT the published kit)" | tee -a $log
[[ -n "$shim" ]] && echo "LAB SHIMS ACTIVE: \$(ls /root/chp-shims | tr '\n' ' ')" | tee -a $log
$shim ./\$gen $cmd $* 2>&1 | tee -a $log
exit \${PIPESTATUS[0]}
REMOTE
mkdir -p "$here/../chp-logs"; dest="$here/../chp-logs/$tag$cmd-$ts.log"
# shellcheck disable=SC2029
ssh -n "$host" "sudo cat $log" > "$dest.tmp"
if "$here/../tools/secrets-scan.sh" "$dest.tmp" >/dev/null; then mv "$dest.tmp" "$dest"; else echo "log held back: secrets scan hit ($dest.tmp)" >&2; fi
echo "kit '$cmd' rc=$rc; log: lab/chp-logs/$(basename "$dest")"
exit "$rc"
