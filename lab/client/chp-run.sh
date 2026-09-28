#!/usr/bin/env bash
# chp-run.sh CMD [args]  (RUNS ON THE MAC): run one CHP kit command on client1 from a FRESH COPY of the kit.
# The kit in ~/Desktop/chp-build is never modified: this refuses to run if it differs from lab/client/chp-kit.sha256.
# The copy gets the lab's PLACEHOLDERS (lab/client/chp-placeholders.lab.md) applied with the kit's own script.
# The command's output is logged on client1 and copied to lab/chp-logs/ only if the secrets scan passes.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; KIT=~/Desktop/chp-build; host="${CHP_HOST:-client1}"
cmd="${1:?usage: chp-run.sh CMD [args]}"; shift
( cd "$KIT" && shasum -a 256 -c --quiet "$here/chp-kit.sha256" ) || { echo "the CHP kit changed; refusing" >&2; exit 1; }
ts=$(date -u +%Y%m%dT%H%M%SZ); log=/root/chp-run/logs/$cmd-$ts.log
ssh -n "$host" 'rm -rf /tmp/chp-kit && mkdir -p /tmp/chp-kit'
rsync -a --exclude '.DS_Store' --exclude '2026-09-27_aero-Lab-and-Local-AI-Testing-Record.md' "$KIT/" "$host:/tmp/chp-kit/"
scp -q "$here/chp-placeholders.lab.md" "$host:/tmp/chp-kit/PLACEHOLDERS.md"
# shellcheck disable=SC2029  # cmd/args/log expand on the Mac by design
rc=0
ssh -n "$host" "sudo rm -rf /root/chp-run.new && sudo cp -a /tmp/chp-kit /root/chp-run.new && sudo mkdir -p /root/chp-run/logs \
  && sudo cp -a /root/chp-run/logs /root/chp-run.new/ && sudo rm -rf /root/chp-run && sudo mv /root/chp-run.new /root/chp-run \
  && cd /root/chp-run && sudo ./chp-apply-placeholders.sh PLACEHOLDERS.md chp-build.sh >/dev/null \
  && sudo bash -c './chp-build.sh $cmd $* 2>&1 | tee $log; exit \${PIPESTATUS[0]}'" || rc=$?   # keep going: log + rc matter
mkdir -p "$here/../chp-logs"; dest="$here/../chp-logs/$cmd-$ts.log"
# shellcheck disable=SC2029
ssh -n "$host" "sudo cat $log" > "$dest.tmp"
if "$here/../tools/secrets-scan.sh" "$dest.tmp" >/dev/null; then mv "$dest.tmp" "$dest"; else echo "log held back: secrets scan hit ($dest.tmp)" >&2; fi
echo "kit '$cmd' rc=$rc; log: lab/chp-logs/$(basename "$dest")"
exit "$rc"
