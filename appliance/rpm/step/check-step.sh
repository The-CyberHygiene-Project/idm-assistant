#!/usr/bin/env bash
# Runs ON build1: what the step RPMs ship. Go version and FIPS module pinned (Review Focus 5), the unit keeps
# GODEBUG=fips140=on and never fips140=only (row 13), versions are real, and nothing lab-specific is inside.
set -Eeuo pipefail
# (piped greps read all input: `grep -q` would SIGPIPE the writer and fail the check under pipefail)
here="$(cd "$(dirname "$0")" && pwd)"; D="${1:-$HOME/rpmbuild/RPMS/x86_64}"
GOV=$(cat "$HOME/step-build/go-version.txt")
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
ca=$(ls "$D"/step-ca-0.30.2-3.chp*.rpm); cli=$(ls "$D"/step-cli-0.31.0-2.chp*.rpm)
for r in "$ca" "$cli"; do ( cd "$tmp" && rpm2cpio "$r" | cpio -idm --quiet ); done
bad=0; t() { if eval "$2"; then echo "OK    $1"; else echo "FAIL  $1"; bad=1; fi; }
t "step-ca built with $GOV"            "'$HOME/step-build/go/bin/go' version -m '$tmp/usr/bin/step-ca' | grep >/dev/null \"$GOV\""
t "step-ca uses a frozen FIPS module"  "'$HOME/step-build/go/bin/go' version -m '$tmp/usr/bin/step-ca' | grep -E >/dev/null 'GOFIPS140=v1\\.0\\.0'"
t "step-cli built with $GOV"           "'$HOME/step-build/go/bin/go' version -m '$tmp/usr/bin/step-cli' | grep >/dev/null \"$GOV\""
t "step-ca reports 0.30.2"             "'$tmp/usr/bin/step-ca' version 2>&1 | grep >/dev/null 0.30.2"
t "step-cli reports 0.31.0"            "'$tmp/usr/bin/step-cli' version 2>&1 | grep >/dev/null 0.31.0"
t "step -> step-cli"                   "[[ \$(readlink '$tmp/usr/bin/step') == step-cli ]]"
t "unit sets GODEBUG=fips140=on"       "grep -qx 'Environment=GODEBUG=fips140=on' '$tmp/usr/lib/systemd/system/step-ca.service'"
t "unit never sets fips140=only"       "! grep -qE '^Environment=.*fips140=only' '$tmp/usr/lib/systemd/system/step-ca.service'"
t "%pre creates user step (the sysusers FILE trigger does not run in Anaconda)" "rpm -qp --scripts '$ca' 2>/dev/null | grep -E 'useradd.*step|getent passwd step|systemd-sysusers' >/dev/null"
t "sysusers creates step"              "grep -qE '^u step ' '$tmp/usr/lib/sysusers.d/step-ca.conf'"
t "licence files shipped"              "ls '$tmp'/usr/share/licenses/step-ca/LICENSE '$tmp'/usr/share/licenses/step-cli/LICENSE >/dev/null"
t "nothing lab-specific inside"        "! grep -rqs 'kanidm.lab.test\\|192.168.100' '$tmp/usr/lib' '$tmp/usr/share'"
(( bad == 0 )) || exit 1; echo "STEP RPMS OK"

