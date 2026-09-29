#!/usr/bin/env bash
# sign-session.sh '<command>' (RUNS ON THE MAC): run ONE command on aero with this Mac's gpg-agent (and so the
# YubiKey) forwarded as aero's agent socket. The secret key never leaves the card; aero has the socket only while
# the command runs. aero's sshd has StreamLocalBindUnlink=no, so a leftover socket would silently break the
# forward: it is removed before and after. aero's gpg is told never to start a local agent (it has no key).
set -Eeuo pipefail
H=${SIGN_HOST:-aero}
here="$(cd "$(dirname "$0")" && pwd)"
[[ $# -eq 1 ]] || { echo "usage: sign-session.sh '<command>'"; exit 2; }
gpg --card-status >/dev/null 2>&1 || { echo "YubiKey not found: plug it in"; exit 1; }
local_sock=$(gpgconf --list-dir agent-extra-socket)
gpg-connect-agent /bye >/dev/null 2>&1
remote_sock=$(ssh "$H" 'gpgconf --create-socketdir 2>/dev/null; gpgconf --list-dir agent-socket' 2>/dev/null)
ssh "$H" "mkdir -p -m 700 ~/.gnupg; grep -qx no-autostart ~/.gnupg/gpg.conf 2>/dev/null || echo no-autostart >> ~/.gnupg/gpg.conf; gpgconf --kill gpg-agent 2>/dev/null || true; rm -f '$remote_sock'" 2>/dev/null
ssh "$H" 'gpg --batch --quiet --import 2>/dev/null' < "$here/RPM-GPG-KEY-cyberhygiene" 2>/dev/null
set +e
ssh -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes -R "$remote_sock:$local_sock" "$H" "$1"
rc=$?
set -e
ssh "$H" "rm -f '$remote_sock'" 2>/dev/null
exit $rc
