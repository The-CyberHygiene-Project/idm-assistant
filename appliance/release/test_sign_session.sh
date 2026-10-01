#!/usr/bin/env bash
# test_sign_session.sh (RUNS ON THE MAC; YubiKey plugged in; touch it when it blinks, twice).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fails=0
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
FPR=$(awk '$2=="cyberhygiene"{print $1}' "$here/trusted-keys.txt")
cmd="echo sign-session-test > /tmp/ss.txt && gpg --batch --yes -u $FPR --detach-sign --armor -o /tmp/ss.txt.asc /tmp/ss.txt && gpg --verify /tmp/ss.txt.asc /tmp/ss.txt 2>&1 | grep -q 'Good signature'"
t "aero signs through the forwarded agent"            "bash '$here/sign-session.sh' \"$cmd\""
t "a second session right after also works (stale socket cleared)" "bash '$here/sign-session.sh' \"$cmd\""
t "without a session aero cannot sign (the key is not on aero)" \
  "! ssh aero 'gpg --batch --yes -u $FPR --detach-sign -o /tmp/ss2.sig /tmp/ss.txt' >/dev/null 2>&1"
t "no forwarded socket is left behind" "! ssh aero 'test -S \$(gpgconf --list-dir agent-socket)'"
ssh aero 'rm -f /tmp/ss.txt /tmp/ss.txt.asc /tmp/ss2.sig'
exit $fails
