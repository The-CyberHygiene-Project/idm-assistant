#!/usr/bin/env bash
# sign-user-cert.sh USER PUBKEY_FILE [VALIDITY]  (RUNS ON THE MAC) -> prints the signed certificate on stdout.
# Principals are the short name AND the Kanidm SPN: unixd reports users as USER@idm.kanidm.lab.test (D10), and sshd
# matches the certificate principal against that name.
set -Eeuo pipefail
u="${1:?usage: sign-user-cert.sh USER PUBKEY_FILE [VALIDITY]}"; pub="${2:?pubkey file}"; v="${3:-+1h}"
scp -q "$pub" srv1:/tmp/"$u"-sign.pub
# shellcheck disable=SC2029  # values expand on the Mac by design
ssh -n srv1 "sudo ssh-keygen -q -s /etc/ssh-ca/user_ca -I $u-cert -n $u,$u@idm.kanidm.lab.test -V $v /tmp/$u-sign.pub && cat /tmp/$u-sign-cert.pub; rm -f /tmp/$u-sign*"
