#!/usr/bin/env bash
# sign-user-cert.sh USER PUBKEY_FILE [VALIDITY]  (RUNS ON THE MAC) -> prints the signed certificate on stdout.
# The CA also records the registered public key and the issued certificate (public) under /var/lib/ssh-ca/.
# Principals are the short name AND the Kanidm SPN: unixd reports users as USER@idm.kanidm.lab.test (D10), and sshd
# matches the certificate principal against that name.
set -Eeuo pipefail
u="${1:?usage: sign-user-cert.sh USER PUBKEY_FILE [VALIDITY]}"; pub="${2:?pubkey file}"; v="${3:-+1h}"
[[ $u =~ ^[a-z0-9_]+$ ]] || { echo "bad user name: $u" >&2; exit 1; }       # interpolated into a root command on srv1
[[ $v =~ ^[-+0-9a-zA-Z:]+$ ]] || { echo "bad validity: $v" >&2; exit 1; }
scp -q "$pub" srv1:/tmp/"$u"-sign.pub
# shellcheck disable=SC2029  # values expand on the Mac by design (validated above)
ssh -n srv1 "set -e; trap 'sudo rm -f /tmp/$u-sign*' EXIT; sudo ssh-keygen -q -s /etc/ssh-ca/user_ca -I $u-cert -n $u,$u@idm.kanidm.lab.test -V $v /tmp/$u-sign.pub; sudo install -m 0644 /tmp/$u-sign.pub /var/lib/ssh-ca/keys/$u.pub; sudo install -m 0644 /tmp/$u-sign-cert.pub /var/lib/ssh-ca/issued/$u-cert.pub; cat /tmp/$u-sign-cert.pub"
