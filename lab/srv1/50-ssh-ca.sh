#!/usr/bin/env bash
set -Eeuo pipefail
install -d -m 0700 /etc/ssh-ca
[[ -f /etc/ssh-ca/user_ca ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C 'kanidm.lab.test user CA' -f /etc/ssh-ca/user_ca
# FIPS evidence: does OpenSSH allow an ed25519 key on this host? (non-fatal either way)
if ssh-keygen -q -t ed25519 -N '' -f /tmp/ed-test 2>/tmp/ed-err; then echo "ed25519 under FIPS: ALLOWED" >&2
else echo "ed25519 under FIPS: REFUSED ($(tr '\n' ' ' < /tmp/ed-err))" >&2; fi
rm -f /tmp/ed-test* /tmp/ed-err
cat /etc/ssh-ca/user_ca.pub
