#!/usr/bin/env bash
# ssh-cert-login.sh USER [HOST]  (RUNS ON THE MAC): ONE SSH-certificate login (never a password, so a refusal never
# counts toward faillock). Key + certificate: ~/idm-lab-secrets/USER_ecdsa{,-cert.pub}. Prints RESULT: OK <name> | DENIED.
set -Eeuo pipefail
u="${1:?usage: ssh-cert-login.sh USER [HOST]}"; host="${2:-192.168.100.13}"
[[ $u =~ ^[a-z][a-z0-9_]*$ ]] || { echo "bad user name" >&2; exit 2; }
k=~/idm-lab-secrets/${u}_ecdsa
if out=$(ssh -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o PasswordAuthentication=no \
            -o KbdInteractiveAuthentication=no -o ConnectTimeout=10 -i "$k" -o CertificateFile="$k-cert.pub" \
            "$u@$host" id -un 2>/dev/null </dev/null); then
  echo "RESULT: OK $out"
else
  echo "RESULT: DENIED"
fi
