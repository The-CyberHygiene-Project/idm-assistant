#!/usr/bin/env bash
# Copy the host-prep scripts to aero and run one step with sudo:  lab/host/push.sh b1-media --check
set -Eeuo pipefail
step="$1"; shift
here="$(cd "$(dirname "$0")" && pwd)"
ssh aero 'mkdir -p /tmp/lab-host'
scp -q "$here"/*.sh aero:/tmp/lab-host/
sed "s|@SSH_PUBKEY@|$(cat ~/.ssh/aero_ecdsa.pub)|" "$here/../kickstart/build1.ks.in" > /tmp/build1.ks
scp -q /tmp/build1.ks aero:/tmp/lab-host/build1.ks
for n in srv1 client2; do OUT=/tmp/$n.ks bash "$here/../kickstart/render.sh" $n >/dev/null; scp -q /tmp/$n.ks aero:/tmp/lab-host/$n.ks; done
# client1's kickstart carries the LUKS passphrase: render it only for b10, and shred the Mac copy at once (b10 shreds aero's).
if [[ $step == b10-vm-client1 ]]; then
  ( umask 077; OUT=/tmp/client1.ks bash "$here/../kickstart/render.sh" client1 >/dev/null )
  scp -q /tmp/client1.ks aero:/tmp/lab-host/client1.ks; rm -P /tmp/client1.ks 2>/dev/null || rm -f /tmp/client1.ks
fi
# shellcheck disable=SC2029  # step/args are meant to expand on the Mac
ssh aero "sudo bash /tmp/lab-host/${step}.sh $*"
