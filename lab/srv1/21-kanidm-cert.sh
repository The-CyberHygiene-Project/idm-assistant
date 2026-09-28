#!/usr/bin/env bash
# srv1: issue idm.kanidm.lab.test via the ACME provisioner (http-01, standalone on :80), install the renewal timer.
set -Eeuo pipefail
export STEPPATH=/root/.step
R=/etc/step-ca/certs/root_ca.crt; D=/etc/pki/kanidm
mkdir -p $D
chmod 700 $D
step-cli ca bootstrap --ca-url https://ca.kanidm.lab.test:9000 --fingerprint "$(step-cli certificate fingerprint $R)" --force >/dev/null
if [[ ! -s $D/chain.pem ]]; then
  firewall-cmd -q --add-service=http   # runtime only: open :80 just for the http-01 challenge
  step-cli ca certificate idm.kanidm.lab.test $D/chain.pem $D/key.pem --provisioner acme --kty EC --crv P-384 --force
  firewall-cmd -q --remove-service=http
fi
chmod 600 $D/*.pem
install -m 0644 /tmp/srv1/units/cert-renew-kanidm.service /tmp/srv1/units/cert-renew-kanidm.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cert-renew-kanidm.timer
step-cli certificate inspect $D/chain.pem --short
