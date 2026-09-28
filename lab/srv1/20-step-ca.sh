#!/usr/bin/env bash
# srv1: step-ca with an internal root + intermediate (step's default ECDSA P-256: `ca init` has no key-type option),
# JWK + ACME provisioners, run as user step.
set -Eeuo pipefail
export STEPPATH=/etc/step-ca
id step >/dev/null 2>&1 || useradd --system --home-dir /etc/step-ca --shell /sbin/nologin step
if [[ ! -f $STEPPATH/config/ca.json ]]; then
  mkdir -p $STEPPATH
  chmod 700 $STEPPATH
  ( umask 077; head -c 32 /dev/urandom | base64 > $STEPPATH/password )
  step-cli ca init --name "kanidm.lab.test Lab CA" --dns ca.kanidm.lab.test --dns srv1.kanidm.lab.test \
    --address 192.168.100.10:9000 --provisioner lab-admin --password-file $STEPPATH/password \
    --provisioner-password-file $STEPPATH/password --deployment-type standalone --acme
  chown -R step:step $STEPPATH
fi
install -m 0644 /tmp/srv1/units/step-ca.service /etc/systemd/system/step-ca.service
systemctl daemon-reload
systemctl enable --now step-ca
firewall-cmd -q --permanent --add-port=9000/tcp
firewall-cmd -q --reload
install -m 0644 $STEPPATH/certs/root_ca.crt /etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt
update-ca-trust   # public cert: 0644 (cp kept step's 0600)
for _ in $(seq 20); do step-cli ca health --ca-url https://ca.kanidm.lab.test:9000 --root $STEPPATH/certs/root_ca.crt >/dev/null 2>&1 && break; sleep 1; done
step-cli ca health --ca-url https://ca.kanidm.lab.test:9000 --root $STEPPATH/certs/root_ca.crt   # hard failure if still down
