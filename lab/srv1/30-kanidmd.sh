#!/usr/bin/env bash
# srv1: install kanidm-server + kanidm-clients from lab-local (fapolicyd ENFORCING), configure, start.
set -Eeuo pipefail
dnf -y -q install kanidm-server kanidm-clients
install -m 0640 /tmp/srv1/server.toml /etc/kanidm/server.toml
install -D -m 0644 /tmp/srv1/kanidmd-credentials.conf /etc/systemd/system/kanidmd.service.d/credentials.conf
printf 'uri = "https://idm.kanidm.lab.test"\nca_path = "/etc/step-ca/certs/root_ca.crt"\n' > /etc/kanidm/config
systemctl daemon-reload
kanidmd configtest -c /etc/kanidm/server.toml || true   # informative; the unit is the real test
systemctl enable --now kanidmd
firewall-cmd -q --permanent --add-service=https && firewall-cmd -q --reload
for _ in $(seq 30); do curl -fsS https://idm.kanidm.lab.test/status >/dev/null 2>&1 && break; sleep 2; done
curl -fsS https://idm.kanidm.lab.test/status; echo
