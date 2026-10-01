#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# cert-renew-kanidm [--issue] (root; cert-renew-kanidm.service every 15 min): keep the Kanidm TLS certificate valid.
# Renew with `step ca renew`; if the certificate is missing or ALREADY EXPIRED (renew refuses expired certificates, so a
# timer outage longer than the lifetime would otherwise need a person, row 26), re-issue it over ACME (http-01, :80 opened
# only for the challenge). --issue forces an ACME issue (first boot). kanidmd is restarted on any change.
set -Eeuo pipefail
export STEPPATH=/root/.step
IDM=$(chp-site get KANIDM_FQDN); D=/etc/pki/kanidm; C=$D/chain.pem; K=$D/key.pem
# One-way door: never request a certificate for a name Kanidm was not initialised for (a changed site DOMAIN).
if [ -f /var/lib/chp/kanidm-domain ] && [ "$(cat /var/lib/chp/kanidm-domain)" != "$IDM" ]; then
  logger -t cert-renew-kanidm "refusing: Kanidm serves $(cat /var/lib/chp/kanidm-domain), site.conf now says $IDM"; exit 1
fi
issue() {
  firewall-cmd -q --add-service=http
  if step-cli ca certificate "$IDM" "$C" "$K" --provisioner acme --kty EC --crv P-384 --force >/dev/null; then rc=0; else rc=$?; fi
  firewall-cmd -q --remove-service=http || true
  [ "$rc" -eq 0 ] || return "$rc"
  chmod 0600 "$C" "$K"; systemctl try-restart kanidmd
  logger -t cert-renew-kanidm "issued a new certificate for $IDM over ACME"
}
if [ "${1:-}" = --issue ] || [ ! -s "$C" ] || ! openssl x509 -in "$C" -noout -checkend 0 >/dev/null 2>&1; then
  issue; exit 0
fi
if ! step-cli ca renew --force --expires-in 8h --exec "systemctl try-restart kanidmd" "$C" "$K" >/dev/null 2>&1; then
  if openssl x509 -in "$C" -noout -checkend 0 >/dev/null 2>&1; then exit 1; fi   # still valid: a real renewal error
  issue                                                                           # expired meanwhile: ACME fallback
fi
