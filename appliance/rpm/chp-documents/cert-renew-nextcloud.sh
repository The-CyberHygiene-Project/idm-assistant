#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# cert-renew-nextcloud [--issue] (root; chp-nextcloud-cert-renew.service every 15 min): keep the NextCloud TLS
# certificate (/etc/pki/nextcloud/chain.pem, key.pem; name FQDN from /etc/chp/documents.conf) valid. Renew with
# `step ca renew`; if the certificate is missing or ALREADY EXPIRED, re-issue it over ACME (http-01, :80 opened only
# for the challenge, as cert-renew-kanidm does). --issue forces an issue (documents enable). httpd is reloaded on change.
set -Eeuo pipefail
export STEPPATH=/root/.step
C0=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
FQDN=$(sed -n 's/^FQDN=//p' "$C0" | head -1)
[ -n "$FQDN" ] || { logger -t cert-renew-nextcloud "no FQDN in $C0"; exit 1; }
D=/etc/pki/nextcloud; C=$D/chain.pem; K=$D/key.pem
S=${CHP_DOCS_STATE:-/var/lib/chp/documents}
install -d -m 0700 "$D" "$S"
# One-way door (as cert-renew-kanidm): never request a certificate for a name NextCloud was not set up for.
if [ -f "$S/fqdn" ] && [ "$(cat "$S/fqdn")" != "$FQDN" ]; then
  logger -t cert-renew-nextcloud "refusing: NextCloud serves $(cat "$S/fqdn"), documents.conf now says $FQDN"; exit 1
fi
issue() {
  # one ACME renewer at a time may hold :80 open (shared with cert-renew-kanidm)
  exec 9>/run/chp-acme.lock; flock -w 300 9
  firewall-cmd -q --add-service=http
  if step-cli ca certificate "$FQDN" "$C" "$K" --provisioner acme --kty EC --crv P-384 --force >/dev/null; then rc=0; else rc=$?; fi
  firewall-cmd -q --remove-service=http || true
  [ "$rc" -eq 0 ] || return "$rc"
  printf "%s\n" "$FQDN" > "$S/fqdn"; chmod 0600 "$C" "$K"; systemctl try-reload-or-restart httpd
  logger -t cert-renew-nextcloud "issued a new certificate for $FQDN over ACME"
}
if [ "${1:-}" = --issue ] || [ ! -s "$C" ] || ! openssl x509 -in "$C" -noout -checkend 0 >/dev/null 2>&1; then
  issue; exit 0
fi
if ! step-cli ca renew --force --expires-in 8h --exec "systemctl try-reload-or-restart httpd" "$C" "$K" >/dev/null 2>&1; then
  if openssl x509 -in "$C" -noout -checkend 0 >/dev/null 2>&1; then exit 1; fi   # still valid: a real renewal error
  issue                                                                           # expired meanwhile: ACME fallback
fi
