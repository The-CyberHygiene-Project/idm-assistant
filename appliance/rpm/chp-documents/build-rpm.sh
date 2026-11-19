#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-rpm.sh (RUNS ON THE MAC): build chp-documents' noarch RPM on aero into /data/chp-release/built/. The package has
# no PHP content, so it builds the normal way (as chp-security does); a build that needs PHP goes to chp-build instead.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../../.." && pwd)"
ssh aero 'rm -rf /tmp/chpdoc && mkdir -p /tmp/chpdoc/SOURCES /tmp/chpdoc/SPECS /data/chp-release/built'
scp -q "$here"/nextcloud-httpd.conf "$here"/nextcloud-lan.inc "$here"/nextcloud-fpm.conf "$here"/nextcloud-egress.nft \
  "$here"/nextcloud-egress-addr.nft.example "$here"/chp-nextcloud-egress.service "$here"/nextcloud-egress-validate.sh \
  "$here"/nextcloud-bindsto.conf "$here"/nextcloud-bindsto-httpd.conf "$here"/nextcloud-httpd-stock-off.sh \
  "$here"/nextcloud-cron.service "$here"/nextcloud-cron.timer "$here"/chp-nextcloud-backup \
  "$here"/chp-nextcloud-backup.service "$here"/chp-nextcloud-backup.timer "$here"/cert-renew-nextcloud.sh \
  "$here"/chp-nextcloud-cert-renew.service "$here"/chp-nextcloud-cert-renew.timer "$here"/65-chp-nextcloud.rules \
  "$here"/chp-documents-lib.sh "$here"/monitor.d/77-nextcloud-services.sh "$here"/monitor.d/78-nextcloud-cert.sh \
  "$here"/monitor.d/79-nextcloud-egress.sh "$here"/README.md "$top/LICENSE" "$here"/chp-documents-check.service \
  "$here"/chp-documents-check.timer "$here"/monitor.d/81-documents-tags.sh \
  "$here"/httpd/nextcloud-login-rewrite.conf "$here"/units/chp-docs-ledger.path "$here"/units/chp-docs-ledger.service \
  "$here"/units/chp-docs-ledger-alert.service aero:/tmp/chpdoc/SOURCES/
scp -q "$here/chp-documents.spec" aero:/tmp/chpdoc/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpdoc" /tmp/chpdoc/SPECS/chp-documents.spec >/tmp/chpdoc/build.log 2>&1 || { tail -20 /tmp/chpdoc/build.log; exit 1; }
          cp /tmp/chpdoc/RPMS/noarch/chp-documents-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-documents-*.rpm
          rpm -qp --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" /data/chp-release/built/chp-documents-*.rpm
          sha256sum /data/chp-release/built/chp-documents-*.rpm; rm -rf /tmp/chpdoc'
