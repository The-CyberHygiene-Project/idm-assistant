#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# aide-baseline (chp-aide-baseline.service; spec 2026-10-12 §5.1): build the FIRST AIDE baseline once this host's role
# first boot has finished: server.done on the server (its client.done appears earlier, during the self-client steps),
# client.done on a client. Never overwrites an existing database. Exit 1 = not ready yet or failed (the unit retries).
set -uo pipefail
S=${CHP_AIDE_STATE:-/var/lib/chp/aide}; DB=${CHP_AIDE_DB:-/var/lib/aide/aide.db.gz}
NEW=${CHP_AIDE_NEWDB:-/var/lib/aide/aide.db.new.gz}; L=${CHP_AIDE_LOG:-/var/log/aide}
AIDE=${CHP_AIDE_BIN:-/usr/sbin/aide}; FB=${CHP_FIRSTBOOT_DIR:-/var/lib/chp/firstboot}
sha() { if command -v sha512sum >/dev/null 2>&1; then sha512sum "$1"; else shasum -a 512 "$1"; fi | cut -d' ' -f1; }
role=${CHP_ROLE:-$(rpm -q --quiet chp-identity-server && echo server || echo client)}
if [ -f "$DB" ]; then logger -t chp-aide "baseline: a database already exists; not rebuilt"; exit 0; fi
for _ in $(seq "${CHP_AIDE_WAIT:-60}"); do [ -e "$FB/$role.done" ] && break; sleep "${CHP_AIDE_POLL:-10}"; done
if [ ! -e "$FB/$role.done" ]; then
  logger -p authpriv.warning -t chp-aide "baseline: $role first boot not finished yet; will retry"; exit 1; fi
by=first-boot; [ -e "$S/installed-on-existing-host" ] && by=package-install
mkdir -p "$S" "$L" && chmod 0755 "$S" && chmod 0700 "$L" || exit 1
t=$(date -u +%Y%m%dT%H%M%SZ); e=$(date -u +%s)
# Pin the site stick's USBGuard hash first (only if it is plugged in; read-only, never allows it): otherwise its first
# use after the baseline adds /etc/chp/site-stick.hash and the first daily check alerts (quiet check 2026-10-16).
if command -v chp-site >/dev/null 2>&1 && ! chp-site stick-pin-hash >/dev/null 2>&1; then
  logger -p authpriv.warning -t chp-aide "baseline: chp-site stick-pin-hash failed; building the baseline anyway"; fi
rm -f "$NEW"
if ! "$AIDE" --init > "$L/init-$t.log" 2>&1 || [ ! -f "$NEW" ]; then
  logger -p authpriv.warning -t chp-aide "baseline: aide --init failed (see $L/init-$t.log)"; exit 1; fi
mv -f "$NEW" "$DB" && chmod 0600 "$DB" || exit 1
sum=$(sha "$DB")
printf 'DB_SHA512=%s\nBUILT_AT=%s\nBUILT_EPOCH=%s\nBUILT_BY=%s\n' "$sum" "$t" "$e" "$by" > "$S/baseline.tmp" \
  && chmod 0600 "$S/baseline.tmp" && mv -f "$S/baseline.tmp" "$S/baseline" || exit 1
logger -p authpriv.notice -t chp-aide "baseline built ($by) sha512=${sum:0:16}"
