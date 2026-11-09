#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 75-review (review spec §6, server only): yesterday's review built, no review unsigned for 2 days, the latest review's
# new attention items (once), the ledger chain intact, and long-lived certificates or keys within 7 days of expiry.
# The rules live in `chp-site review monitor`; this check only passes its lines through.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
role=$(sed -n 's/^ROLE=//p' "$C" | head -1)
[ "$role" = server ] || { echo "OK the daily review is checked on the server"; exit 0; }
out=$(chp-site review monitor 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  echo "ALERT chp-site review monitor failed (exit $rc): $(printf '%s\n' "$out" | tail -1)"
else
  printf '%s\n' "$out"
fi
exit 0
