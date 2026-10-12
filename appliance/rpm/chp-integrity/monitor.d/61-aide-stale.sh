#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 61-aide-stale (spec §5.3): no completed AIDE check for more than 26 h, or the daily timer is not active. This is the
# check dc1 never had: a control that is configured but never runs must not stay silent.
S=${CHP_AIDE_STATE:-/var/lib/chp/aide}; DB=${CHP_AIDE_DB:-/var/lib/aide/aide.db.gz}
MAX=${CHP_AIDE_MAX_AGE:-93600}; now=${CHP_NOW:-$(date -u +%s)}
if [ ! -f "$DB" ]; then echo "OK AIDE stale check: no baseline yet (60-aide-result alerts)"; exit 0; fi
systemctl is-active --quiet chp-aide-check.timer || echo "ALERT AIDE daily check timer is not active: systemctl enable --now chp-aide-check.timer"
ref=$(sed -n 's/^EPOCH=//p' "$S/last-result" 2>/dev/null | head -1)
[ -n "$ref" ] || ref=$(sed -n 's/^BUILT_EPOCH=//p' "$S/baseline" 2>/dev/null | head -1)
case $ref in ''|*[!0-9]*) echo "ALERT AIDE: no usable time of the last check or baseline in $S"; exit 0 ;; esac
age=$((now - ref))
if [ "$age" -gt "$MAX" ]; then echo "ALERT AIDE: no completed check for $((age / 3600)) h (limit 26 h): check chp-aide-check.service"
else echo "OK AIDE last check or baseline $((age / 3600)) h ago"; fi
exit 0
