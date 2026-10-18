#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 62-aide-pin (spec §5.3): the current AIDE baseline's hash is not yet on the site stick (the off-host copy).
S=${CHP_AIDE_STATE:-/var/lib/chp/aide}
b=$(sed -n 's/^DB_SHA512=//p' "$S/baseline" 2>/dev/null | head -1)
if [ -z "$b" ]; then echo "OK AIDE pin check: no baseline yet"; exit 0; fi
p=$(sed -n 's/^DB_SHA512=//p' "$S/pinned" 2>/dev/null | head -1)
if [ "$b" = "$p" ]; then echo "OK AIDE baseline pinned to the site stick"
else echo "ALERT AIDE baseline not pinned to the site stick: plug it in and run chp-site aide-pin"; fi
exit 0
