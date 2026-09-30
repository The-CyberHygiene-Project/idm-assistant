#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 20-clock: alert when the clock is more than 30 s off (#30: CUI makestep 1.0 3 slews a later jump for hours).
off=$(chronyc tracking 2>/dev/null | awk '/^System time/{print $4}')
if [ -z "$off" ]; then echo "ALERT chrony gives no time offset (is chronyd running?)"
elif awk -v o="$off" 'BEGIN{exit !(o > 30)}'; then echo "ALERT clock is ${off}s off (limit 30s): a person must decide (#30)"
else echo "OK clock offset ${off}s"; fi
