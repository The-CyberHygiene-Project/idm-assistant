#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 31-renew-timer: the Kanidm certificate renewal timer must be active (row 24).
if systemctl is-active --quiet cert-renew-kanidm.timer; then echo "OK renewal timer active"
else echo "ALERT cert-renew-kanidm.timer is $(systemctl is-active cert-renew-kanidm.timer 2>/dev/null)"; fi
