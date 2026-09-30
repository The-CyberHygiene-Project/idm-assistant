#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 31-renew-timer: the Kanidm certificate renewal timer must be active (row 24).
if systemctl is-active --quiet cert-renew-kanidm.timer; then echo "OK renewal timer active"
else echo "ALERT cert-renew-kanidm.timer is $(systemctl is-active cert-renew-kanidm.timer 2>/dev/null)"; fi
# a renewal unit that fails every run is otherwise invisible until the certificate is nearly expired
if systemctl is-failed -q cert-renew-kanidm.service; then echo "ALERT cert-renew-kanidm.service failed on its last run: journalctl -u cert-renew-kanidm"; fi
