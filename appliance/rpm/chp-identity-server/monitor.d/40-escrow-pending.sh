#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 40-escrow-pending: recovery secrets must not stay on the server (Kanidm admin passwords, step-ca password, ROOT CA key).
P=/root/chp-escrow-pending
names=$(ls -A "$P" 2>/dev/null | tr '\n' ' ')
if [ -n "$names" ]; then echo "ALERT recovery secrets still on the server (${names% }): plug in the site stick and run chp-site export-client"
else echo "OK no recovery secrets on the server"; fi
