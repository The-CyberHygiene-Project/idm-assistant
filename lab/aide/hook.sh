#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# Lab-only ALERT_HOOK: append each alert to a file the proof reads (spec §9 "a test ALERT_HOOK script receives it").
printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" >> /var/log/chp-test-hook.log
