#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# client-firstboot (chp-client-firstboot.service): enrol this client once (spec §7). Resume: systemctl restart chp-client-firstboot.
exec /usr/libexec/chp/client-enrol --role client
