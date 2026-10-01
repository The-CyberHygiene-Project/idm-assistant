#!/bin/sh
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# /usr/bin/chp-site: run the packaged zipapp with the system python3 (the zipapp has no shebang on purpose: fapolicyd).
exec /usr/bin/python3 /usr/share/chp-site/chp-site.pyz "$@"
