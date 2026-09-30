#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build.sh: pack chp_site into one zipapp, dist/chp-site.pyz, run by the system python3 (installer, hosts, Mac).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$here/dist"; cp -R "$here/chp_site" "$T/"; find "$T" -name __pycache__ -prune -exec rm -rf {} +
python3 -m zipapp "$T" -m "chp_site.cli:run" -p "/usr/bin/python3" -o "$here/dist/chp-site.pyz"
echo "$here/dist/chp-site.pyz"
