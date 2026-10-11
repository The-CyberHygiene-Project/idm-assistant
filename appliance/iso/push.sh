#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# push.sh (RUNS ON THE MAC): build/render the ISO inputs and copy them, with the build scripts, to aero.
set -Eeuo pipefail
top="$(cd "$(dirname "$0")/../.." && pwd)"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
bash "$top/appliance/chp-site/build.sh" >/dev/null
bash "$top/appliance/kickstart/render-ks.sh" >/dev/null
bash "$top/appliance/iso/render-boot.sh" "$T" >/dev/null
cp "$top/appliance/chp-site/dist/chp-site.pyz" "$top/appliance/kickstart/server.ks" "$top/appliance/kickstart/client.ks" \
   "$top/appliance/branding/NOTICE.txt" "$top/appliance/iso/build-iso.sh" "$top/appliance/iso/check-iso.sh" "$T/"
ssh aero 'rm -rf /data/chp-release/iso-src && mkdir -p /data/chp-release/iso-src'
scp -q "$T"/* aero:/data/chp-release/iso-src/
echo "pushed to aero:/data/chp-release/iso-src/: $(ls "$T" | tr '\n' ' ')"
