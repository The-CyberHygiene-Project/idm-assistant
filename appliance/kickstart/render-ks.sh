#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# render-ks.sh: server.ks and client.ks from chp.ks.in (the only difference is @ROLE@).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
for r in server client; do sed "s/@ROLE@/$r/g" "$here/chp.ks.in" > "$here/$r.ks"; done
echo "rendered: $here/server.ks $here/client.ks"
