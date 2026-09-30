#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# render-ks.sh: server.ks and client.ks from chp.ks.in (the only difference is @ROLE@).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
python3 - "$here" <<'PY'
import sys
here = sys.argv[1]
roles = {"server": {"@ROLE_PACKAGES@": "chp-base\nchp-identity-server\nchp-identity-client",
                    "@ROLE_ENABLE@": "chp-server-firstboot.service"},
         "client": {"@ROLE_PACKAGES@": "chp-base\nchp-identity-client", "@ROLE_ENABLE@": "chp-client-firstboot.service"}}
t = open(f"{here}/chp.ks.in").read()
for role, subs in roles.items():
    out = t.replace("@ROLE@", role)
    for k, v in subs.items():
        out = out.replace(k, v)
    open(f"{here}/{role}.ks", "w").write(out.replace("chp-monitor.timer \n", "chp-monitor.timer\n"))
PY
echo "rendered: $here/server.ks $here/client.ks"
