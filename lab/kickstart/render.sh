#!/usr/bin/env bash
# render.sh NAME -> $OUT (default /tmp/NAME.ks) from base.ks.in. SSH_PUBKEY defaults to ~/.ssh/aero_ecdsa.pub.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; n="${1:?usage: render.sh NAME}"
case "$n" in
  srv1)    ip=192.168.100.10; pkgs="bind bind-utils policycoreutils-python-utils setools-console" ;;
  client1) ip=192.168.100.12; pkgs=""; tmpl=client1.ks.in ;;
  client2) ip=192.168.100.13; pkgs="authselect expect policycoreutils-python-utils setools-console cryptsetup clevis clevis-luks clevis-systemd tpm2-tools" ;;
  *) echo "unknown host: $n" >&2; exit 1 ;;
esac
key="${SSH_PUBKEY:-$(cat ~/.ssh/aero_ecdsa.pub)}"; out="${OUT:-/tmp/$n.ks}"; tmpl="${tmpl:-base.ks.in}"
# client1's LUKS passphrase: $LUKSPASS (tests) or the lab secret; it is passed to python via the environment, not argv.
if [[ $n == client1 ]]; then export LUKSPASS="${LUKSPASS:-$(cat ~/idm-lab-secrets/client1-luks.pass)}"; fi
( umask 077; python3 - "$here/$tmpl" "$out" "$n" "$ip" "$key" "$pkgs" <<'PY'
import sys
src, out, host, ip, key, pkgs = sys.argv[1:]
s = open(src).read()
import os
for k, v in {"@HOST@": host, "@IP@": ip, "@SSH_PUBKEY@": key, "@PACKAGES@": "\n".join(pkgs.split()),
             "@LUKSPASS@": os.environ.get("LUKSPASS", "")}.items():
    s = s.replace(k, v)
open(out, "w").write(s)
PY
)
echo "$out"
