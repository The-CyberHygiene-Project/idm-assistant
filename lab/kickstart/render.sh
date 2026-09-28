#!/usr/bin/env bash
# render.sh NAME -> $OUT (default /tmp/NAME.ks) from base.ks.in. SSH_PUBKEY defaults to ~/.ssh/aero_ecdsa.pub.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; n="${1:?usage: render.sh NAME}"
case "$n" in
  srv1)    ip=192.168.100.10; pkgs="bind bind-utils policycoreutils-python-utils setools-console" ;;
  client2) ip=192.168.100.13; pkgs="authselect expect policycoreutils-python-utils setools-console cryptsetup clevis clevis-luks clevis-systemd tpm2-tools" ;;
  *) echo "unknown host: $n" >&2; exit 1 ;;
esac
key="${SSH_PUBKEY:-$(cat ~/.ssh/aero_ecdsa.pub)}"; out="${OUT:-/tmp/$n.ks}"
python3 - "$here/base.ks.in" "$out" "$n" "$ip" "$key" "$pkgs" <<'PY'
import sys
src, out, host, ip, key, pkgs = sys.argv[1:]
s = open(src).read()
for k, v in {"@HOST@": host, "@IP@": ip, "@SSH_PUBKEY@": key, "@PACKAGES@": "\n".join(pkgs.split())}.items():
    s = s.replace(k, v)
open(out, "w").write(s)
PY
echo "$out"
