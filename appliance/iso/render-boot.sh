#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# render-boot.sh OUT_DIR [VOLID]: grub.cfg and isolinux.cfg for the ISO (banner from appliance/branding/boot-banner.txt).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; out=$1; volid=${2:-CHP-LAB-EL9}
mkdir -p "$out"
python3 - "$here" "$out" "$volid" <<'PY'
import sys
here, out, volid = sys.argv[1:]
banner = [ln for ln in open(f"{here}/../branding/boot-banner.txt").read().splitlines() if ln.strip()]
for ln in banner:
    assert "'" not in ln, "banner lines must not contain a single quote (grub echo quoting)"
echo = "\n".join(f"echo '{ln}'" for ln in banner)
say = "\n".join(f"say {ln}" for ln in banner)
g = open(f"{here}/grub.cfg.in").read().replace("@VOLID@", volid).replace("@BANNER_ECHO@", echo)
i = open(f"{here}/isolinux.cfg.in").read().replace("@BANNER_SAY@", say)
open(f"{out}/grub.cfg", "w").write(g)
open(f"{out}/isolinux.cfg", "w").write(i)
PY
echo "rendered: $out/grub.cfg $out/isolinux.cfg ($volid)"
