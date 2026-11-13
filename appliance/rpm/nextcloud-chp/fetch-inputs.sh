#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# fetch-inputs.sh (RUNS ON THE MAC, the only machine with internet; the build VM and the server never reach it):
# download and VERIFY the upstream inputs of nextcloud-chp into ${IDM_INPUTS:-~/idm-lab-inputs}/nextcloud-chp, and
# write MANIFEST.txt next to this script (file|version|bytes|sha256|source|verification). Files already present are
# not downloaded again, but always verified again. Versions are pinned here and in nextcloud-chp.spec (a static
# test checks that they agree).
#   server tarball: sha256 == the published .sha256 AND a GPG signature by Nextcloud Security
#                   (fingerprint 2880 6A87 8AE4 23A2 8372 792E D758 99B9 A724 937A, pinned below)
#   app tarballs:   the app store's release signature (RSA-SHA512 over the tarball) verified with the app's
#                   certificate; that certificate verified against the Nextcloud code-signing root shipped in the
#                   (already verified) server tarball (resources/codesigning/root.crt); CN == app id
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; MAN="$here/MANIFEST.txt"
NC=35.0.3
APPS="groupfolders:23.0.1 files_accesscontrol:6.0.1 user_oidc:8.13.0"
FPR=28806A878AE423A28372792ED75899B9A724937A
D="${IDM_INPUTS:-$HOME/idm-lab-inputs}/nextcloud-chp"; mkdir -p "$D"; cd "$D"
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
get() { [[ -s $1 ]] || curl -fsSL --retry 3 -o "$1" "$2"; }
B=https://download.nextcloud.com/server/releases
for s in "" .sha256 .asc; do get "nextcloud-$NC.tar.bz2$s" "$B/nextcloud-$NC.tar.bz2$s"; done
get nextcloud.asc https://nextcloud.com/nextcloud.asc
[[ $(awk -v f="nextcloud-$NC.tar.bz2" '$2==f{print $1}' "nextcloud-$NC.tar.bz2.sha256") == "$(sha "nextcloud-$NC.tar.bz2")" ]] || { echo "server sha256 MISMATCH"; exit 1; }
G=$(mktemp -d); trap 'rm -rf "$G"' EXIT
gpg --homedir "$G" -q --import nextcloud.asc 2>/dev/null
gpg --homedir "$G" --status-fd 1 --verify "nextcloud-$NC.tar.bz2.asc" "nextcloud-$NC.tar.bz2" 2>/dev/null | grep -q "VALIDSIG $FPR" \
  || { echo "server GPG signature NOT valid for $FPR"; exit 1; }
echo "server: nextcloud-$NC sha256 + GPG OK"
tar -xjOf "nextcloud-$NC.tar.bz2" nextcloud/resources/codesigning/root.crt > nc-root.crt
get "apps-$NC.json" "https://apps.nextcloud.com/api/v1/platform/$NC/apps.json"
{ echo "# nextcloud-chp inputs (fetch-inputs.sh, $(date -u +%F)): file|version|bytes|sha256|source|verification"
  echo "nextcloud-$NC.tar.bz2|$NC|$(stat -f %z "nextcloud-$NC.tar.bz2")|$(sha "nextcloud-$NC.tar.bz2")|$B|sha256 == published .sha256; GPG VALIDSIG $FPR"; } > "$MAN.new"
for pin in $APPS; do
  app=${pin%%:*}; ver=${pin#*:}
  python3 -I - "apps-$NC.json" "$app" "$ver" > "$app.rel" <<'PY'
import json, sys
apps = {a["id"]: a for a in json.load(open(sys.argv[1]))}; a = apps[sys.argv[2]]
rel = [r for r in a["releases"] if r["version"] == sys.argv[3] and not r["isNightly"]]
if len(rel) != 1:
    sys.exit(f"{sys.argv[2]} {sys.argv[3]}: not in the app store listing for this NextCloud version")
print(rel[0]["download"]); print(rel[0]["signature"].replace("\n", "")); print(a["certificate"].replace("\n", "\\n"))
PY
  { read -r url; read -r sig; read -r cert; } < "$app.rel"
  f="$app-$ver.tar.gz"; get "$f" "$url"
  printf '%b\n' "$cert" > "$app.crt"; printf '%s' "$sig" | base64 -d > "$f.sig"
  openssl verify -CAfile nc-root.crt "$app.crt" >/dev/null || { echo "$app: certificate NOT signed by the Nextcloud root"; exit 1; }
  cn=$(openssl x509 -in "$app.crt" -noout -subject | sed -n 's/.*CN *= *//p')
  [[ $cn == "$app" ]] || { echo "$app: certificate CN '$cn' != app id"; exit 1; }
  openssl x509 -in "$app.crt" -noout -pubkey > "$app.pub"
  openssl dgst -sha512 -verify "$app.pub" -signature "$f.sig" "$f" >/dev/null || { echo "$app: release signature NOT valid"; exit 1; }
  echo "$app: $ver certificate (Nextcloud root, CN=$app) + release signature OK"
  echo "$f|$ver|$(stat -f %z "$f")|$(sha "$f")|$url|app-store RSA-SHA512 signature OK; cert CN=$app chains to nextcloud root.crt" >> "$MAN.new"
  rm -f "$app.rel" "$app.pub"
done
mv "$MAN.new" "$MAN"; echo "MANIFEST: $MAN"
