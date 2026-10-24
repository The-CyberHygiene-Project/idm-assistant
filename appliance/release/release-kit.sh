#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# V=… REPO_V=… release-kit.sh (RUNS ON THE MAC, YubiKey plugged in): publish the site-stick kit for the RELEASED V to the
# For Jeff share as site-stick-kit-V/, beside V/ (neither V/ nor any earlier kit is touched): the guide, the two templates, and chp-site.pyz taken from the RELEASED
# repo tarball (the exact checker the 0.1.0 installer runs), with SHA256SUMS signed by the project key. Also writes the
# share's top-level README.md (a pointer only; nothing in it needs to be trusted). Built in <target>.partial; renamed
# only when every check passed.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; kit="$top/appliance/site-stick-kit"
FPR=2DE0D71BF37D8F5E4201A590521276F43C908F8E
V=${V:?set V (the released version, e.g. 0.2.0)} REPO_V=${REPO_V:?set REPO_V (its signed repo)}
SHARE="/Volumes/For Jeff"; B="$SHARE/cyberhygiene-lab-installer"; T="$B/site-stick-kit-$V"; P="$T.partial"
REL="$B/$V"; TAR="$REL/chp-repo-$REPO_V.tar.gz"
[[ -d $SHARE ]] || { echo "refusing: $SHARE is not mounted"; exit 1; }
[[ -e $T ]] && { echo "refusing: $T already exists"; exit 1; }
gpg --card-status >/dev/null 2>&1 || { echo "refusing: YubiKey not found (plug it in)"; exit 1; }
echo "== the released $V checksums must still verify (the pyz comes from its repo tarball)"
gpg --verify "$REL/SHA256SUMS.asc" "$REL/SHA256SUMS" 2>&1 | grep -q "Good signature" || { echo "refusing: $V SHA256SUMS signature"; exit 1; }
# Only the repo tarball is re-checked here (the 15 GB ISO is not needed for the kit):
want=$(grep " chp-repo-$REPO_V.tar.gz\$" "$REL/SHA256SUMS" | cut -d' ' -f1)
[[ -n $want && $(shasum -a 256 "$TAR" | cut -d' ' -f1) == "$want" ]] || { echo "refusing: repo tarball checksum"; exit 1; }
rm -rf "$P"; mkdir -p "$P"; w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
RPM=$(tar tzf "$TAR" | grep -E '^(\./)?repo/chp-site-.*\.noarch\.rpm$' | head -1)
[[ -n $RPM ]] || { echo "refusing: no chp-site RPM in $TAR"; exit 1; }
(cd "$w" && tar xzf "$TAR" "$RPM" && tar xf "$RPM")
cp "$w/usr/share/chp-site/chp-site.pyz" "$P/"
cp "$kit/SITE-STICK.md" "$kit/site.conf.template" "$kit/hosts.template" "$P/"
(cd "$P" && shasum -a 256 SITE-STICK.md site.conf.template hosts.template chp-site.pyz > SHA256SUMS)
echo "== signing SHA256SUMS (PIN dialog, then touch the key)"; say "Kit signing now. Watch for the PIN dialog." 2>/dev/null || true
gpg --local-user "$FPR" --armor --detach-sign -o "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
echo "== checks"
gpg --verify "$P/SHA256SUMS.asc" "$P/SHA256SUMS"
(cd "$P" && shasum -a 256 -c SHA256SUMS)
python3 "$P/chp-site.pyz" --version
mv "$P" "$T"
cat > "$B/README.md" <<'EOF'
# CyberHygiene Project Lab Installer — For Jeff

Internal test images for the CyberHygiene Project development team. Not an official Rocky Linux product.

| Folder | What it is | Start with |
|---|---|---|
| `0.1.0/` | release 0.1.0: the installer ISO, its signed package repo, the release key | `0.1.0/VERIFY.md` |
| `site-stick-kit/` | the site-stick kit for 0.1.0 | `site-stick-kit/SITE-STICK.md` |
| `0.2.0/` | release 0.2.0 (adds AIDE file integrity): ISO, signed repo, key, upgrade note for 0.1.0 sites | `0.2.0/VERIFY.md` |
| `site-stick-kit-0.2.0/` | the site-stick kit for 0.2.0 | `site-stick-kit-0.2.0/SITE-STICK.md` |

Each folder has its own `SHA256SUMS` and `SHA256SUMS.asc`, signed with the project release key. Check a folder as its
release's `VERIFY.md` describes before you use anything in it.

Never put a filled-in site stick, or a copy of it, in this share: after the first install it holds every machine's
recovery passwords.
EOF
echo "RELEASED: $T"; ls -l "$T"; echo "README: $B/README.md"
