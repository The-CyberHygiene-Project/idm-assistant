#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-iso.sh REPO_V ISO_V (RUNS ON AERO, sudo): the Rocky 9.8 DVD + signed repo REPO_V + /data/chp-release/iso-src
# -> /var/lib/libvirt/images/chp-iso/ISO_V/cyberhygiene-lab-installer-el9.iso. The boot chain (shim, grub, kernel,
# initrd, El Torito and GPT boot records) is replayed from the DVD unchanged; only the menus and /chp are new.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
REPO_V=$1 ISO_V=$2
DVD=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso
DVD_SHA=d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f
REPO=/data/chp-release/$REPO_V/repo TOOLS=/data/chp-release/tools SRC=/data/chp-release/iso-src
OUT=/var/lib/libvirt/images/chp-iso/$ISO_V NAME=cyberhygiene-lab-installer-el9.iso VOLID=CHP-LAB-EL9
[[ -e $OUT ]] && { echo "refusing: $OUT exists"; exit 1; }
for f in grub.cfg isolinux.cfg server.ks client.ks chp-site.pyz NOTICE.txt; do
  [[ -f $SRC/$f ]] || { echo "refusing: $SRC/$f missing (run appliance/iso/push.sh on the Mac)"; exit 1; }
done
avail=$(df --output=avail -B1G /var/lib/libvirt/images | tail -1 | tr -d ' ')
(( avail >= 20 )) || { echo "refusing: only ${avail} GB free under /var/lib/libvirt/images (need 20)"; exit 1; }
echo "== DVD: sha256 (takes about a minute)"
[[ $(sha256sum "$DVD" | cut -d' ' -f1) == "$DVD_SHA" ]] || { echo "refusing: DVD sha256 differs from the pin"; exit 1; }
echo "== repo $REPO_V: signatures"
bash "$TOOLS/verify-repo.sh" "$REPO" "$TOOLS"
W=$(mktemp -d -p /var/tmp chp-iso.XXXXXX); m=$W/mnt; mkdir "$m"
trap 'mountpoint -q "$m" && umount "$m"; rm -rf "$W"' EXIT
echo "== stage /chp"
mkdir -p "$W/chp/ks"
cp -a "$REPO"/. "$W/chp/"
install -m 0644 "$SRC/chp-site.pyz" "$W/chp/chp-site.pyz"
install -m 0644 "$SRC/server.ks" "$SRC/client.ks" "$W/chp/ks/"
echo "== efiboot.img: our grub.cfg (USB/UEFI boot reads this copy; the EFI binaries are not touched)"
xorriso -osirrox on -indev "$DVD" -extract /images/efiboot.img "$W/efiboot.img" 2>/dev/null
chmod u+w "$W/efiboot.img"
mount -o loop "$W/efiboot.img" "$m"
[[ -f $m/EFI/BOOT/grub.cfg ]] || { echo "efiboot.img has no EFI/BOOT/grub.cfg"; exit 1; }
cp "$SRC/grub.cfg" "$m/EFI/BOOT/grub.cfg"; sync; umount "$m"
echo "== ISO"
mkdir -p "$OUT"
xorriso -indev "$DVD" -outdev "$OUT/$NAME" -volid "$VOLID" \
  -map "$W/chp" /chp \
  -map "$SRC/grub.cfg" /EFI/BOOT/grub.cfg \
  -map "$SRC/isolinux.cfg" /isolinux/isolinux.cfg \
  -map "$W/efiboot.img" /images/efiboot.img \
  -map "$SRC/NOTICE.txt" /NOTICE.txt \
  -boot_image any replay 2>&1 | tail -3
(cd "$OUT" && sha256sum "$NAME" > SHA256SUMS)
{ echo "ISO $ISO_V built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname -s)"
  echo "DVD Rocky-9.8-x86_64-dvd.iso sha256 $DVD_SHA"
  echo "repo $REPO_V repomd.xml sha256 $(sha256sum "$REPO/repodata/repomd.xml" | cut -d' ' -f1)"
  for f in chp-site.pyz server.ks client.ks grub.cfg isolinux.cfg NOTICE.txt; do echo "$f sha256 $(sha256sum "$SRC/$f" | cut -d' ' -f1)"; done
  echo "xorriso $(xorriso -version 2>/dev/null | head -1)"
  cat "$OUT/SHA256SUMS"; } > "$OUT/BUILD-RECORD.txt"
chmod 0644 "$OUT"/*
echo "built: $OUT/$NAME"
