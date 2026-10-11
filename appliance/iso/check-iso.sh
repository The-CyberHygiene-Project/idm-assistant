#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# check-iso.sh ISO DVD (RUNS ON AERO, sudo): inspect a built ISO. The Secure Boot chain must be byte-identical to the
# DVD's (on the ISO and inside efiboot.img), both menus must be ours, /chp must hold a signed repo, and the boot records
# must still point at /images/efiboot.img (El Torito for DVD, GPT partition for USB). One line per check; exit 1 on any BAD.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
ISO=$1 DVD=$2 bad=0
W=$(mktemp -d -p /var/tmp chp-check.XXXXXX); trap 'for d in "$W"/m*; do mountpoint -q "$d" && umount "$d"; done; rm -rf "$W"' EXIT
ok() { echo "OK   $1"; }
no() { echo "BAD  $1"; bad=1; }
x() { xorriso -osirrox on -indev "$1" -extract "$2" "$3" 2>/dev/null; }
[[ $(xorriso -indev "$ISO" -pvd_info 2>/dev/null | sed -n "s/^Volume Id *: *//p" | tr -d "'") == CHP-LAB-EL9 ]] && ok "volume ID CHP-LAB-EL9" || no "volume ID"
el=$(xorriso -indev "$ISO" -report_el_torito as_mkisofs 2>/dev/null)
[[ $el == *"-e '/images/efiboot.img'"* && $el == *"-isohybrid-gpt-basdat"* ]] && ok "boot records: El Torito EFI + GPT partition -> /images/efiboot.img" || no "boot records"
# The bytes that UEFI really boots from a USB stick: GPT partition 2. On rc1 (xorriso replay) it held the DVD's ORIGINAL
# efiboot.img while the file in the ISO tree was ours. Compare the partition's bytes with the ISO's /images/efiboot.img.
[[ $el != *append_partition* ]] && ok "no appended EFI partition" || no "appended EFI partition (replay-style layout)"
read -r p2s p2n < <(xorriso -indev "$ISO" -report_system_area plain 2>/dev/null | awk '/^GPT start and size :/ && $6 == 2 {print $7, $8}') || true   # no GPT -> empty -> BAD below
x "$ISO" /images/efiboot.img "$W/eb"
if [[ -n ${p2s:-} && -n ${p2n:-} ]] && dd if="$ISO" of="$W/p2" bs=512 skip="$p2s" count="$p2n" status=none \
   && cmp -s -n "$(stat -c %s "$W/eb")" "$W/p2" "$W/eb"; then
  ok "GPT partition 2 (USB UEFI boot) == /images/efiboot.img"
else no "GPT partition 2 differs from /images/efiboot.img (USB boot would not show our menu)"; fi
rm -f "$W/eb" "$W/p2"
for p in /chp/repodata/repomd.xml.asc /chp/chp-site.pyz /chp/ks/server.ks /chp/ks/client.ks /NOTICE.txt; do
  x "$ISO" "$p" "$W/f" && ok "present: $p" || no "missing: $p"; rm -f "$W/f"
done
for f in EFI/BOOT/BOOTX64.EFI EFI/BOOT/grubx64.efi EFI/BOOT/mmx64.efi images/pxeboot/vmlinuz images/pxeboot/initrd.img; do
  x "$DVD" "/$f" "$W/a"; x "$ISO" "/$f" "$W/b"
  cmp -s "$W/a" "$W/b" && ok "unchanged from the DVD: $f" || no "CHANGED: $f"; rm -f "$W/a" "$W/b"
done
x "$DVD" /images/efiboot.img "$W/e1"; x "$ISO" /images/efiboot.img "$W/e2"; mkdir "$W/m1" "$W/m2"
mount -o loop,ro "$W/e1" "$W/m1"; mount -o loop,ro "$W/e2" "$W/m2"
for f in EFI/BOOT/BOOTX64.EFI EFI/BOOT/grubx64.efi EFI/BOOT/mmx64.efi; do
  cmp -s "$W/m1/$f" "$W/m2/$f" && ok "efiboot.img unchanged: $f" || no "efiboot.img CHANGED: $f"
done
x "$ISO" /EFI/BOOT/grub.cfg "$W/g"
cmp -s "$W/g" "$W/m2/EFI/BOOT/grub.cfg" && ok "efiboot.img grub.cfg == ISO grub.cfg (USB boot shows our menu)" || no "efiboot.img grub.cfg differs"
grep -q "CHP-LAB-EL9:/chp/ks/server.ks" "$W/g" && ! grep -q "Install Rocky" "$W/g" && ok "menu is ours" || no "menu"
mkdir "$W/repo"; xorriso -osirrox on -indev "$ISO" -extract /chp "$W/repo" 2>/dev/null || true   # missing /chp -> BAD below
bash /data/chp-release/tools/verify-repo.sh "$W/repo" /data/chp-release/tools >/dev/null && ok "repo on the ISO verifies" || no "repo on the ISO"
python3 "$W/repo/chp-site.pyz" verify-repo --url "file://$W/repo" >/dev/null && ok "chp-site verify-repo accepts it" || no "chp-site verify-repo"
if (( bad )); then echo "ISO BAD"; exit 1; fi
echo "ISO OK"
