#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# firstboot-common.sh (root; chp-firstboot-common.service, both roles, once):
#   1. TPM binding: bind clevis (TPM2, PCR 7) using the ONE-TIME key the installer left at /root/.chp-bind.key (in its
#      own LUKS slot), then kill that slot and shred the file. The escrowed passphrase never touches this disk.
#      On failure: log loudly, keep key + slot (retry: systemctl restart chp-firstboot-common), never fail the boot.
#   2. restorecon over the identity paths.   3. shred the installer's kickstart copies (row 16).
set -uo pipefail
M=/var/lib/chp/firstboot; K=/root/.chp-bind.key
install -d -m 0700 "$M"
log() { echo "chp-firstboot-common: $*"; logger -t chp-firstboot-common -- "$*"; }
ok=1

if [ -f "$K" ]; then
  dev=$(lsblk -rpno NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1}')
  if [ "$(printf '%s\n' "$dev" | grep -c .)" -ne 1 ]; then
    log "CHP: TPM binding failed (expected exactly one LUKS device, found: ${dev:-none}); the escrowed passphrase still unlocks; retry: systemctl restart chp-firstboot-common"
    touch "$M/common.bind-failed"; ok=0
  else
    slot=$(cryptsetup luksOpen --test-passphrase --key-file "$K" --verbose "$dev" 2>&1 | sed -n 's/^Key slot \([0-9]*\) unlocked.*/\1/p')
    if [ -z "$slot" ]; then
      log "CHP: TPM binding failed (the one-time key does not open $dev); the escrowed passphrase still unlocks"
      touch "$M/common.bind-failed"; ok=0
    elif clevis luks list -d "$dev" 2>/dev/null | grep -q tpm2 \
         || err=$(clevis luks bind -y -k "$K" -d "$dev" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}' 2>&1); then
      # Already bound (a retry) or bound now. Batch mode (-q) needs no remaining key; the one-time key must NOT be given
      # as the "remaining" key, because it belongs to the slot being killed.
      if cryptsetup luksKillSlot -q "$dev" "$slot"; then
        shred -u "$K"; rm -f "$M/common.bind-failed"
        log "TPM binding done on $dev (PCR 7); one-time key slot $slot removed"
      else
        log "CHP: TPM bound, but removing one-time key slot $slot failed; remove it by hand: cryptsetup luksKillSlot $dev $slot"
        ok=0
      fi
    else
      log "CHP: TPM binding failed ($(printf '%s' "$err" | tail -n 1)); the escrowed passphrase still unlocks; retry: systemctl restart chp-firstboot-common"
      touch "$M/common.bind-failed"; ok=0
    fi
  fi
fi

for p in /etc/chp /etc/kanidm /etc/pki/kanidm /etc/ssh-ca /var/lib/ssh-ca /etc/step-ca /etc/idm-collect; do
  if [ -e "$p" ]; then restorecon -R "$p"; fi
done
for f in /root/original-ks.cfg /root/anaconda-ks.cfg; do
  if [ -e "$f" ]; then shred -u "$f"; fi
done

if [ "$ok" -eq 1 ]; then touch "$M/common.done"; log "first boot (common) complete"; fi
exit 0
