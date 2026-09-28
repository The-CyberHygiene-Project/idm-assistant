#!/usr/bin/env bash
# client2: LUKS2 on the 2 GB test disk (vdb), bound to the virtual TPM with clevis; unattended unlock at boot via
# crypttab + clevis-luks-askpass. Lab passphrase (fallback key) is generated here into /root/luks-lab.pass (0600).
set -Eeuo pipefail
D=/dev/vdb; P=/root/luks-lab.pass
[[ -s $P ]] || { head -c 32 /dev/urandom | base64 > $P; chmod 600 $P; }
if ! cryptsetup isLuks $D; then
  cryptsetup luksFormat --type luks2 --batch-mode --key-file $P $D
fi
cryptsetup luksDump $D | grep -E 'PBKDF|Cipher|Hash' | sort -u      # FIPS evidence: which KDF did FIPS mode choose?
clevis luks list -d $D | grep -q tpm2 || clevis luks bind -y -k $P -d $D tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
clevis luks list -d $D
cryptsetup open --key-file $P $D labdata 2>/dev/null || true
blkid /dev/mapper/labdata >/dev/null 2>&1 || mkfs.xfs -q /dev/mapper/labdata
uuid=$(cryptsetup luksUUID $D)
grep -q '^labdata ' /etc/crypttab || echo "labdata UUID=$uuid none luks,_netdev" >> /etc/crypttab
mkdir -p /srv/labdata
grep -q '/srv/labdata' /etc/fstab || echo "/dev/mapper/labdata /srv/labdata xfs defaults,_netdev 0 0" >> /etc/fstab
systemctl enable clevis-luks-askpass.path
mountpoint -q /srv/labdata || mount /srv/labdata
echo "tpm-bound" > /srv/labdata/marker   # on the encrypted volume (mounted first)
# Hand the volume back to systemd: a mapping opened by hand has no systemd-cryptsetup unit, and the next shutdown
# then waits forever on "A stop job is running for /dev/mapper/labdata (no limit)" (seen 2026-09-27).
umount /srv/labdata 2>/dev/null || true
cryptsetup close labdata 2>/dev/null || true
systemctl daemon-reload
