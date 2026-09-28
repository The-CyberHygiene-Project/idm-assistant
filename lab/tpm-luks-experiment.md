# Virtual TPM + LUKS/clevis experiment (Plan 3, Task 11, 2026-09-27)

**Question (ISSO, from Plan 2):** can a VM have a TPM, and can the TPM unlock a LUKS volume at boot so that disk encryption and unattended reboots coexist?

**Answer:** yes, in the lab.
- A **software TPM** (swtpm) works on the FIPS host and inside a FIPS guest.
- **clevis** unlocks a LUKS2 data volume automatically at boot.
- The unlock **refuses** once the bound PCR changes.

The PCR used here carries **no boot-integrity meaning** in the lab (see "Limits").

## Setup

| Item | Value |
|---|---|
| Host | aero, `fips=1`; swtpm 0.8.0 + libtpms 0.9.1 (already present as libvirt dependencies) |
| Guest | client2 (Rocky 9.8, `fips=1`, SELinux enforcing, CUI); libvirt `<tpm model='tpm-crb'><backend type='emulator' version='2.0'/>`; SeaBIOS |
| TPM seen by the guest | `/dev/tpm0`, `/dev/tpmrm0`; family `2.0`, manufacturer `IBM` (swtpm); `tpm2_getrandom` works; 33 algorithms listed |
| Volume | second virtual disk `vdb` (2 GB), LUKS2, script `lab/client/20-vtpm-luks.sh` |

## Results

1. **LUKS2 under FIPS:** `cipher aes-xts-plain64`, 512-bit key, hash `sha256`, **PBKDF `pbkdf2`**. FIPS mode makes cryptsetup use PBKDF2 instead of its default Argon2id, because Argon2 is not FIPS-approved.
2. **clevis binding:** slot 1 = `tpm2 {"hash":"sha256","key":"ecc","pcr_bank":"sha256","pcr_ids":"7"}`. The passphrase slot stays as a fallback; it is kept on client2 in `/root/luks-lab.pass`, 0600, lab only.
3. **Unattended unlock at boot:** after a cold start, `systemd-cryptsetup@labdata` opened the volume in about 4 s with no passphrase, and `/srv/labdata` mounted. This was repeated after a normal reboot.
4. **Negative test:**
   - Extending PCR 7 (`tpm2_pcrextend 7:sha256=00…`), then `clevis luks unlock` → **refused**: `Esys_Unseal … ErrorCode (0x0000099d)`, a TPM policy mismatch.
   - A reboot reset the PCRs, and automatic unlock worked again.

## Defects and lessons (mine, fixed in the script)

- **Shutdown hang:** the script first opened the volume by hand (`cryptsetup open`) after adding the crypttab line, without `systemctl daemon-reload`. At the next shutdown, systemd had no cryptsetup unit for it and waited forever: "A stop job is running for /dev/mapper/labdata (no limit)". The VM needed a hard power-off. The script now closes the manual mapping and reloads systemd before finishing.
- The first run wrote the test marker before the volume was mounted, so the marker landed on the plain directory. Fixed: mount first.

## Limits of this lab result

- **PCRs 0 and 7 read all zeros:** SeaBIOS does not measure the boot into the TPM. Binding to PCR 7 here only proves the *mechanism* (seal/unseal/refuse). It does **not** prove that a tampered boot would be refused. On dc2 (UEFI, Secure Boot) PCR 7 reflects the Secure Boot state and is meaningful. A UEFI (OVMF) lab VM would be the next step to show this.
- The volume is a **data** volume. Unlocking the **root** volume needs `clevis-dracut` in the initramfs; that is a separate test.
- swtpm keeps its state in a file on aero. A software TPM protects nothing against someone who can read the host; it is a lab stand-in for a hardware TPM.
- Kanidm's own `tpm` feature (TPM-bound credential cache in unixd) was not built (ISSO Decision 5). unixd did start with the TPM present: its unit grants `/dev/tpmrm0` and the `tss` group.

## What this means for dc2

- A **hardware TPM + clevis** can give LUKS-encrypted **data** volumes unattended reboots; use UEFI/Secure Boot and bind to PCR 7 (optionally more PCRs).
- **Root-volume** unlock at boot is a separate design and test (`clevis-dracut`); decide whether the root volume gets TPM unlock or stays passphrase-only.
- Keep a **fallback passphrase slot** in escrow (the bound TPM refuses after a firmware or Secure Boot change, by design).
- FIPS mode changes LUKS2 defaults (PBKDF2). Volumes created on a non-FIPS system with Argon2id may not open on a FIPS host; create them on the FIPS host.

## Revert (client2)

```
umount /srv/labdata; cryptsetup close labdata
clevis luks unbind -d /dev/vdb -s 1 -f
cryptsetup erase /dev/vdb            # destroys the lab volume's keys
sed -i '/^labdata /d' /etc/crypttab; sed -i '\#/srv/labdata#d' /etc/fstab
systemctl daemon-reload; rm -f /root/luks-lab.pass
```
Or simply `lab/reset.sh client2` (golden predates this experiment).
