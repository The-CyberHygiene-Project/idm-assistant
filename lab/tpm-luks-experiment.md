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

## Root volume + Secure Boot (Plan 4, client1, 2026-09-28)

client1 is a UEFI VM (OVMF `OVMF_CODE.secboot.fd`, Microsoft keys enrolled, q35/SMM) with swtpm TPM 2.0. Its **root** LVM sits inside LUKS2 (swap included), per the CHP kit's PARTITIONS_3.

| Firmware state | Secure Boot | PCR 7 (sha256) | Root unlock |
|---|---|---|---|
| Microsoft keys enrolled | enabled | `0x4B041925…5D310CCE` | **automatic**: after `virsh destroy` + `start`, sshd was reachable within ~20 s with nobody at the console, twice |
| Blank variable store (`OVMF_VARS.fd`) | disabled, "Setup Mode" | `0xB926225A…ABECDDF1` | **refused by the TPM**; passphrase typed via serial console |
| Enrolled store restored | enabled | `0x4B041925…5D310CCE` (identical) | **automatic** again |

**Findings:**
- **PCR 7 is meaningful under UEFI Secure Boot.** It changes with the Secure Boot state and is stable across reboots. Unlike Plan 3's SeaBIOS VM (all-zero PCRs), this proves boot-state binding, not just the mechanism.
- **Bind on the first real boot, not in the kickstart `%post`.** virt-install `--location` starts the installer by direct kernel boot, bypassing shim/GRUB, so PCR 7 during install differs and a `%post` binding never unlocks. For dc2 on real hardware the installer does boot through shim, but binding after the first real boot is the safe rule (`lab/client/bind-root-tpm.sh`).
- The console still *shows* "Please enter passphrase" while clevis answers it from the TPM. A human sees a prompt that needs no answer.
- `clevis luks bind -k -` reads the passphrase from stdin; a preceding command in the same remote shell can swallow it.
- Lab VMs now use a pty serial console that also logs to file (`vm-lib.sh`), so a LUKS prompt can be answered via `virsh console` (`lab/host/luks-console-unlock.exp`, passphrase over stdin).

**Passphrase at rest (review finding, fixed):** Anaconda keeps a verbatim `/root/original-ks.cfg`. With `part … --passphrase=`, it held the **plaintext LUKS passphrase** on the volume it protects (and in any backup of `/root`). It was found and shredded on client1 on 2026-09-28, and older snapshots were deleted. `bind-root-tpm.sh` now shreds it after binding. **For dc2:** never leave the install passphrase on the installed system; check `/root/*ks*`.

**For dc2:** TPM2 + clevis + Secure Boot (PCR 7) gives an unattended reboot of an encrypted **root** volume. A Secure Boot change (firmware update, key change, SB disabled) makes the TPM refuse by design, and the escrowed passphrase is then needed. Plan firmware updates accordingly (re-bind afterwards).
