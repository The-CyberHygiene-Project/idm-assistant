# ISO Plan 5a proof record: install from nothing, from the ISO (gate 1)

**Date:** 2026-10-10 · **ISO:** `cyberhygiene-lab-installer-el9.iso` 0.1.0-rc2
(sha256 `b2a24baacaadb29554da560d157fecac7ef68ffb428f986aeb286fa87c78725e`) · **Repo:** 0.6.0 (on the ISO)
**Script:** `lab/iso5/prove.sh` (from `lab/iso4/prove.sh`; the install steps now boot the ISO) · **Log:** `~/idm-lab-secrets/iso5-proof-run1.log`
(secrets-scanned: no escrow values, no private keys)

## Hosts

All are q35 VMs on aero: UEFI with Secure Boot on and Microsoft keys enrolled, a vTPM 2.0, one 120 GB disk. Each boots
the ISO as a CD-ROM; the site stick is a removable USB disk image labelled `OEMDRV`.

| VM | MAC | IP | Role | Menu entry chosen |
|---|---|---|---|---|
| `iso5-srv` | 52:54:00:c4:05:50 | .50 | server | 2: *Install identity server, serial console ttyS0* |
| `iso5-cli1` | 52:54:00:c4:05:51 | .51 | client | 3: *Install client workstation, serial console ttyS0* |
| `iso5-cli2` | 52:54:00:c4:05:52 | .52 | client | 3 |

The entry is chosen like a person would: wait for our menu (serial console), then press Down ×N and Enter (`virsh send-key`).
Nothing else is typed during the install.

## Results (run 1): 132 PASS, 0 FAIL

| Stage | PASS | What it proves |
|---|---|---|
| prep | 2/2 | site validates; stick made |
| negrepo | 5/5 | **row 37**: (a) no network in `%pre` → an `http://` repo can't be read → install stops (fail closed); (b) with early network (`ip=`) a tampered `repomd.xml` → `signature is NOT valid` → stop. In both cases the disk is untouched (first and last MiB zero) and no escrow is written |
| server | 2/2 | installed **from the ISO**: our menu, `inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/server.ks`, `REPO SIGNATURE OK: file:///run/install/repo/chp` in `%pre` (gpgv works in the FIPS installer); first boot unlocked with the escrowed passphrase |
| firstboot | 16/16 | server first boot (Kanidm domain, step-ca, SSH CA, tokens, self-client); 0 fapolicyd denials, 0 AVC |
| reboot | 2/2 | **TPM unlock (PCR 7) under Secure Boot with the ISO's boot chain** (rows 15, 17; spec §9 first verification) |
| export | 5/5 | export-client: secrets + both client tokens to the stick |
| client1 | 17/17 | installed from the ISO; pinned anchor; unixd online; authselect / nsswitch / sshd; 0 denials / AVC; TPM unlock after reboot |
| client2 | 17/17 | same |
| ga | 59/59 | second factor (rows 11, 36, 42, 43): the same count as Plan 4b |
| negtrust | 3/3 | a wrong CA pin is refused; the right one restores the anchor |
| scan | 4/4 | CUI scan evaluated on all three pristine hosts; no secrets in the results (gate 3: `DEVIATIONS.md`) |

**Run notes (both recorded in the ledger):**
- The first `negrepo` attempt expected the signature refusal but got the fail-closed stop: `%pre` has no network. The
  stage now checks both cases.
- `ga`'s summary line was lost because the script was edited while it ran. Its 59 checks had all passed, and its last
  line (deleting the GA secrets on aero) had run.

## The spec §9 verifications

- **The ISO build keeps Secure Boot working:** yes. `check-iso.sh` shows shim, grub, mm, the kernel and the initrd are
  byte-identical to the DVD's. The TPM unlocked after reboot on all three hosts.
  - The build uses xorriso with the DVD's own mkisofs options, not `mkksiso` (lorax isn't installed on aero).
  - xorriso's `replay` mode was tried first and rejected: rc1, `RELEASE-RECORD-0.6.0.md`.
- **Anaconda finds `OEMDRV` on a VM USB disk:** yes. A real USB stick is not proven here.

## Gate-1 exception for the ISSO

The first boot after each install asks **once** for the escrowed LUKS passphrase. The TPM is bound during that first
boot (Plan 3a design). `unlock.sh` types it over the serial console. Every later boot unlocks by TPM. Gate 1 says "no
console typing beyond choosing the boot entry", so this is an exception for the ISSO to accept or to turn into a design
change.

## Not proven here

- Real hardware: physical UEFI/TPM PCR values, a real USB stick, a DVD drive.
- The non-serial menu entries (0 and 1). They differ from 2 and 3 only by `console=ttyS0,115200`.
- The regression on installed hosts (gate 2): Plan 5b.
