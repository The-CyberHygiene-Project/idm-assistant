# Release record: CyberHygiene Project Lab Installer 0.1.0 (EL9)

**Date:** 2026-10-11 · **Released to:** `For Jeff/cyberhygiene-lab-installer/0.1.0/` (Synology share, development team
only; not a public release, spec §8) · **Signed by:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey)

**0.1.0 is byte-for-byte ISO 0.1.0-rc5**, the build that passed all three acceptance gates. Nothing was rebuilt after
testing. `release-iso.sh` refuses any other sha256.

| | |
|---|---|
| ISO | `cyberhygiene-lab-installer-el9.iso`, 15,486,507,008 bytes, sha256 `efcba98a4268ec35ccef0b66b78122b3c78246424f76186cfa45a1ba80ff81b2` |
| Package repository | 0.6.3 (`RELEASE-RECORD-0.6.3.md`), also shipped as `chp-repo-0.6.3.tar.gz` |
| Base | Rocky Linux 9.8 DVD (sha256 `d2bcbb64…6d01f`); shim, grub and kernel unchanged (`check-iso.sh`) |

## Gates (spec §1)

| Gate | Result | Evidence |
|---|---|---|
| 1. Install from nothing (server + 2 clients, UEFI + Secure Boot + vTPM) | 141/141 | `lab/iso5/PROOF-RECORD.md` (run 4) |
| 2. Regression on the installed hosts | 11 scenarios GREEN ×3 (33/33) + row 36 ×3 | `lab/iso5/regression-2026-10-11.md` |
| 3. CUI scan (dc2 tailoring) | 102 pass, 0 fail on every host | `lab/iso5/DEVIATIONS.md` |

## Known limits (accepted by the ISSO, 2026-10-11)

- **Proven on VMs only.** It has not yet run on real hardware, a real USB stick, the physical TPM's PCR values, or the
  non-serial menu entries. Jeff's dc2 install is the first real-hardware run.
- **The first start of each installed host** asks once for the escrowed LUKS passphrase from the site stick. The TPM is
  bound during that boot.
- **The ISO is about 15 GB** (the full Rocky DVD is kept).
- **Seven minor review findings from Plan 5a are deferred** (listed in PR #24).

## Signed checksums (`SHA256SUMS`, verified with `gpg --verify`: "Good signature")

```
efcba98a4268ec35ccef0b66b78122b3c78246424f76186cfa45a1ba80ff81b2  cyberhygiene-lab-installer-el9.iso
cd103d797f600639e6de15ae7010e0fc44787ec7fb5bed4a4368c0a623b3f579  chp-repo-0.6.3.tar.gz
f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f  RPM-GPG-KEY-cyberhygiene
a6fd63e474f8f5a1af099d1fe3c662c5796b165f92fcb531327552ca8ed057a8  NOTICE.txt
c2ad5b52cc62eea9e1ac9b37661d1ddc273864c48adc16622b66bddae4caae07  VERIFY.md
```
