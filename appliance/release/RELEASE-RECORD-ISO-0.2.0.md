# Release record: CyberHygiene Project Lab Installer ISO 0.2.0

**Date:** 2026-10-24 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.2.0/` and `…/site-stick-kit-0.2.0/`
(beside `0.1.0/` and `site-stick-kit/`, which were verified byte-identical before and after) · **Audience:** CyberHygiene
Project development team. Not an official Rocky Linux product.

**What's new:** AIDE file integrity in the core (spec `docs/superpowers/specs/2026-10-12-core-0.2.0-aide-design.md`,
requirement row 47):
- a first-boot baseline, with the site stick's hash pinned before it;
- a daily check and monitor alerts;
- baselines changed only by an audited `aide-accept` (the ISSO or `BASELINE_DELEGATES`);
- each baseline's hash pinned to the site stick.

0.1.0 sites can upgrade in place: see `0.2.0/UPGRADE-FROM-0.1.0.md`.

## Bytes

| File | sha256 |
|---|---|
| `cyberhygiene-lab-installer-el9.iso` (= **0.2.0-rc2**, the tested bytes) | `1332d9114c9cd7fdfc7459ab68a529171aaa39f8beea666b097e381499f4d24e` |
| `chp-repo-0.7.4.tar.gz` | `f2e852b70ecdf035f4e7d86c056d8f2d72c97a31be5d3e3eb7c9892f3fca0ecc` |
| `RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `NOTICE.txt` | `a6fd63e474f8f5a1af099d1fe3c662c5796b165f92fcb531327552ca8ed057a8` |
| `VERIFY.md` | `73537010dbdd9eae50efa83925aff3b20d8970849bd2bf4cc751881b191a7a8a` |
| `UPGRADE-FROM-0.1.0.md` | `91428c42b5b7d43e2a8d51fa146a0b1650dba899b8e4e0523e74a8badb502742` |

**Kit** (`site-stick-kit-0.2.0/`): `SITE-STICK.md` `d55c2f72429c218f…` · `site.conf.template` `dd7bbf6482ebc0dc…` · `hosts.template` `c20a3d8702ca417e…` · `chp-site.pyz` `129d0052037351c2…` · `chp-site.pyz` reports `chp-site 0.7.1`.

**Signatures:** both `SHA256SUMS.asc` were made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey) and
verified with `gpg --verify` → Good signature. The packages are repo 0.7.4: `RELEASE-RECORD-0.7.4.md`.

## Gates (evidence in `lab/iso5/PROOF-RECORD.md`)

1. **Install from nothing + a quiet day:** rc2, 105/0 install checks, then a clean `quietcheck` on all three hosts.
   The quiet window included a reboot, a root shell, the evening certificate renewal and log rotation.
2. **Regression:** 33/33 (`lab/iso5/regression-2026-10-24.md`), plus row 36 ×3.
3. **CUI scan:** 108 pass and 2 fail on every host; the 2 failures are AIDE deviations accepted in spec §8
   (`lab/iso5/DEVIATIONS.md`).

rc1 failed gate 1 (AIDE alerts after reboots and root shells). That was fixed in `chp-integrity` 0.1.4 and rc2.

## Known limits

- **Proved on VMs only:** a real USB site stick and real hardware are unproven.
- **A live auditd rotation inside a quiet window was not observed.** The exclusion is proved with `aide --path-check`.
- **One-time alert:** if the site stick is removed before first boot finishes, the first later stick use raises one
  AIDE alert, which is accepted.
- **The upgrade path** (0.1.0 → 0.2.0) was proved in Plan A on repo 0.7.2. With 0.7.4 it is the same procedure,
  using the newer `chp-integrity`.
