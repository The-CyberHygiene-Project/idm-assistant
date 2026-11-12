# Release record: ISO 0.6.0 (= rc2) with signed repo 0.11.0

**Date:** 2026-11-12 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.6.0/` and `…/site-stick-kit-0.6.0/`
(earlier folders untouched; the share's `README.md` gains rows for both) · **Audience:** CyberHygiene Project
development team. Not an official Rocky Linux product.

**What's new** (spec `docs/superpowers/specs/2026-11-09-iso-0.6.0-design.md`, plan
`docs/superpowers/plans/2026-11-09-iso-0.6.0-plan.md`; closes requirements row 50):
- **Disk layout sized by disk and role.** Servers of 900 GB or more: fixed system volumes (`/` 90, `/var` 100,
  `/var/log` 50, `/var/log/audit` 30, `/var/tmp` 15, `/tmp` 15, swap 29 GiB) and the rest split `/home` 15.6 %,
  `/data` 22.9 %, `/backup` 39.2 %, ~22 % left unallocated (a real 2 TB SSD: `/home` 238, `/data` 350, `/backup`
  600, 342 GiB free). Workstations of 240 GB or more: their own layout (`/` 40, `/var/log` 20, `/home` 25 % of the
  rest, the rest unallocated; no `/data` or `/backup`). Smaller disks keep the previous layout byte for byte. Servers
  under 1.9 TB get a `DISK_NOTE` line in their escrow file and the install log. `/data` `nodev,nosuid`; `/backup`
  `nodev,nosuid,noexec`. On sized servers Wazuh data lives on `/data`.
- **Monitor check 76 (disk space)** on every host: alert at 85 % on any local XFS volume, once per crossing, again
  every 24 h while above, with the volume group's free space.
- **Daily-review sign-off fixes:** a terminal is required to sign; a concurrent second signer is refused inside the
  ledger lock; `--date` must be `YYYY-MM-DD`; `--notes` at most 1,000 characters, no control characters; the nightly
  build uses the site `TIMEZONE`.
- **Short-lived certificates** (lifetime under 90 days) are ATTENTION only below 30 % of their life (the 24 h Kanidm
  certificate renews at 8 h left and is no longer flagged while healthy; found on the rc1 quiet day).
- `chp-yara.json` is rotated. Two runbooks ship in the kit: grow a volume; move `/backup` to a second drive.
- Existing installs are not repartitioned: the new layout reaches a site only by reinstalling.

## Packages (repo 0.11.0, 28, all signed by pinned keys)

Changed from 0.10.0: `chp-site-0.13.0-2`, `chp-base-0.1.0-4` (check 76), `chp-security-0.4.1-1` (logrotate). The
repo was signed twice; only the second signing is published. The first (chp-site 0.13.0-1, the rc1 bytes) is kept,
never published, at `aero:/data/chp-release/0.11.0/repo-superseded-chp-site-0.13.0-1/`.

## Bytes

| File | sha256 |
|---|---|
| `0.6.0/cyberhygiene-lab-installer-el9.iso` (rc2) | `0cb27c1497acdd245af74508ab16a8d9f75a57dd10089372ac2ef9a68067cac0` |
| `0.6.0/chp-repo-0.11.0.tar.gz` | `0b1a4eda02e47a764e8f04d1fa2acde4f96b570f0364fe7e502cef219d12baa6` |
| `0.6.0/VERIFY.md` | `73034af7b6992fe0f43478d9ff550876f50ab1fcd6bfdd106561977bb3bab5b2` |
| `0.6.0/RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `0.6.0/NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |

**Kit** (`site-stick-kit-0.6.0/`): `SITE-STICK.md` `3d25ac975e1ea3fd…` · `site.conf.template` `527963d7824b9939…` ·
`hosts.template` `c20a3d8702ca417e…` · `profile.ini.template` `3a00f51ea489cf78…` · `chp-site.pyz` `51c1bce154c6fefa…`
(reports `chp-site 0.13.0`) · `runbooks/grow-a-volume.md` `a00d895f68f8b9b6…` ·
`runbooks/move-backup-to-a-second-drive.md` `a3f77b96ffef8470…` (new, additive).

**Signatures:** both `SHA256SUMS.asc` made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey; signature
counter 834 → 836) and verified → Good signature.

## Evidence (`lab/security/PROOF-RECORD-ISO-0.6.0.md`, `lab/security/SPIKE-DISK.md`)

- Spike: a 2 TB sparse install takes ~10.5 GB on aero; a 50 GB size guard was active on every large lab disk and
  never tripped.
- rc1: CUI scan 108/2 on every host (no deviation from the new volumes), regression 33/33, row 36 3/3, online
  `lvextend`, check 76 catch, review proofs, the backup-drive runbook followed word for word (TPM unlock of both
  disks, 600 GiB returned), and a ~36 h quiet day (two real review builds, every hook line explained, no false
  check-76 alert).
- rc2 (chp-site 0.13.0-2): fresh reinstall of all hosts, CUI scan 108/2, regression 33/33, row 36 3/3, review
  proofs, the Kanidm certificate row OK; plus a 1 TB server install proving the `DISK_NOTE` path.
- Final whole-branch review: 0 Critical; 4 Important fixed (share README rows, the under-1.9 TB install, the
  runbook's `luksFormat` confirmation, the guide's note wording) plus two must-fix minors.

## Known limits

Proved on VMs only. Sign-off proofs used a scripted terminal, not a person. The `%pre` disk note goes to
`/dev/console` but was observed only in the install log and the escrow file. A dead backup drive no longer stops
the server at boot (`nofail`); `/backup` is made immutable while unmounted so writes fail loudly.
