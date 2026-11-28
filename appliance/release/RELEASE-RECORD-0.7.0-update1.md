# Release record: 0.7.0-update1 with signed repo 0.15.0

**Date:** 2026-11-28 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.7.0-update1/` and
`…/site-stick-kit-0.7.0-update1/` (earlier folders untouched; the share's `README.md` gains rows for both) ·
**Audience:** CyberHygiene Project development team. Not an official Rocky Linux product.

Package update for 0.7.0 sites. No new ISO.

## What changed

- `chp-templates` 1.4.0-4, built from the signed templates 1.4.0 release (`For Jeff/chp-templates/1.4.0/`, tag
  `templates-1.4.0` = chp-templates `ab4392b`, content 1.2.9).
- POA&M seed rows T-08 to T-16: NIST numbers confirmed by the owner 2026-11-27; the pending notice removed.
- `chp-site` 0.14.0-14: the ISSO override alert always names the person and the document (P3-D16); the nightly
  documents check no longer raises a false alert about `config.php` after a backup.

Repo 0.15.0: 72 packages, all signed by pinned keys. Changed from 0.14.1: those two packages.

## Bytes

| File | sha256 |
|---|---|
| `0.7.0-update1/chp-repo-0.15.0.tar.gz` | `cf053ef24b01eaf5237c6d4d4ee3236d6d19e4da1b1ffb57ea1f12556e256482` |
| `0.7.0-update1/RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `0.7.0-update1/NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |
| `0.7.0-update1/UPDATE.md` | `2d84e7e487023f39287b580dd7637e3cc2d5c10743802099230b8f8e633e1310` |
| `site-stick-kit-0.7.0-update1/SITE-STICK.md` | `17a6d90f43ab4b2819b24dd79dc8834fc00664e197cec16755211bb89d79feb9` |
| `site-stick-kit-0.7.0-update1/site.conf.template` | `2b809d459d7b2abf78560d537778645a6430610636515d079752cbdd7513c964` |
| `site-stick-kit-0.7.0-update1/hosts.template` | `c20a3d8702ca417e306ab9651c1694f86921893342d3ef56e08348c2e7bf98f9` |
| `site-stick-kit-0.7.0-update1/profile.ini.template` | `3a00f51ea489cf78f9be2f108e710cdb7e62ef6fa85058792c05ac5c4c9281a1` |
| `site-stick-kit-0.7.0-update1/poam-seeds-0.7.0.md` | `e7fe9490687479d59a5d811d83e729705ace7542712b992f830dedf4ec3b83b8` |
| `site-stick-kit-0.7.0-update1/chp-site.pyz` | `8087839f41e8ab5e1fc3248ac196b19cc7907b2c2c285494fd704ea4ec0b9f23` |
| `site-stick-kit-0.7.0-update1/runbooks/grow-a-volume.md` | `a00d895f68f8b9b65ba764c4a2a15f4e67a5bf506b77476a308080c84db4c833` |
| `site-stick-kit-0.7.0-update1/runbooks/move-backup-to-a-second-drive.md` | `a3f77b96ffef8470e3f53d6661c1d6ce86293da91acabbb592b91d0052fa8208` |

Both `SHA256SUMS.asc`: Good signature, release key `2DE0D71BF37D8F5E4201A590521276F43C908F8E`, re-verified after
publishing together with every file checksum. Card signature counter 989 → 1011.

## Evidence

- `lab/security/PROOF-RECORD-0.7.0-update1.md` (before signing, on VMs).
- After publishing: srv and cli2 rolled back to the 0.7.0 packages, then upgraded from the published tarball by the
  update note's step 2: `dnf upgrade` completed on both (srv `chp-site`; cli2 `chp-site` and `chp-templates`).
- Not run: a fresh install, the regression gate.

## Deferred

The server's OpenSCAP tailoring in the kickstart (next ISO); the Rev 3 crosswalk; P3-D6.
