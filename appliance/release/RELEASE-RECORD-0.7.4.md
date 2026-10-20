# Release record: package repository 0.7.4 (candidate for ISO 0.2.0; not released)

**Date:** 2026-10-20 · **Location:** `aero:/data/chp-release/0.7.4/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.4`) ·
**Audience:** CyberHygiene Project development team only. Released 0.1.0 (repo 0.6.3) and the For Jeff share are unchanged.

**Why 0.7.4 (core 0.2.0 Plan B Task 5, gate 1 failed on rc1):**
- `chp-integrity-0.1.4-1.chp`: no AIDE alerts from reboots, logins or root shells (owner decisions 2026-10-20). The
  rule changes are `/boot/efi NORMAL-i` (vfat inode numbers), `/etc/fapolicyd CHPCONTENT-c` (fapolicyd resets
  ownership at every start), and `PERMS-sha512` for `random-seed`, `lastlog` and `/root/.bash_history`.
- Every other package is the same build as in 0.7.3 (re-signed, so sha256 differs); `aide` keeps Rocky's signature.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). Third-party signatures kept: EPEL, Rocky.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `c1243f98de8b721ef042431833b497b02aa8665b77e65539cf96f6f7018f48d2` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `0c04eda603bf20858fe507de0b56160e0a1b3bc98663d5316e410966b3f47b41` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `86204d64beddd86d396cf8aa90ccb39147199a9e7a6f9c4de770888e7c805a18` |
| chp-integrity-0.1.4-1.chp.el9.noarch | 521276f43c908f8e | `4251fbbb0ce3638ac402564987c2b2c80b5438ef502392116fffa4f6dcf655b0` |
| chp-site-0.7.1-1.chp.el9.noarch | 521276f43c908f8e | `a7a1b6a995910a093b55ab60d9c4448a90935a3725b2001ae1148a4891cfb577` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `170c7a301703ab51464844b82c209c6051575a93da0528e2fa0a8e551ca94f29` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e537f63d7e037b253f13262fe38ac2cd48f6d6c3cb09be1ee6d3720368f443b7` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `fe41b6d16c3ca63cda680580414725a01bb9d2daf36a8f5d5c53f2f40e02bdf2` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `95afe5e98d870e190ac1d5be0c3f3c9c91e6dad113f6bca6941ac38cdbf25bdf` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `b9b8ff3a94d5eb521be1d8097453ce62c1b0c449c7fe7b200981e76f73117521` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `8201a31f828009ab0a5fb0bca07bd0602550cbe5bddbdfe288bd640be04d77e1` |

Repository metadata: `repomd.xml` `9885c193dd40ea07db3944dc6f1b7f9cbcaf21a72710e2ab51dfd7e2e67bf3fb`, `repomd.xml.asc` `b7dd94eba990e5b29f01a6af0c905408af0ce651e299964ad91f958accf4d2ec`.

`verify-repo.sh`: `REPO OK: 13 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

**ISO built from this repo:** `0.2.0-rc2`, `check-iso.sh` → `ISO OK`, sha256
`1332d9114c9cd7fdfc7459ab68a529171aaa39f8beea666b097e381499f4d24e`. aero suspended (S3) for 3 minutes during the build;
the build resumed and completed, and `check-iso.sh` was re-run on the result.
