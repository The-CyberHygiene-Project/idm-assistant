# Release record: package repository 0.7.1 (lab candidate for core 0.2.0; not released)

**Date:** 2026-10-14 · **Location:** `aero:/data/chp-release/0.7.1/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.1`) ·
**Audience:** CyberHygiene Project development team only. Released 0.1.0 (repo 0.6.3) and the For Jeff share are unchanged.

**Why 0.7.1 (core 0.2.0 Plan A Task 13, spec `2026-10-12-core-0.2.0-aide-design.md` §4.4):**
- `chp-integrity-0.1.1-1.chp`: exclusions settled by measurement (`lab/aide/MEASUREMENT.md`): `!/etc/pki/kanidm`,
  `!/etc/step-ca/db`, `!/var/log/aide`; `/var/log`, `/var/log/journal`, `/var/log/audit` back to stock checks without a
  content hash.
- Every other package is the same build as in 0.7.0 (re-signed, so sha256 differs); `aide` keeps Rocky's signature.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). Third-party signatures kept: EPEL, Rocky.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `e14e682e227e9628112456577f2891db30a916c15f81e36ccc75a1dd883d9c1b` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `ee8e1503b9adcd8cc4428a0cafac5d8d915648a1ff30ebd4a308bb9e855476e6` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `70c5b62600d7873c23c3330a6e954ed2f896136e794b6adccb0225c07653590d` |
| chp-integrity-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `efe1d6f956062e4a7a8e92ee87a1b1f84e12efb75c995c75f603af5b31614126` |
| chp-site-0.7.0-1.chp.el9.noarch | 521276f43c908f8e | `fc24f62c398f55268ec7cb44fd8340c069a48470fd219405ad39b013d4f5d829` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `fce88d441f05b0664fc12674aed039f1ebe9f858c86190ada3e3329e8626cec2` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `2a76ede45547b42bc8c70815b081de70e0b5e4b0b2e66703da9453510e5d19de` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `501727d190bc300333fa8f2858905795e82d8425662407e9943453eea8c3490a` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `593068e9f12355776ac004858b55de80fa6daf221e8220af1228aee370393706` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `e823a0ca010cd2f549ca006d65ce69aab8b65152e8da73fe0426a46c13a2b479` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `322729a6184475ade557e1194bd3b72fe9b848d7e867b3b83a33f580acb17b43` |

Repository metadata: `repomd.xml` `495850a9ccef5fc542dbe112e581544b0525ff35c6f9be3e372b83bbd3dd6172`, `repomd.xml.asc` `af405d5127b26d34e00acb9c0cf7be11490af36666dd672e5549f151c89542c0`.

`verify-repo.sh`: `REPO OK: 13 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`
