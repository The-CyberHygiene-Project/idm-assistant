# Release record: package repository 0.7.0 (lab candidate for core 0.2.0; not released)

**Date:** 2026-10-12 · **Location:** `aero:/data/chp-release/0.7.0/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.0`) ·
**Audience:** CyberHygiene Project development team only. Released 0.1.0 (repo 0.6.3) and the For Jeff share are unchanged.

**Why 0.7.0 (core 0.2.0 Plan A, spec `2026-10-12-core-0.2.0-aide-design.md`):**
- `chp-site-0.7.0-1.chp`: `aide-accept`, `aide-pin`, `aide-verify-pin`; `export-client` pins the AIDE baseline; `BASELINE_DELEGATES`.
- `chp-integrity-0.1.0-1.chp` (new): `aide.conf` (Rocky stock + SSG remediation + CHP additions), daily check + timer,
  first-baseline service, monitor checks 60/61/62.
- `aide-0.19.2-5.el9` (Rocky 9.8 DVD AppStream) carried with **Rocky's own signature** (new pinned key
  `21CB256AE16FC54C6E652949702D426D350D275D`, `trusted-keys.txt`), so a 0.1.0 host can install it from this repo.
- Every other package is the same build as in 0.6.3 (re-signed, so sha256 differs).

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). Third-party signatures kept: EPEL, Rocky.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `9e3dc951ca6ddec607452f69b0654750e1f348c0abcdd38fb29bb00f7f8efae0` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `21ff9e0dffc998c6a87281394cd764bd3211f5b03326da9dc34acd6bd4725649` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `e00ec7413409c53cbfd10b3ae78caff6a730ff56486cddf2877811343af7ec20` |
| chp-integrity-0.1.0-1.chp.el9.noarch | 521276f43c908f8e | `6e372ac8cb210e948e16e5e9c44dd215f85b8bb11be40c9b57e611038b74354f` |
| chp-site-0.7.0-1.chp.el9.noarch | 521276f43c908f8e | `21a2adc70f3c4cf17dec927b04e43403430719b64441594b1aab90cdf4428d20` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `3006aadcc5fcc02c53fcb04a27e1ecba1783fd3203d670555e55ea7f075c87e8` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `068dae5c9277bdec97d84511df1e7de04c14c9341517d8ee0f4e6457bc90cace` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `48faca4aeae90acd518c63cac0d288970520f958990daf89afac9c21ac85b5bf` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `c9cd8164d67349429e31fae4fadd8425594358cbbd9794fc6688a87f96585673` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `be2a49e560fa79e49bcbffa5ab7950a7e0abd2c266499bba03cb488bc7183033` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `2fc19522358471bcc0d3f7110fbcf0415336e630020fd9a3567ebb4fe28df34f` |

Repository metadata: `repomd.xml` `52fef0b4918c762be8a83a100ec34b16e0beebbd1295a0b21b2beaa74e28e5c3`, `repomd.xml.asc` `cc32cdee7430bc4890694e95f0dd195d61468fab4a8eafcf7b8c41563ee22092`.

`verify-repo.sh`: `REPO OK: 13 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`
