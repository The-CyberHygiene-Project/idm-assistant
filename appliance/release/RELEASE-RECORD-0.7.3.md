# Release record: package repository 0.7.3 (candidate for ISO 0.2.0; not released)

**Date:** 2026-10-18 · **Location:** `aero:/data/chp-release/0.7.3/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.3`) ·
**Audience:** CyberHygiene Project development team only. Released 0.1.0 (repo 0.6.3) and the For Jeff share are unchanged.

**Why 0.7.3 (core 0.2.0 Plan B Task 4):**
- `chp-integrity-0.1.3-1.chp`: `!/root/chp-escrow-pending` (owner decision 2026-10-18). `export-client` empties that
  folder after the first-boot baseline, and the exclusion also keeps hashes of the recovery secrets out of the AIDE
  database. It is covered by `40-escrow-pending`.
- This is the first repo for ISO 0.2.0. Its kickstarts install `chp-integrity` and enable its timer and first-boot
  baseline.
- Every other package is the same build as in 0.7.2 (re-signed, so sha256 differs); `aide` keeps Rocky's signature.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). Third-party signatures kept: EPEL, Rocky.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `c72c257535d1df7b9725cda045a807e1df59c92f2ac25615614a2e5612958283` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `081cabf65f9ad428fbecb4566eb3d5a1a08d6b4b31caae586a10c4ffd639437a` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `ff3414165820998b70926dcd3f07eebad1d8120f0ec5fe08ab13a6255a9ef1f0` |
| chp-integrity-0.1.3-1.chp.el9.noarch | 521276f43c908f8e | `1e04552376ff8c6f07256b183f8c16bbff05220b0090c79189f553e453316c5f` |
| chp-site-0.7.1-1.chp.el9.noarch | 521276f43c908f8e | `3cb2df22bd93dc27d49bc117db02ef2c349fb4f5b01f7daee74c71f52b83736b` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `87b5214948a31597576487538138d66112ec5369b59ef285b2e698d8f11a8ec9` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `025d621becce37088d022d1ab1d1ffc235024d8892f05a6d5f3731da1f8c4130` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `f18f7fb6576e9f455fcc553fb7b209479f6fb666d9be38b47aecfb0071e238a2` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e7d72c45540a41b0f2d471cc06b241dcab1fda3aa26dd99b51f059db5e4a173e` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `6858e37c69ca448e183ecbd07812493927488a640c9c12bb81f12efcaf00a737` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `6163826089b2b58db307561a80cd56fef54fbfd15cdf49702b8c3f2a9c85c531` |

Repository metadata: `repomd.xml` `9ca10e4ab8114152d5fee2f0b28ea53cd0a3779213b475d914f35b22eec36089`, `repomd.xml.asc` `8b47e194885787734a7b9a032d93e9aab96b53eb2d8204850229b8bff5126da4`.

`verify-repo.sh`: `REPO OK: 13 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

**ISO built from this repo:** `0.2.0-rc1` (`aero:/var/lib/libvirt/images/chp-iso/0.2.0-rc1/`), `check-iso.sh` → `ISO OK`, sha256 `fafdceb399d29917cc9903253143a7e9a5bf69f576da5d1602e1a4ad7068e840`.
