# Release record: package repository 0.5.2 (supersedes 0.5.1)

**Date:** 2026-10-03 · **Location:** `aero:/data/chp-release/0.5.2/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.5.2`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.2 (account lockout, ISSO requirement row 44):**
- `idm-collect-0.1.0-3.chp`: new `faillock` report section for `--user` (the lockout limit and lock time from
  `/etc/security/faillock.conf`, and each failed login from `faillock`); unknown is `null`, never "not locked".
- Every other package is the same build as in 0.5.1. Their sha256 values differ from the 0.5.1 record only because
  the whole repository is signed afresh (signature bytes change; the payloads do not).

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `0ae4eb4cafedbddba0d648afc260302b5b2d62343a64ee85fd9931725b89192e` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `0da5be70b27ccf5068223c7a92808417ab81cac4940e147623de4c63b4187054` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `1f71fdcc14417f73f9e8670a4ad8fd2c4b3881c82da8dd5ba4a1a6d299f4dd58` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `5315554203a08941484646a98bc6ac0ccd117126f33e2fcc56f373babf6340ae` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `fea75e043bd1f06320286b3e0a350b09130854e6b8e0542e1494e434ee0335ea` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `a328dcb36cad4eac5381c1648495388e3308ae05989ba4b6d2e8ae47b1c9e965` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `be3fd7c123cdec477cb5b66ff9e88734f5be931282987b053b456eaee8d73d2c` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `c1a8ea4c579e637e1cb88236e8f1bd5c4f15b2e28bd8ff77980d81df9a656838` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `8265c12755e71afd32f0cc1e79117182a95a91dd0636dcf4dcce4e3d61bb8523` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `a043a354e1a47483a033a54656dca8ab2612db36a8d532b56a743c17b26c7159` |

Repository metadata: `repomd.xml` `8c656c4ed131d3922aaed71816c212c71b99c5b2d4f0333006271edadde92029`, detached signature `repomd.xml.asc` `d71d02a79b789b7f332ec9e867cf6db5ed8b6712d2a08802f3c79aae2a263aa7`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/plan8/` (lockout plan, Task 6).
