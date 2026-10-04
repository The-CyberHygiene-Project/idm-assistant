# Release record: package repository 0.5.6 (supersedes 0.5.5)

**Date:** 2026-10-03 · **Location:** `aero:/data/chp-release/0.5.6/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.5.6`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.6 (fapolicyd final review, ISSO requirement row 46):**
- `idm-collect-0.1.0-7.chp`: the `fapolicyd` section also reports the packages fapolicyd has never loaded (with their
  signers) and trust-file entries not yet loaded, so the trust refresh can refuse when it would trust anything not
  carrying a pinned key (0.1.0-6 let a refresh trust unvetted packages: `fapolicyd-cli --update` reloads the whole
  package database). Only real denials count (FANOTIFY `resp=2`, `success=no`).
- **0.5.5 is not to be used.** Every other package is the same build as in 0.5.5; sha256 values differ only because
  the repository is signed afresh.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `a60b3788c3520d3a13444ba8123a7c791c240302d9783cd90af5c81a0f8ac7c4` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `b1bfc7bdb47d995e1304f4d36b9e7ac671dd063e35e9d88626faad74705de350` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `89c90f235c23ee6000981791c87b9bea45cc1a3bf68306f91482f5b2d1952a5a` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `988a97df3047b58209d77271926bfca23ab96d94230486fa703cb63dac03f69f` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-7.chp.el9.noarch | 521276f43c908f8e | `f2c9897558ccd89824e94f884961d025b50d299b57738771910a95e3649903a8` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `7fea5d404f9624dec5d2d6c9b68321a768648f9bd495d63fa5abc1ee588d6edd` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `8843cf6e5e69644dae525c10fe1f97c0eb8a1a39a10288c11141c7355fbf799b` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `b8136c16ff8c04fe31dfbe2a54f9e6421025378fc44db44523d3ca6735336a94` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `178ffdadf2a7a14b50c657ca01edd6cc6a5e4e348a029fad64e0cab3f6b52aff` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `1d72ef03473346df24a952a2ec4d138de70d7b329ea058563d76dc5e4b8b588e` |

Repository metadata: `repomd.xml` `5e13ca31cdb4c17f1342f031fcdc6cadfd63e9feba3f6503e166e22af32a248d`, detached signature `repomd.xml.asc` `e3793a3e27c9cec21fa6334d8abab6581e2c91384535dc0e3e95aa8c00a30c6f`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/plan8/` (fapolicyd plan, final review).
