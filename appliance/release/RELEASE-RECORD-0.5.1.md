# Release record: package repository 0.5.1 (supersedes 0.5.0)

**Date:** 2026-10-01 · **Location:** `aero:/data/chp-release/0.5.1/repo` (a lab copy is served at
`http://192.168.100.1:8080/chp/0.5.1/`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.1 (ISO Plan 4b, after the final review):**
- `chp-identity-client-0.2.1-1.chp`:
  - kanidm-unixd reports **short names** (`uid_attr_map`/`gid_attr_map = "name"`). Under 0.5.0, `sudo`'s PAM user was the SPN, so the second factor looked for the wrong token file and every Kanidm admin's `sudo` failed.
  - the `53-ga` monitor alerts if `allow_local_account_override` is set
- `chp-site-0.5.1-1.chp`: `onboard` refuses a person or group named like a local account or group (final review I1).
- Everything else is unchanged from 0.5.0. 0.5.0 is not to be used.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `a767ee4cf7eeff3bdf841dbd62c140ecd8362cb09731f7adf7af54c9af6bfe01` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `a00a1c522b189569e6d6264525b288856233fdf23596bf2c681758c091199bd9` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `0160fc89198d78d5f0abf069d6402c3a566cb24c9c377efbacb7fdafd23dab20` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `e01bfbcba2627f082aae882caa618affa08e445a8c52a103f42ecb4e634ad25b` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-2.chp.el9.noarch | 521276f43c908f8e | `ae891de20573e4832d8b85e53ec82a7d2649044a4f291a475d11e219ec2a4126` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `606ed421978425c54311a89cefcbfbe575e3f618fe7270d77e51184415338990` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `c44cf461b23739ed290e2fe3d087064516d7806d0edb7b0befaf4ed3f347376d` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `4c2559e8b6c3775150c88008711fee904f85ca74aba806f2dea2bd8cf8d7eaa8` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `ef1e4e50be88dc7790e476f984c93e45967cbaf2db28c2d45c544dd12f4a5ade` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `36bfd4f448227de02eb1066106df64b974469a1cfb5252ca0f9f0a274561f985` |

Repository metadata: `repomd.xml` `ef605b963b360f81f3a303d88b00599bfdc047d349448ad7f42cd14b8eb822b9`, detached signature `repomd.xml.asc` `699d167ca9c6c0420c95a862a49d8e5fc83b5bedf8b25be84dca521a45a616fc`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/iso4/PROOF-RECORD.md` (Plan 4b, run 2).
