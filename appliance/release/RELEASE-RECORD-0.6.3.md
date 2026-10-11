# Release record: package repository 0.6.3 (supersedes 0.6.2) and ISO 0.1.0-rc5

**Date:** 2026-10-11 · **Location:** `aero:/data/chp-release/0.6.3/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.6.3`) · **Audience:** CyberHygiene Project development team only.

**Why 0.6.3 (ISO Plan 5b; ISSO decision 2026-10-11, option a):**
- `idm-collect-0.1.0-11.chp` adds `user_nss.kanidm_groups`: the user's groups that resolve through Kanidm.
  - With short names (row 9) a group name alone cannot tell a Kanidm group from a local one.
  - So the engine's stale-cache rule (`UNIXD_CACHE_STALE`, row 28) was blind on the appliance. Scenario l3 failed
    diagnosis in the first shakedown.
  - The engine now compares short names, using this field.
- Every other package is the same build as in 0.6.2. The sha256 values differ only because the repository was signed again.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). The only third-party signature kept is EPEL's.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `a8d5dc0faa6fa0e2312b99f62616ca79fbb0ede56761c0620f9d7b5f790c53d0` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `7ba097f85e3e91f1267516cb947fced46c92003ef8505a763000d34690145629` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `9a76dc64808f3f909316fb251ae896cda46ea0757f3e5b066aa32beff5fdce81` |
| chp-site-0.6.1-1.chp.el9.noarch | 521276f43c908f8e | `c2419564ab88df570b45e94c578189af00b1bee0f38fccf67f51639244c66c55` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `feb4d7ed34a146a798623acceeac1bc6e879c0197f3057a79ffb59f7e3fba6ff` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `a02d7452cac468dd6998d19e1d92c27b75103c85179f7deca2d49a3613ab8309` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e069f3c95eaf93ee4f9b9c8b812f5768ab3a0aa9ae32b3cd25d0c1be7e88d68e` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `dd882855e4de1c827f629d38f476b82f2066fbb8b59eb181029184a4b3505048` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `0cd2fe3f14d4c0650fb50b8b333960ece9f82bdfcfd187faf9556fcbe2cad831` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `7e44fb50f08a1c0f58f7b0482e48a112cec7bcec800f843242c1bfb8d5265069` |

Repository metadata: `repomd.xml` `cc2e41ea8e9d532b6427e10f652c840e1c1e009f51cbca557e0981373652a8fd`, `repomd.xml.asc` `456a843c52cc593c50d51cdbd916c6c5d93af4450129b4b739f488d51307ffce`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

## ISO 0.1.0-rc5 (supersedes rc4): the release candidate that passed all three gates

`aero:/var/lib/libvirt/images/chp-iso/0.1.0-rc5/`. `check-iso.sh`: `ISO OK`.

| Gate | Result | Evidence |
|---|---|---|
| 1, install from nothing | 141/141 | `lab/iso5` run 4 |
| 2, regression | 33/33 + row 36 ×3 | `lab/iso5/regression-2026-10-11.md` |
| 3, CUI scan | 102 pass, 0 fail on every host | `lab/iso5/DEVIATIONS.md` |

```
ISO 0.1.0-rc5 built 2026-10-11T16:40:06Z on Aero
DVD Rocky-9.8-x86_64-dvd.iso sha256 d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f
repo 0.6.3 repomd.xml sha256 cc2e41ea8e9d532b6427e10f652c840e1c1e009f51cbca557e0981373652a8fd
chp-site.pyz sha256 e15e09e39952f63274f87495d129ddf7ba94360ad4b04cad054a065bd41af21a
server.ks sha256 6fe8ec29b8a8366cd879de3234a7724186f20f565c1c6f2ad648289839429c47
client.ks sha256 8096cba0ecae684811cb234aada8e48cd1af40cfe90da8e2280139b0080a6422
grub.cfg sha256 08756fb514cc743245129ed4a97573965a9ba693e54c6820b0a7378bed632309
isolinux.cfg sha256 c8814bb9a88b46e43a3d04440a4ff638a800a7c039c8b0153c9b8df82b0b509f
NOTICE.txt sha256 a6fd63e474f8f5a1af099d1fe3c662c5796b165f92fcb531327552ca8ed057a8
xorriso xorriso 1.5.4
efcba98a4268ec35ccef0b66b78122b3c78246424f76186cfa45a1ba80ff81b2  cyberhygiene-lab-installer-el9.iso
```
