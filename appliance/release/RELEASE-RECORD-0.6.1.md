# Release record: package repository 0.6.1 (supersedes 0.6.0) and ISO 0.1.0-rc3

**Date:** 2026-10-10 · **Location:** `aero:/data/chp-release/0.6.1/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.6.1`) · **Audience:** CyberHygiene Project development team only.

**Why 0.6.1 (ISO Plan 5a gate 3; ISSO decisions 2026-10-10, `lab/iso5/DEVIATIONS.md`):**
- `chp-site-0.6.1-1.chp`: `pre` makes a random per-host boot-loader password and escrows it on the site stick as
  `GRUB_PASSWORD`. The kickstart receives only its PBKDF2-SHA512 hash, through `/tmp/chp/boot.ks` (CUI rule `grub2_password`).
- The kickstart (on the ISO, not a package) also imports Rocky's release key (CUI rule `ensure_redhat_gpgkey_installed`).
- Every other package is the same build as in 0.6.0. The sha256 values differ only because the repository was signed again.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). The only third-party signature kept is EPEL's.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `8a8355ca1b85235ae4ee265af06c30f05c3e88ea95c3bcf8a7416130d6fca3f4` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `199facec29421254eca7319b9d35ad30cbde18e4baff99205761938c053ab6d8` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `b464aa72685fb601191aa479478e89344fc18eb893139dd51d8c84fce7fd47fc` |
| chp-site-0.6.1-1.chp.el9.noarch | 521276f43c908f8e | `0904228fcabca2dcba9da2be87d0c748012e865d801ea88f4fc80d8bf7aa90bb` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-9.chp.el9.noarch | 521276f43c908f8e | `7c4c2041584dd1ae96a509285244b1ad45b744158257cdb8257ba694ed223fc1` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `488a4e207cdda2a7c0cfeed7e276700464c5bab844b0aec5ac6bd75e0c6ee90b` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `68796a7a949282145474d572cf32dd7b1c135e69d2e3279ee3074b9397b9c57b` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `f5ad541450d151ffb118de431a9a0ba0f7bc81904ccf4080c37dd9478322322b` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `6b78e497ed6edfd5276876c79c0e60ad5393bd881d4f44162d09ea00583526ae` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `b458f094f91b10e14ee3433238aa20cd2da614fb5de31b764dc9a4ae8d04f9ef` |

Repository metadata: `repomd.xml` `faae2d2735d5c817136bedc988d972ab81f37b67effd1e56553f274785b36c02`, `repomd.xml.asc` `c2d34522dc29da2f6c8e8762f9d39748fe8045becca6721fc6fe20e66f5cf729`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

## ISO 0.1.0-rc3 (supersedes rc2)

`aero:/var/lib/libvirt/images/chp-iso/0.1.0-rc3/`. Not released: the release follows Plan 5b's gate 2.
`check-iso.sh`: `ISO OK`. Installed from nothing in `lab/iso5` run 2: 138/138. CUI scan: 102 pass, 0 fail on every host.

```
ISO 0.1.0-rc3 built 2026-10-11T00:02:38Z on Aero
DVD Rocky-9.8-x86_64-dvd.iso sha256 d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f
repo 0.6.1 repomd.xml sha256 faae2d2735d5c817136bedc988d972ab81f37b67effd1e56553f274785b36c02
chp-site.pyz sha256 ab1ab67a0e0b9835e6bf769303f97dcf40a1ac9ff5ffab5191b40e50d17ce306
server.ks sha256 6fe8ec29b8a8366cd879de3234a7724186f20f565c1c6f2ad648289839429c47
client.ks sha256 8096cba0ecae684811cb234aada8e48cd1af40cfe90da8e2280139b0080a6422
grub.cfg sha256 08756fb514cc743245129ed4a97573965a9ba693e54c6820b0a7378bed632309
isolinux.cfg sha256 c8814bb9a88b46e43a3d04440a4ff638a800a7c039c8b0153c9b8df82b0b509f
NOTICE.txt sha256 a6fd63e474f8f5a1af099d1fe3c662c5796b165f92fcb531327552ca8ed057a8
xorriso xorriso 1.5.4
144ec3459b8da5048ac15ef36bc6c21f145d364650db87a3d807774bae822c6b  cyberhygiene-lab-installer-el9.iso
```
