# Release record: package repository 0.6.2 (supersedes 0.6.1) and ISO 0.1.0-rc4

**Date:** 2026-10-11 · **Location:** `aero:/data/chp-release/0.6.2/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.6.2`) · **Audience:** CyberHygiene Project development team only.

**Why 0.6.2 (ISO Plan 5b; both defects were found by measuring the installed iso5 hosts):**
- `chp-identity-client-0.2.2-1.chp` (P1): client enrolment now writes `/etc/idm-collect/collect.conf`. Before this, every
  appliance client reported `COLLECT_CONF_INVALID`, so the diagnostic collector could not check TLS or trust there.
- `idm-collect-0.1.0-10.chp` (P2): the label check (`restorecon -n`) also covers `/etc/ssh/chp_user_ca.pub`, the
  appliance's SSH CA key (row 33).
- Every other package is the same build as in 0.6.1. The sha256 values differ only because the repository was signed again.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). The only third-party signature kept is EPEL's.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `9f0f07e14a8b6875f9108188aaaf0d4719f0ef1d9af27c318cc42242ebda8c55` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `e1c0994c73339337a19adc997be2a6caae07442cd3240093e1f81e71890c5fad` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `386a6f915e94cc8643e16010472c9b96ebcce99dc09293c1cc1a7ed1737cf23c` |
| chp-site-0.6.1-1.chp.el9.noarch | 521276f43c908f8e | `99a0c183765fb388a61d6ee748278f9018e5a15cbab65d922dbf5c327360fe37` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-10.chp.el9.noarch | 521276f43c908f8e | `81c41287238e9dd450fbdc1604420020c1acd391e97f437b794c13418f885ee8` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `760891caeb991346f1a03929d607812d6431bc25a591602cea266f80e6e7cff5` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `776dca2589769d749e735a1275aea71d8527fb23dd2160cb08e1ccf91fa219e5` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `c76a82702ac15eb6089875a6bdc77032b1b9f0e17454854041794d2cff5ec037` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `85ce1f9d2ba92aebd422e8016ad27d5c454c07ad91f94b8f43c5a7392b958710` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `a428f7e8b40361d316df290311dbf9ec8fff564855f8bdac04656540efe44865` |

Repository metadata: `repomd.xml` `594acd6c78e2ebf3eab3556e1f7f790cf63a4fd2b05cfa550c5c240992f0412a`, `repomd.xml.asc` `ebe7fb1fcba609d8bff5ad634e5a8f9a73bf30ba1e53b6a1048664e36c6c3f95`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

## ISO 0.1.0-rc4 (supersedes rc3): the release candidate

`aero:/var/lib/libvirt/images/chp-iso/0.1.0-rc4/`. `check-iso.sh`: `ISO OK`. Installed from nothing in `lab/iso5` run 3:
141/141. The diagnostic baseline finds 0 findings on all three hosts. CUI scan: 102 pass, 0 fail on every host.

(`chp-site.pyz` on the ISO is built from the same chp-site 0.6.1 source as in rc3. Its sha256 differs because the zip
records build timestamps.)

```
ISO 0.1.0-rc4 built 2026-10-11T14:24:44Z on Aero
DVD Rocky-9.8-x86_64-dvd.iso sha256 d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f
repo 0.6.2 repomd.xml sha256 594acd6c78e2ebf3eab3556e1f7f790cf63a4fd2b05cfa550c5c240992f0412a
chp-site.pyz sha256 2b05c630051980fc02cfad0902feb93a59ac2ff0a49cb8b0216f0915a44def5d
server.ks sha256 6fe8ec29b8a8366cd879de3234a7724186f20f565c1c6f2ad648289839429c47
client.ks sha256 8096cba0ecae684811cb234aada8e48cd1af40cfe90da8e2280139b0080a6422
grub.cfg sha256 08756fb514cc743245129ed4a97573965a9ba693e54c6820b0a7378bed632309
isolinux.cfg sha256 c8814bb9a88b46e43a3d04440a4ff638a800a7c039c8b0153c9b8df82b0b509f
NOTICE.txt sha256 a6fd63e474f8f5a1af099d1fe3c662c5796b165f92fcb531327552ca8ed057a8
xorriso xorriso 1.5.4
53ab4f6ffe9dc130804d5270e9441ccca6cdf46be637ad725446e847e7626eec  cyberhygiene-lab-installer-el9.iso
```
