# Release record: package repository 0.6.0 (supersedes 0.5.8) and ISO 0.1.0-rc2

**Date:** 2026-10-10 · **Location:** `aero:/data/chp-release/0.6.0/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.6.0`) · **Audience:** CyberHygiene Project development team only.

**Why 0.6.0 (ISO Plan 5a):**
- `chp-site-0.6.0-1.chp`: new `verify-repo` command. The kickstart `%pre` uses it to check the install repo's
  `repomd.xml.asc` against the pinned project key before the site gate and before any disk is touched (row 37).
  The project's public key is bundled in the zipapp.
- Every other package is the same build as in 0.5.8. The sha256 values differ only because the repository was signed again.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `ad2f0a9d234591c68d16b292b9a4151e562195f9d1cadadf4d0d7d09fa3be279` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `14a2b7419458c3638837e1d4debd63352ffab751bb8843953d2259cf523917d7` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `08dc217225903f6882484fd17954a1821f02b8dd50fbac379c8cbbee6ac8761c` |
| chp-site-0.6.0-1.chp.el9.noarch | 521276f43c908f8e | `2de7534b61b3830e9ab6e3b8b67083134a5c1a1f907448a016248c3ad7c30ea0` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-9.chp.el9.noarch | 521276f43c908f8e | `a2a0ac75d0c61fed07641a399c64ccadc6be2752c2266ff9ca03403c6d93c098` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `53aeea2c830a2949f6d37d5ea8666e88631ba6e8a8907b41300f63c53fbbd65d` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `5a3d31dbd540b85539c099dda193f0d7c463ea0f8f5bbd1971dc7d66c2ff6848` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `5dda0468996d93c9286c3550f4393668be630ced349dcf89b8e15ccf3e247ce5` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `08639cf5e7642eb68f5ab17e3f6e4f3b29c7362821a0d6bd06217b06ea69142a` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `1d3f832cfd47870aeda2ea1edbc0e673654bb2ce7ccd906974920931bc189fb0` |

Repository metadata: `repomd.xml` `b9f79745b8d159c050271d8f6ce2cd33e453122e1ed42549ce11cd39aaa8b0aa`, detached signature `repomd.xml.asc` `b0b82dc24bec1ffc8db183ecbf5532acd496f5f4bbd7f64bfb3e4c629d6208d5`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

The first signing attempt was cancelled at the PIN prompt. sign-repo.sh is all-or-nothing, so nothing was written. The second attempt signed.

## ISO 0.1.0-rc2

`aero:/var/lib/libvirt/images/chp-iso/0.1.0-rc2/` (not released; the release follows Plan 5b's gates).

**ISO 0.1.0-rc1 is discarded.** It was built with `xorriso -boot_image any replay`. replay re-used the DVD's *original*
EFI image as an appended partition, so rc1 would have booted Rocky's menu and searched for a volume label that no longer
exists. `check-iso.sh` reported `BAD boot records`. rc2 is built from the DVD's tree with the DVD's own mkisofs boot
options.

```
ISO 0.1.0-rc2 built 2026-10-10T22:17:59Z on Aero
DVD Rocky-9.8-x86_64-dvd.iso sha256 d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f
repo 0.6.0 repomd.xml sha256 b9f79745b8d159c050271d8f6ce2cd33e453122e1ed42549ce11cd39aaa8b0aa
chp-site.pyz sha256 6db7ffb17072d4d9360450bae4edf7cf4c5d67cdfb0278abd2cbfac3301e6e14
server.ks sha256 9d1ade99d7c266ad2bca109e8390ad383fd0791e474196f3cf9a4b269b27060c
client.ks sha256 455e0a615061dbb319d4ec5271d8ce2e46edb21ef723a1ed3e4d409a3025b655
grub.cfg sha256 08756fb514cc743245129ed4a97573965a9ba693e54c6820b0a7378bed632309
isolinux.cfg sha256 c8814bb9a88b46e43a3d04440a4ff638a800a7c039c8b0153c9b8df82b0b509f
NOTICE.txt sha256 a6fd63e474f8f5a1af099d1fe3c662c5796b165f92fcb531327552ca8ed057a8
xorriso xorriso 1.5.4
b2a24baacaadb29554da560d157fecac7ef68ffb428f986aeb286fa87c78725e  cyberhygiene-lab-installer-el9.iso
```

`check-iso.sh` on rc2: every check OK. Volume ID `CHP-LAB-EL9`. The El Torito EFI entry and the GPT partition both point
to `/images/efiboot.img`. BOOTX64.EFI, grubx64.efi, mmx64.efi, vmlinuz and initrd.img are byte-identical to the DVD's,
both on the ISO and inside efiboot.img. efiboot.img's grub.cfg is the same file as the ISO's. The repo on the ISO passes
`verify-repo.sh` and `chp-site verify-repo`. Result: `ISO OK`.
