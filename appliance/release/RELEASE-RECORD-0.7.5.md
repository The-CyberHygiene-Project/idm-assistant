# Release record: package repository 0.7.5 (update for ISO 0.2.0, published as `0.2.0-update1/`)

**Date:** 2026-10-24 · **Location:** `aero:/data/chp-release/0.7.5/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.5`)

**Why 0.7.5 (Plan B final review I2):**
- `chp-integrity-0.1.5-1.chp`: the CHP AIDE exclusions are anchored with `(/|$)`, so they no longer also hide sibling
  paths such as `/root/chp-escrow-pendingX/`.
- Every other package is the same build as in 0.7.4 (re-signed, so sha256 differs); `aide` keeps Rocky's signature.

**Lab proof (2026-10-24, rc2 golden srv1 + client2, reverted afterwards):**
- `dnf --enablerepo=chp upgrade chp-integrity` succeeded and `aide --config-check` passed.
- `aide --path-check` shows `/root/chp-escrow-pendingX/y` is now checked under `/root NORMAL`.
- The `aide-accept` summary lists the package's 10 files as **explained** and `/etc/aide.conf` as **not explained**,
  because `/etc/aide.conf` is copied into place by the package rather than owned by it. `UPDATE.md` tells the ISSO to
  `cmp` the file and run `rpm -V` before accepting.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). Third-party signatures kept: EPEL, Rocky.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `26cde2adfb66e8f1449fc7d67ea6d0d31cd67764e3331370d78f458515e1340c` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `eb0b2256ecb769c3d3c19c9383e53578a833518289916e22fa0e7118e6b5adb0` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `eef07a057dfede2942400456448fca24a02dbde10b0f3812a655c272a771d418` |
| chp-integrity-0.1.5-1.chp.el9.noarch | 521276f43c908f8e | `753361752adc65dd2118d354061a0dc5b76864a674bb0e887d6ba38616616d2e` |
| chp-site-0.7.1-1.chp.el9.noarch | 521276f43c908f8e | `d5a9a2bd63eddd5709a6cba4ced6680d5b998e83ff2a6512e896bcd3e12ac8b4` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `61af39281d02bbc77f385f0fb3685d11599831a1471cb795e8da81943a5a21be` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `7e7eec1110cfe9f3f9ba7923ada5157d9df223cbda8a46ff3a740f97ef2d9091` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `11db45b99b978b91ad4205c76551044300671338ca18b5035b4e9d954f0839b6` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `ecfd2717b83ba725729ac7763755feaca21bf0f0f627febea9b0e02894415235` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `9795b563fa34f1e03b27635091bb6f866a1cad10b9807f75ee598fed829a003f` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `5bec10af17419558cc2da3442a5923382d8795e6daba724b27d68cb82421bf8b` |

Repository metadata: `repomd.xml` `b1c60984ea58ed98bf5edc6eaddeaa54f7302951d95683f8228cd16bb049029d`, `repomd.xml.asc` `522390e618d62783879a041eadf7ae1deb20087ea693d0f97fa893a9ac8c8650`.

`verify-repo.sh`: `REPO OK: 13 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`
