# Release record: package repository 0.4.0

**Date:** 2026-09-30 · **Location:** `aero:/data/chp-release/0.4.0/repo` (a lab copy is served at
`http://192.168.100.1:8080/chp/0.4.0/`) · **Audience:** CyberHygiene Project development team only.

**Why 0.4.0 (ISO Plan 4a: the client role, core):**
- **new** `chp-identity-client-0.1.0-1.chp`:
  - client enrolment (pinned CA root, per-host unixd token, authselect `custom/kanidm` from the CUI profile, sshd drop-ins)
  - the diag and chpcache forced-command accounts, and `chp_admins` sudo
  - the `chp_kanidm` SELinux module
  - the authselect, sshd and Kanidm-TLS monitors
- `chp-identity-server-0.1.1-1.chp`: first-boot steps `unixd-tokens` (login groups + one read-only token per host) and `self-client`.
- `chp-site-0.4.0-1.chp`:
  - per-client tokens: `pre` stages the host's own, `export-client` moves them with read-back, and `client-token HOST` covers hosts added later
  - `get` with the client.conf values
  - `COLLECTOR_SSH_PUBKEY`
  - `authselect-patch`
  - `onboard` adds `chp_users`
- Everything else is unchanged from 0.3.3. chp-base is still `0.1.0-3`; rebuilds of unchanged packages carry new hashes.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `6ea15e151d4de2279abec9ca14cedc7a792965959f1546274ee16600051f048c` |
| chp-identity-client-0.1.0-1.chp.el9.noarch | 521276f43c908f8e | `d66fae80efe482d658f221b7b669f7841a4eab415306413ad5f0a0664311fc86` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `64f96f68bdba997f68fe0625e13ca0ac38e0d070f69e0ef72f6a0b087a16dbe8` |
| chp-site-0.4.0-1.chp.el9.noarch | 521276f43c908f8e | `d35c4f3b47de626ebc8d1c731366a072c263e6710e59b065940ddb56f8d40feb` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-2.chp.el9.noarch | 521276f43c908f8e | `9efd8fc2a4304b7f9ad2cf5a1bc1635274668e4311bfc3985cd8d0cfe87d1d39` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `07c6516ef3522cd02f712f6a9d812372352ab5af63b1e393c425beeb2523664d` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `235bbb140cf37159c912c8620ca9bbe949c2aa6afd841b7df21d22db3cc08ca5` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `55326177ecc98c66ead7e416679ccd577f3b37062c3fbff7e19cd1849d50e26c` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `0955a4428d41b24f07234c363ad6e9ad1fa8a4cb5046952e1900e6a06d01795c` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `9f393ee0ea372c93d6024693b124ccbb585639aedf1e5900975840e4bc40b1d8` |

Repository metadata: `repomd.xml` `88e5deb2ec214e2f3703dc309288d3dda3178805c32b2261fd405b2e77ed85e5`, detached signature `repomd.xml.asc` `366524de7a06a15e83d040e3f5c631b9bf63653f53fc6b2222728563735fbfc3`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/iso4/PROOF-RECORD.md`.
