# Release record: package repository 0.1.1 (supersedes 0.1.0)

**Date:** 2026-09-29 · **Location:** `aero:/data/chp-release/0.1.1/repo` (a lab copy is served at
`http://192.168.100.1:8080/chp/0.1.1/`) · **Audience:** CyberHygiene Project development team only.

**Why 0.1.1:** the final whole-branch review of ISO Plan 1 found two package defects in 0.1.0:
- `step-ca-0.30.2-2.chp` had an **empty `%pre`**, so it never created the `step` user. The systemd sysusers *file trigger*
  does not run inside Anaconda, so an ISO install would have had no `step` user (fixed in `3.chp`: same binary, only the
  scriptlet changed).
- `idm-collect` reported a missing or invalid `collect.conf` as a network or trust fault (fixed in `0.1.0-2.chp`).

The repo tooling was also hardened: `sign-repo.sh` signs only our own unsigned RPMs; `assemble-repo.sh` takes our packages
only from `built/`; `verify-repo.sh` accepts only pinned **primary** keys; the published key is signing-only. 0.1.0 is not
to be used.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `97b5ca4075a715bce828758fe177e2f2c55b6c1278d8435e293e8ed4a9f14d3d` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `ffe1998092c5ebe15e7154fc06ad4f9e2f986b88ec76390cbed6d394b0aaa071` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `eaafffb77adde57780c1a23d5137c302231f6a72c2231424c7055d304b9ed607` |
| step-ca-0.30.2-**3**.chp.el9.x86_64 | 521276f43c908f8e | `96ac523c84d310745836d586a9e46773dc3a87bff977fd4b64fecb1fa6cb8623` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `f76ae1a0c8359799290e5078aed1d1287963cc47998f2c991dc12616fc71e996` |
| idm-collect-0.1.0-**2**.chp.el9.noarch | 521276f43c908f8e | `26e0fee078f74f181992932e5ff624e3c9b52245440dca216e30bee0484b7a8c` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |

Repository metadata: `repomd.xml` `127810be298186eb686daa721f1458bc8bd3b04a3fd1561fc0d8f59d99c6f8dd`, detached signature
`repomd.xml.asc` `9ad127af08469fed8e47872bf960aeeed372fa46d719d6ee8091b98b7e714683`.

`verify-repo.sh`: `REPO OK: 7 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

## Install test (`lab/host/iso1-install-test.sh 0.1.1`, srv1 + client2, then reset to golden)

The repo was configured with `gpgcheck=1`, `repo_gpgcheck=1` and both pinned keys (the signing-only public key).

| Check | Observed |
|---|---|
| Positive control: with our key, the repo's metadata is accepted | **PASS** (`PASS: accepted with our key`) |
| With only EPEL's key, dnf refuses the repo, **and the refusal is a signature error** (not a download failure) | **PASS** (`PASS: refused (signature)`) |
| srv1 upgrades to kanidm-server/clients 2.chp, step-ca 3.chp, step-cli 2.chp; kanidmd and step-ca active; Kanidm `/status` `true`; step-ca health `ok` | **PASS** |
| client2 FIPS-variant unixd talks to the FIPS-variant server: `Kanidm: online`; `getent passwd lab02` | **PASS** |
| client2 **fresh** install of step-ca 3.chp (no `step` user before) creates the user | **PASS** (`step:x:992:992:step-ca service:/etc/step-ca:/sbin/nologin`) |
| idm-collect 0.1.0-2.chp on both hosts; healthy hosts give no findings | **PASS** (`srv1 findings: []`, `client2 findings: []`) |
| every kanidm, step and idm-collect package signed by key ID 521276f43c908f8e | **PASS** (both hosts) |
| fapolicyd denials since the test started (`ausearch --input-logs`, positive control shown in the 0.1.0 record) | **PASS**: srv1 0, client2 0 |
| lab restored to golden | **PASS** |

What the test still does not show: package-level `gpgcheck` refusing an unsigned or foreign-signed RPM from the repo (the negative
exercises the metadata signature; `localpkg_gpgcheck` refusing an unsigned local RPM was seen in Task 4).
