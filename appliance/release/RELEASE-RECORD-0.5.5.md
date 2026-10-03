# Release record: package repository 0.5.5 (supersedes 0.5.4)

**Date:** 2026-10-03 · **Location:** `aero:/data/chp-release/0.5.5/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.5.5`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.5 (fapolicyd, ISSO requirement row 46; plus two DNS fixes held back by the ISSO for this release):**
- `idm-collect-0.1.0-6.chp`:
  - new `fapolicyd` report section: state (active, permissive) and recent execute denials from the audit log, each
    with its owning package, the key that signed it, and whether fapolicyd trusts it now;
  - a missing or dangling `/etc/resolv.conf` no longer ends the report (DNS final review I1);
  - hosts-file names are matched case-insensitively, as glibc does (DNS final review M1).
- Every other package is the same build as in 0.5.4; sha256 values differ only because the repository is signed afresh.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `d466ba4a3203802f84eaccd18c2983ed12c794bc30a30484bf67ea21eceb4f33` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `d1b740625fe9c964e2603dccd971eee32610737e8a737bdbbb233a2fd28c57c8` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `43d66cf3fc5a379f17a7ebd15f373e8943f4d71b1f279523e3c3c70edc2beb94` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `9e48f65a3d2a48a4a8a9f12e5a5d6fc9c1303e8a6f5684117c035df94928c0e8` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-6.chp.el9.noarch | 521276f43c908f8e | `a2920628639fbed27bb4d4747354025763fc58a3f005f6513ddf62e112ea0a7c` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `aeafa7b38f4771d46a2c464300d29d3a2ef398cac59a4a042c8e147120a78f5e` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `b68dbd5043caa1f733df504d26b864fbe3926241601529c70f0a5409e572bc3f` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `25b7c8fe7e6f9f889d4358f2fcd45dcb9c9e7f5c9101e25f1769e255ebd6ef25` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `d57c19d9d7574f9e596e558698d1e116c3381e28a24e0b78cac7a8ffc91fd89c` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `aa48f366e692f94de479257b58073c4f5e6c30bbb9811777f1fa60440088ac69` |

Repository metadata: `repomd.xml` `bf735e6a9732dab2fcf679101c0c7e2075f2bcb31f3f751649e0665c72c63d1d`, detached signature `repomd.xml.asc` `7b69feba5fc24299e3979ee6bb42e4d46a600f4676efad568e891841dd003245`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/plan8/` (fapolicyd plan, Task 5).
