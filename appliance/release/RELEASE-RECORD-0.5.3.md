# Release record: package repository 0.5.3 (supersedes 0.5.2) — SUPERSEDED by 0.5.4, do not use

**Date:** 2026-10-03 · **Location:** `aero:/data/chp-release/0.5.3/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.5.3`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.3 (DNS faults, ISSO requirement row 45):**
- `idm-collect-0.1.0-4.chp`: new `name` report section on workstations (how the identity server's name resolves via
  getent, whether the answer came from the hosts file or DNS, the DNS servers, and whether the first one answers on
  port 53: answers / refused / unreachable) and `own_addresses` on the server.
- Every other package is the same build as in 0.5.2; sha256 values differ only because the repository is signed afresh.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `716eeafa4392336622d31e98fe04c674bc71a680090237a3203f00d03508b5c1` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `a2b6622614c6f28ed306ba168ab934d97d67103f9fc273a1cb7bd402a04a06ea` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `f8210d62bf8c62d6cd3b36ee85f340d6a702bcea2b18f315267391c5917cbf38` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `9233c4586e225af5eef904cac58a3c334fa7ef801c4670cded334fd6f8dce25b` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-4.chp.el9.noarch | 521276f43c908f8e | `c2ff7e7361cbf51243b1d87da5d91aa3010d82adbde00ecdb13b6deec6bd9a4d` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `ff25f3c62ec9b384b64b93f705efd4bb053cddcbde2c0f914fe3f352c2809de5` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `80dffd7213438a31cf02a13e8beb5ae22b469360f9f2c011989b26fa164c0906` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `bf0f9664182ddc1f6c06cb0244f3c2d917595ac9aa66bd48c231664ce67b1d88` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `c1e4bcb119f78d1d1655713f87b8d35d5d8c929c549db635e836bb3609ef1c3f` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `881041615195cc1e9ce99a5e5e867f5615c5e7f24d6c0aade4fbc51a491d37e8` |

Repository metadata: `repomd.xml` `eafe8034853936950e41dc8996fe2b7772c5d677cff3e65f61055318bf3b6f81`, detached signature `repomd.xml.asc` `6f508b6e7936c18fa731da46eb7576d977abdcdaf730f2ec8309547e0302520b`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/plan8/` (DNS plan, Task 5).
