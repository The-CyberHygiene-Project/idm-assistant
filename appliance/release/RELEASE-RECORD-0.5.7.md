# Release record: package repository 0.5.7 (supersedes 0.5.6) — SUPERSEDED by 0.5.8, do not use

**Date:** 2026-10-04 · **Location:** `aero:/data/chp-release/0.5.7/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.5.7`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.7 (snapshot/image restore, requirement row 18; power outage):**
- `idm-collect-0.1.0-8.chp`:
  - `time.source_state`: chrony's state for its source. After a snapshot restore chrony keeps saying "synchronized"
    while it rejects its source as too variable (`~`); with this field the engine sees the hidden clock error.
  - `uptime_s`: seconds since boot, so findings right after a power-on say they often clear by themselves.
- Every other package is the same build as in 0.5.6; sha256 values differ only because the repository is signed afresh.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `30238373bcffaf0858deed1d12d917e220632b637c636d00c2ab7ed0a6ddda41` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `c1e824ae4758b69e79f4d917dc524741e8066e2a302c8ef86e8322780676cc3d` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `0eb8bd11cb55f33f2659b8f013a06a9d4e4427642582a3d341ccacd2d8d8d8d4` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `d9dc528af98bab3361e3b617163bc54d3fee07775f35bba8c2a161c79e284a94` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-8.chp.el9.noarch | 521276f43c908f8e | `3c9b6106bbe1c135f32d63e4a56ea6287286279fa7f1c536d501134cbd71d198` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `3f450a74e28552f82aac61bcd9ba854cdcc059a36d4576c9ee26513efdb7c933` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `1f5fb3d71b5177151b828118ed9b4d8abcbe3a9036ea8cff47c758af507af1e7` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `fb532b4c8be8900fb590f834a866cdc5a06109ccbaaaba3885e4b0372ea31af2` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `71d19377742bda2bf6bceb6702303caee433c6889a3bcf8fb646a74bca2e71a6` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `c0d37715118c838af9b3f0827fd0e3475623bafe134571ac185e2b0438c08dca` |

Repository metadata: `repomd.xml` `7a8e37ab1d799979aad99727f99092fd5cb283b20113f7c5874bdae49330d91a`, detached signature `repomd.xml.asc` `2df0696a925573777fce7ff911f1dd5c906e17dc1471f1297730577da5727c81`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/plan8/` (restore plan, Task 5).
