# Release record: package repository 0.3.3

**Date:** 2026-09-30 · **Location:** `aero:/data/chp-release/0.3.3/repo` (a lab copy is served at
`http://192.168.100.1:8080/chp/0.3.3/`) · **Audience:** CyberHygiene Project development team only.

**Why 0.3.3 (ISO Plan 3b):**
- `chp-site-0.3.0-1.chp`: `onboard`, `revoke`, `unexpire` (spec §4.4; ISSO #28, #32), `client.conf` `CACHE_PUBKEY`, audit
  records before and after every change.
- `chp-identity-server-0.1.0-5.chp`: the `cache-key` first-boot step (the revoke fan-out key), and the collector login retry
  that Plan 3a built as `0.1.0-4` but did not sign (carried forward).
- Everything else is unchanged from 0.3.2.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `024fbff3538c210303db9cbfe3e172191e1b92ba846f15bc82d7613624c6b04c` |
| chp-identity-server-0.1.0-**5**.chp.el9.noarch | 521276f43c908f8e | `ca95cbce77203933a9725999f1013010b17c14610a63b36d90ba31b71a4f8eb7` |
| chp-site-**0.3.0**-1.chp.el9.noarch | 521276f43c908f8e | `e805644476d89eeac2f73f109e357dad26ee5dec928cdc0b070d6c71907a9b3b` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-2.chp.el9.noarch | 521276f43c908f8e | `3f56ebe3ab7226c558f8c1b9f3137cdd872904490d5998999df40c00484fffff` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `621691dc19ee0ce264dee55cbc56ca474418d4a03841d4acb475aa36e4eeed95` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `6685ebdde385d9b76b29630add239031a2fd3e4c826ff74fb76fd2515442a588` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `d86db1bf32da2c64c9ce12cc067bfce198bb01adf23547e3577bd825debce694` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `5ecca55efe79e87fa442bdb5b35f0a469d8fc3911a9dfbd78dcf8aa4630e0fdb` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `bc9cce87c0ba462e58dd2af879fa89196f5ffee86e909562da01a5011864c246` |

Repository metadata: `repomd.xml` `4b1b0be286333fe5ff37595cbd7820819216c084449b55382a616b805c235d32`, detached signature
`repomd.xml.asc` `e762a0ba831274d9a37d59115d63ee74ae20293a8e54f5f448acdd87712be1f8`.

`verify-repo.sh`: `REPO OK: 10 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Checked before signing: `server-firstboot` inside `chp-identity-server-0.1.0-5` contains both the login retry and
`step cache-key do_cachekey`. Install test: `lab/iso3/PROOF-RECORD.md` (Plan 3b section).
