# Release record: package repository 0.5.0

> **SUPERSEDED by 0.5.1 — not for installs.** 0.5.0 lacks the short-name unixd setting: `sudo` with the second factor fails for every Kanidm user (ISO Plan 4b final review I2).

**Date:** 2026-10-01 · **Location:** `aero:/data/chp-release/0.5.0/repo` (a lab copy is served at
`http://192.168.100.1:8080/chp/0.5.0/`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.0 (ISO Plan 4b: the second factor):**
- `chp-site-0.5.0-1.chp`:
  - the Google Authenticator PAM lines in `authselect-patch` (Kanidm users; local accounts skip)
  - `ga-enrol USER [--reset] [--no-confirm]` (a host-local token, 5 scratch codes, audited)
  - `pam-test SERVICE USER` (row 36)
- `chp-identity-client-0.2.0-1.chp`:
  - requires `google-authenticator` and `chp-site >= 0.5.0`
  - owns `/var/lib/google-authenticator` (0700)
  - the `53-ga` monitor
  - no `chp_ga` module: Plan 4b Task 4 measured 0 AVC with the policy's `var_auth_t`
- Everything else is unchanged from 0.4.1.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `f67c2dc943ae1b92234b75236d94177e771a8e63cc9a0755645dd641b635a3b7` |
| chp-identity-client-0.2.0-1.chp.el9.noarch | 521276f43c908f8e | `fb953184e1d931680b6f4cf398f5fb3b0edf9444f8a6c61a72e37c556e438e78` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `f2e63fa720928bb448e064cbfb7a92923618f3e050269d8922211002144279a4` |
| chp-site-0.5.0-1.chp.el9.noarch | 521276f43c908f8e | `e43511d974470c5014c1d262f067193fd0d2680a356c9f6b0ae6b61fee8ecbff` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-2.chp.el9.noarch | 521276f43c908f8e | `6113dda0657ec37520d4d14afb3cf402eb357c37f457df3582984ee573a1f71a` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `9154557eb5e51d59609d6185be6437c7516af1e8c2edff5aaa9580f8fed17226` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `d6d198ef729eff808f9e2b800301979ea6c7d669c21616e5679be8fbe48747a5` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e2d549a9bd55d84d5f57ddd251ecce9ab77aadb122248f41cb38209b6266040d` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `4b49799e00ad722783d246f947608b9c1ca90139ffed2c8c9704de4dc47f248a` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `0e10f5c76089dfc240272a8bc76ee233f333d5184d2d44b3da33d2244d17087f` |

Repository metadata: `repomd.xml` `2cb87b059e27fb380779c32799a68d956d88645e29e87790b40bd49274deecac`, detached signature `repomd.xml.asc` `7ff6fba9319dc5e2f5e8cf3b38b3e2e2228a343273df242ba0ecca1935fbbf5f`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/iso4/PROOF-RECORD.md` (Plan 4b).
