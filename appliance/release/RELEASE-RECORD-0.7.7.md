# Release record: package repository 0.7.7 (update for ISO 0.2.0, published as `0.2.0-update3/`)

**Date:** 2026-10-25 · **Location:** `aero:/data/chp-release/0.7.7/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.7`)

**Why 0.7.7 (requirements row 49, owner decision 2026-10-25: dontaudit):**
- **`chp-identity-client-0.2.3-1.chp`**: SELinux module `chp_kanidm` 1.1 adds three `dontaudit` rules for
  `fapolicyd_t` at the kanidm-unixd socket (sock_file write; dir getattr/search; unix_stream_socket connectto). It
  adds no `allow` rule: fapolicyd resolves only local accounts, and nsswitch asks Kanidm first.
- **`chp-site-0.7.3-1.chp`**: `chp-site validate` never runs a chp-templates renderer found next to the site folder
  (Plan C3 final-review fix).
- Every other package is the same build as in 0.7.6 (re-signed, so sha256 differs); `aide` keeps Rocky's signature.

**Lab proof (2026-10-25, iso5-cli2 at rc2 golden, reverted afterwards):**
1. Unpacked 0.7.7 and ran `dnf --enablerepo=chp upgrade chp-identity-client chp-site`. Result:
   chp-identity-client-0.2.3 and chp-site-0.7.3 installed.
2. **Before** (0.2.2), a `fapolicyd` restart logged **4** AVC denials (`fapolicyd_t` → `kanidm_unixd_var_run_t`).
   **After** (0.2.3), the same restart logged **0**. fapolicyd stayed active, Kanidm stayed online, and the Kanidm
   account `lab01` still resolved.
3. **The access is still denied, only silenced:** with dontaudit rules disabled (`semodule -DB`), the restart again
   logged **4** denials; with them restored (`semodule -B`), **0**. The loaded policy has no `allow` rule for
   `fapolicyd_t` on `kanidm_unixd_var_run_t`.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `b1643e34342bb186e2ffa7dadf9389327d281b4ddebd10ee2840cdb3309c9d75` |
| chp-identity-client-0.2.3-1.chp.el9.noarch | 521276f43c908f8e | `27ce90ef8aca23a730582f671a2a4553921067ba97c78cda629fa47e3b68c8bd` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `c20937b3de2078ee8a995e4b1fadc05f11ebc04ce43666d62c5588938506bcfc` |
| chp-integrity-0.1.5-1.chp.el9.noarch | 521276f43c908f8e | `13a96265032c0e01ae28149083cb5488d419385b2936414f335f471208e9e034` |
| chp-site-0.7.3-1.chp.el9.noarch | 521276f43c908f8e | `491b011a0ffd78d7dd4623b56efa37ca1d5cdec8bd7156a076233dacc270ba16` |
| chp-templates-1.2.0-1.chp.el9.noarch | 521276f43c908f8e | `06566827cc230ae47432682f88ff253f0c23afcb2a64e2c12b5281b7f301849a` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `92ce513bb654053b9a8d4ea17528dc9d2711512223f2932b95681232f0fc94b4` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `c36bce6af8d9ef5efbacd6d6f4a76b88d1c5404ff5244aaa8cfcc2183dd3d00b` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `7ed8925d2a3830898a83566d5e82e3dabbebb23ba83e61aa51d0b9255597cad6` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e29b15534165fe8000ac13c9efd83ea2016a0adf92c5a680543afe7fec5e6908` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `5163b39c00d3282d84f1bf3e47f5f2f2326c6b2f32528cb9b4d4a7bfa6c0f2c2` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `32cb6429ca208c125dfb7acbd09f731c935664a3f6177cee7a69fbc6f0567185` |

Repository metadata: `repomd.xml` `0776871c81ddafb77ae5a17fecfa269c1251ea87a8615d8b8ef8cbdc3481de48`, `repomd.xml.asc` `0c068bc7e4dd6d927df740d55032d8bd3b761199564a3f51cc2d7050bfd7c2b8`.

`verify-repo.sh`: `REPO OK: 14 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`
