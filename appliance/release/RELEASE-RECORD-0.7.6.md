# Release record: package repository 0.7.6 (update for ISO 0.2.0, published as `0.2.0-update2/`)

**Date:** 2026-10-25 · **Location:** `aero:/data/chp-release/0.7.6/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.6`)

**Why 0.7.6 (chp-templates Plan C3):**
- **`chp-templates-1.2.0-1.chp` (new)** is built from the signed `templates-1.2.0` release; the build checks its
  signature and its pinned sha256 `ca40b7ff…` first. It installs the library to `/usr/share/chp-templates/`. The
  renderer ships as the zipapp `chpfill.pyz`, because the build host's fapolicyd blocks reading raw `.py` files.
- **`chp-site-0.7.2-1.chp`** adds `chp-site docs` (render the SSP and POA&M from the site stick's `profile.ini`), and
  `chp-site validate` now checks `profile.ini` too.
- Every other package is the same build as in 0.7.5 (re-signed, so sha256 differs); `aide` keeps Rocky's signature.

**Lab proof (2026-10-25, iso5-srv at rc2 golden, reverted afterwards):**
1. Unpacked 0.7.6, then ran `dnf --enablerepo=chp upgrade chp-site` and `install chp-templates`. Result:
   chp-site-0.7.2 and chp-templates-1.2.0 installed.
2. Put the kit's `profile.ini.template` (fictional values) on the site-stick image as `profile.ini`, attached the
   stick, and ran `sudo chp-site docs`. Exit code 0.
3. **USBGuard** temporarily allowed only the site stick, then blocked it again (both steps in the journal).
4. **Output:** `/var/lib/chp/docs/20261025T151530Z/` is mode 0700, and `ssp.md`, `poam.md` and `fill-report.md` are
   each 0600.
   - The boundary list (srv1, ws1) and the contract (with its clause) rendered.
   - 61 placeholders were left for the site: 45 family-status scores, 8 assessment fields, the POA&M due dates and the
     supporting documents.
5. **AIDE:** `aide --path-check d:/var/lib/chp/docs` reports **no matching rule**, so the documents can be edited
   without alerts.
6. `chp-site validate`'s `profile.ini` check accepted the kit template under the real chp-templates rules (50 values,
   1 fact).

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `81b4ca1b097dd5f12b39b36ae5a86ffd6a2ccb577f23443a7de81edcb0620bd9` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `9343b3f2393070df3fdfbd366057d96d37543acc43fb747316ac9108e54df4f3` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `46012ffab7e8b1175765d89e844963f605d6f8619ff2ef376f77889c6d902d64` |
| chp-integrity-0.1.5-1.chp.el9.noarch | 521276f43c908f8e | `41ed4ab60b9ee30a58ab10e6cb1e131f267f97b70e6fd79e0f53a9626fb14274` |
| chp-site-0.7.2-1.chp.el9.noarch | 521276f43c908f8e | `e7b4e3ae632b32a0e6469f68334822abb26f18281b80644e060cc6adf7d2f651` |
| chp-templates-1.2.0-1.chp.el9.noarch | 521276f43c908f8e | `8976c07c76d656540f96f92bd5fa16f94e019d5ad9cf136829dd4a5561afde0d` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `aaf8be74c74ddae4d360001d344b36479e1753bfe9251f3da56f1243bf211847` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `b454a7e395ec0b5eb9abf9f1d49d03942306befdb6f35ca318128de50e1e0f75` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `253f18542b7df4e9633250546e6651cf6a3cdfc5344f9253e1552255bf762e29` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `3331a156ac3918e8c1bb61128c7e0c98ac1777ae75337b9b65598afb46b240eb` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `fbd32944601ddd36c6fb0a07d38c17a1859c5041f67ffc5f3bf425df2a9238e9` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `60c49eb56ceee4dd2b3f80d05a92253af8a06d8b2b1f67911248ca1f7d374878` |

Repository metadata: `repomd.xml` `90c02585ffd1989746286774ac3f0df9e068c3134f5edd7b090724beb478bef3`, `repomd.xml.asc` `273d1144cdccb7a5d96ad37905413eac551b4e0ab11d13ce98135f83393fa727`.

`verify-repo.sh`: `REPO OK: 14 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`
