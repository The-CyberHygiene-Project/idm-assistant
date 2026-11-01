# Release record: package repository 0.7.8 (update for ISO 0.2.0, published as `0.2.0-update4/`)

**Date:** 2026-10-29 · **Location:** `aero:/data/chp-release/0.7.8/repo`

**Why 0.7.8 (security bundle part 1, Plan W1, spec 2026-10-27):**
- **`wazuh-manager-4.14.9-1` and `wazuh-agent-4.14.9-1` (new, third-party):** Wazuh's own packages, unmodified, keeping
  Wazuh's V3 RSA/SHA-256 signature (key `0DCFCA5547B19D2A6099506096B3EE5F29111145`, rpm ID `96b3ee5f29111145`, pinned in
  `trusted-keys.txt`; the key expires 2027-05-15 and the release scripts refuse a key expiring within 90 days).
- **`chp-security-0.1.0-1.chp` (new):** the Wazuh monitor checks (70/71/72), the alert forwarder unit, log retention, and
  drop-ins so Wazuh never starts without its bind-mounted data directory.
- **`chp-site-0.8.0-3.chp`:** `security enable|status`, `alerts`, `wazuh-forward`; ships Wazuh's signing key. AIDE
  counts Wazuh-signed files as explained.
- **`chp-integrity-0.1.6-2.chp`:** AIDE watches `/var/ossec/etc` but never hashes the agent keys or the TLS key (or
  their copies).
- Every other package is the same build as in 0.7.7 (re-signed, so the sha256 values differ); `aide` keeps Rocky's
  signature, `google-authenticator` EPEL's.

**Lab proof:** `lab/security/PROOF-RECORD-W1.md`.
- Proof 1: upgrade and enable; agents connected; ports; 0 Wazuh SELinux or fapolicyd denials; idempotent; reboot.
- Proof 2: catch (brute force, grouping, agent stop, monitor backstop).
- Proof 3: 29-hour quiet check, **0** Wazuh alerts to the hook, no tuning needed.
- Re-run after the final-review fixes:
  - default API logins refused (HTTP 401) for a non-root user;
  - update check off;
  - agent upgrade module off;
  - 0 "No such tag" warnings;
  - Wazuh files explained by AIDE.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `975bef1176a76a07eb38b0e56fa794adae16620ebd1f5a98a7b4df1de548454a` |
| chp-identity-client-0.2.3-1.chp.el9.noarch | 521276f43c908f8e | `095d45801dce7f971174d54b01d988c905d674dbad30b6a8a51775a7a582505b` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `896d9b8d1fb261f7d99ae39ce071066554aafc16a11a814e93f743548f6bc684` |
| chp-integrity-0.1.6-2.chp.el9.noarch | 521276f43c908f8e | `9e62b47603f21673e8364de58da9e28917701a5c4cdaa7a77744d4f43a36f4da` |
| chp-security-0.1.0-1.chp.el9.noarch | 521276f43c908f8e | `2b6ef05e2daa9905303df5555042e3946f39e05974d186b40111295030c3e441` |
| chp-site-0.8.0-3.chp.el9.noarch | 521276f43c908f8e | `418916b846fcabc327d788b24d524aa771b32436517e952d9c69e46191e59f08` |
| chp-templates-1.2.0-1.chp.el9.noarch | 521276f43c908f8e | `83aab7435ced34a1feb6007f08b83e2a883683910221bfc43ec100b417b66ad1` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `a7c9641e48b4c5b26f4fe9fffc783feba3d3bf4f7ba6857b5c3422a02cfae8b7` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `0a22c03ac327d5f602fc21004c4e3502a811c2d535f4de1ba584140eefcd581f` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `f43f3bea85175513a23823986b358b95acc3b4775da05449abc92e3de7597366` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e1d0c02340504e6fc9a884770cce47a9f0c064c740467b43f5f2352c45b84d23` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `29ef0a8a4a2db79dedf9d0b1a707092a9550763e05bd2f06c81cb6e492d8fb1f` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `d3894ed6467e60f4316e14366d7c98a64fde4e7d8db892e3d181a11604905e7a` |
| wazuh-agent-4.14.9-1.x86_64 | 96b3ee5f29111145 | `47596ab933d565c40f7263dda96a9e384495e8cb4a7a48b17694ab6daa145575` |
| wazuh-manager-4.14.9-1.x86_64 | 96b3ee5f29111145 | `d258e605df92371944a5bd18b3adf007b25b4a2ccb551b4ad3fc624d55ad63ec` |

Repository metadata: `repomd.xml` `94a6e7adb7195b69d553d1e98616f3cebded4e571c361af0fdad18908345a644`, `repomd.xml.asc` `12fa34d6f4308577b1ea4e0f9365ef5d8e9cde5fe157d57cc84e2220c06e6e1d`.

`verify-repo.sh`: `REPO OK: 17 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`
