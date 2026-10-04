# Release record: package repository 0.5.8 (supersedes 0.5.7)

**Date:** 2026-10-04 · **Location:** `aero:/data/chp-release/0.5.8/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.5.8`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.8 (snapshot/image restore, final review):**
- `idm-collect-0.1.0-9.chp`: chrony's state and offset are read from the source chrony **uses** (`^*`) when there is
  one, else the first `^` line. 0.1.0-8 read the first line only, so on a site with several time servers (the selected
  one often not listed first) the clock repair's check could never pass on a correct clock.
- **0.5.7 is not to be used.** Every other package is the same build as in 0.5.7; sha256 values differ only because
  the repository is signed afresh.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `4c587d3ce6219021f2169422f48a867e0ec9626fc392065180a4c5e36b4fbbd7` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `1b043f1008932f817d6bbe658a2aae5a6fb7f312da8df50818374707685664a2` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `06598591614fe0022ca0ac3f4f0852a4f7966a3ab3e79cd595fbb7ced2d7133a` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `89e2f05003f54717f2fce8fb632361a5350122b9aa4fc9a69e5180066032767c` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-9.chp.el9.noarch | 521276f43c908f8e | `f67671053a720a920f3254169564892a5e8181995d9681268d82a8eca02b098f` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `f0955b681619a94b6b74289935044e9417c04de7ebd2305201ced1ec7d6eef9e` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `ce8ac44e90737df15a8ce881a4c10d968414845a06bae48911efb025faff555c` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `ba3f529d46cdb2019fb0b6795e4be3949eca5c4319307a69ff4cbc8c509d740a` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `9d36d1b3a61b3c08bff7b783c192a87abf12ef44e2409ae9e90de8ecc0d46adf` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `03e062d78c90c0547e505541000ab2b64dc0298c387bcf56586f9cf841f2c288` |

Repository metadata: `repomd.xml` `ade24c0d428f705799e7fe3eae19af6353a02744850672442e8ad222ae1e1c27`, detached signature `repomd.xml.asc` `957904d2c5400a3ae837b7d4664e14d3f7fa280ba29b0f15684cd33d17b92dd5`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/plan8/` (restore plan, final review).
