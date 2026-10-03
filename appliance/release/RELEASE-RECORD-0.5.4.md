# Release record: package repository 0.5.4 (supersedes 0.5.3)

**Date:** 2026-10-03 · **Location:** `aero:/data/chp-release/0.5.4/repo` (a lab copy is published at
`aero:/data/lab-inputs/chp/0.5.4`) · **Audience:** CyberHygiene Project development team only.

**Why 0.5.4 (DNS faults, ISSO requirement row 45):**
- `idm-collect-0.1.0-5.chp`: the DNS server probe is a bare TCP connect (bash /dev/tcp), closed at once. 0.1.0-4 used
  curl, whose exit 7 also covers "no route" (a blocked route read as a stopped DNS service) and whose telnet mode held
  the connection for named's 30 s idle limit (every collect ~30 s slower). Only the kernel's "Connection refused" now
  reads as refused. The package now requires bash.
- **0.5.3 is not to be used.** Every other package is the same build as in 0.5.3; sha256 values differ only because
  the repository is signed afresh.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey, `SIGNING-KEY.md`). The only third-party signature kept
is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `dc14a3cfe34f58ef78adb53759ce2ebab218e48e75c2c83430d270280c1f20fc` |
| chp-identity-client-0.2.1-1.chp.el9.noarch | 521276f43c908f8e | `e1f9061a5b9ed7e8e269d6a90b1792ece0b2972dc5eb0ec4fc709f5834c6efa3` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `bd4b8589d351eee412ac95a002bf400a68bc1e6205f46906ce51771b42c3260f` |
| chp-site-0.5.1-1.chp.el9.noarch | 521276f43c908f8e | `b3a78fe1474b2ca2af81ec62424fb0364ae69dd13af8361ce2542e45e723d956` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-5.chp.el9.noarch | 521276f43c908f8e | `816bdf6febdfc4fdce2835a55f174e600b7f1566f8d1ab7fcde69396d6c9229e` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `3c009766c2cb5225808c7e43cad0834d35ed0d80542fe8de36c67c8ee4a75dab` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `93325c6fdc44148944ae493a54e81136527acde13b772469dc8dc70c1da69951` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `8c6dbaba9dae6bf7660607f06cdfd3268f620848d782f2f89e35e26603f37ccb` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `9d4092ebec8c308b49be1093982ffe12dce23154c466fea027daaa79a3aad539` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `ab7795d85e7ae04ff9aca7066bdc29d79a3f034d9eba2584a51be93ee2b394ee` |

Repository metadata: `repomd.xml` `064c432f2de9fc2371dd456ce364c04e419bebd9a543878fd6f1d3d91bb7766c`, detached signature `repomd.xml.asc` `ec6269ff63a8376b9df0a45c096f210a5be3b78c93271d65c5790ac5adf553f5`.

`verify-repo.sh`: `REPO OK: 11 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`

Install test: `lab/plan8/` (DNS plan, Task 5).
