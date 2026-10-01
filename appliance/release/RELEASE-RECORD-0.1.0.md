# Release record: package repository 0.1.0

> **Superseded by 0.1.1** (`RELEASE-RECORD-0.1.1.md`): step-ca 2.chp never created its `step` user, and the negative test
> below could pass on a download failure. Do not use 0.1.0.

**Date:** 2026-09-29 · **Location:** `aero:/data/chp-release/0.1.0/repo` (a lab copy is served at
`http://192.168.100.1:8080/chp/0.1.0/`) · **Audience:** CyberHygiene Project development team only
(`appliance/branding/NOTICE.txt`).

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (The CyberHygiene Project Release Signing), a key on a
dedicated YubiKey (`SIGNING-KEY.md`). The only third-party signature kept is EPEL's (`FF8AD1344597106ECE813B918A3872BF3228467C`).
Both are pinned in `trusted-keys.txt`.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `220808e147a99cf9c5b5f8e505ae07ede8fbf797cf446b4d390c34a7c6d47b40` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `127eaa3941cfee4a8cb5b3809f0d91efc35d9a89761f65df702043577d2903e4` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e9f74fad468e947bc0da6da40a120f5c1384d3b9eb91cf31f34efe39f6524d93` |
| step-ca-0.30.2-2.chp.el9.x86_64 | 521276f43c908f8e | `814ece2062423d49d6b1df092ec9ef3a720b8eee2459080d29bd9fa09c4b7d7a` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `d4fef092b00674df1522e59a8f1291c7d7c9c54dbbb8a056a435d70a5aa551cc` |
| idm-collect-0.1.0-1.chp.el9.noarch | 521276f43c908f8e | `8bfd4c357bcbac561b966d7283f4f2bfec2fbb3c9dbcc4db68377a912d4565b9` |
| google-authenticator-1.09-5.el9.x86_64 (EPEL, unchanged) | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |

(The build records list sha256s taken before signing. Signing rewrites each RPM header, so these are the release hashes.)

Repository metadata: `repomd.xml` `37511f4d983cc5fb27bd4fb3c05dc2fced7df5c81289d84ba264a33606b9374f`, detached signature
`repomd.xml.asc` `8fda0d8941b35f999372744ab6dc1694890ade2e8b3ecfa632bef92c756c080a`.

Build provenance: `appliance/rpm/kanidm/BUILD-RECORD.md` (FIPS TLS variant + `client-fips.patch`),
`appliance/rpm/step/BUILD-RECORD.md` (Go 1.26.8, Go Cryptographic Module v1.0.0),
`appliance/rpm/idm-collect/` (noarch, built on aero). Crypto-module status: `CMVP-STATUS.md`.

## verify-repo.sh

```
REPO OK: 7 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E
```

## Install test (`lab/host/iso1-install-test.sh`, srv1 + client2, then reset to golden)

The repo was configured with `gpgcheck=1`, `repo_gpgcheck=1` and both pinned keys from `/etc/pki/rpm-gpg/`.

| Check | Expected | Observed |
|---|---|---|
| dnf with only EPEL's key configured refuses the repo | refused | **PASS** (`PASS: refused`) |
| srv1 upgrades to the 2.chp server packages | kanidm-server, step-ca, step-cli at 2.chp | **PASS** |
| kanidmd and step-ca after restart | active, active | **PASS** |
| Kanidm `/status`; step-ca health | `true`; `ok` | **PASS** |
| client2 upgrades to the FIPS-variant unixd, which talks to the FIPS-variant server | unixd `online`, `getent passwd lab02` | **PASS** (`Kanidm: online`; `lab02@idm.kanidm.lab.test`) |
| every kanidm, step and idm-collect package on the hosts is signed by our key | key ID 521276f43c908f8e | **PASS** (both hosts) |
| fapolicyd denials (FANOTIFY) since the test started | 0 | **PASS**: srv1 0, client2 0 |
| lab restored | golden | **PASS** (`lab reset done: srv1 client2`) |

**About the fapolicyd evidence.** `ausearch` reads *standard input* instead of the audit log when stdin is not a
terminal. The first run hung on it, and the Task 4 "0 denials" check was made the same way, so it was not evidence. All
counts here use `ausearch --input-logs … </dev/null`. A positive control on client2 (running a copied, untrusted binary)
was blocked (`Operation not permitted`) and **counted** (1), so a zero means no denial. With the fixed command, the
golden hosts (collector RPM installed) show **0 FANOTIFY events ever** on both srv1 and client2.
