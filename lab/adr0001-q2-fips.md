# ADR 0001 Q2: Is Kanidm's cryptography FIPS-validated?

**Status:** static half done 2026-09-27 (Plan 2, Task 4). Build-time confirmation and FIPS-variant experiment: see the sections below as they're completed. Runtime behaviour on a FIPS host: Plan 3.

## Finding (static)

Kanidm 1.11.2 links **no OpenSSL**. TLS and primitives use **rustls + aws-lc-rs (non-FIPS AWS-LC build)**, plus `ring`; password hashing uses RustCrypto `argon2`. None of Kanidm's cryptography passes through Rocky's FIPS-validated OpenSSL provider, **regardless of the host's FIPS mode**.

Consequences for the System Security Plan (NIST SP 800-171 **3.13.11**, FIPS-validated cryptography protecting CUI):
- Setting `fips=1` on the host does **not** make Kanidm's TLS, token signing or credential hashing FIPS-validated.
- **Argon2id** (password hashing) is not a FIPS-approved algorithm. Even a FIPS-module build of the TLS stack leaves it outside.
- Several RustCrypto implementations (AES-GCM, ECDSA P-256/384/521, RSA, SHA-1/2, HMAC, HKDF, PBKDF2) are in the dependency set. They are sound implementations but **not CMVP-validated modules**.

## Method

`tools/crypto_inventory.py` classifies every crate in Kanidm's `Cargo.lock` by crypto family.

**Caveat:** `Cargo.lock` lists crates for *all* features and platforms. So it over-reports: for example `tss-esapi` (TPM) is listed but isn't compiled in our build (the `tpm` feature is off). The build-time section below narrows the table to what is actually linked.

## Inventory: Cargo.lock of kanidm-1.11.2 (source tarball, sha256 pinned in `lab/inputs/MANIFEST.txt`)

| family | crate | version |
|---|---|---|
| aws-lc | aws-lc-rs | 1.18.0 |
| aws-lc | aws-lc-sys | 0.44.0 |
| other-crypto | tss-esapi | 8.0.0-alpha.2 |
| ring | ring | 0.17.14 |
| rustcrypto | aes | 0.8.4 |
| rustcrypto | aes-gcm | 0.10.3 |
| rustcrypto | argon2 | 0.5.3 |
| rustcrypto | blake2 | 0.10.6 |
| rustcrypto | cbc | 0.1.2 |
| rustcrypto | ctr | 0.9.2 |
| rustcrypto | ecdsa | 0.16.9 |
| rustcrypto | hkdf | 0.12.4 |
| rustcrypto | hmac | 0.12.1 |
| rustcrypto | hmac | 0.13.0-rc.5 |
| rustcrypto | md-5 | 0.10.6 |
| rustcrypto | p256 | 0.13.2 |
| rustcrypto | p384 | 0.13.1 |
| rustcrypto | p521 | 0.13.3 |
| rustcrypto | pbkdf2 | 0.12.2 |
| rustcrypto | pbkdf2 | 0.13.0-rc.9 |
| rustcrypto | rsa | 0.9.10 |
| rustcrypto | sha1 | 0.10.7 |
| rustcrypto | sha2 | 0.10.9 |
| rustcrypto | sha2 | 0.11.0-rc.5 |

OpenSSL present: NO · AWS-LC FIPS module present: NO

## Build-time confirmation (what is actually linked)

_Filled in by Plan 2 Task 5 (`cargo tree` on build1 for the exact targets and features built)._

## FIPS-variant experiment (rustls → AWS-LC FIPS module)

_Filled in by Plan 2 Task 8._
