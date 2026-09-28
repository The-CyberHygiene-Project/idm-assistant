# ADR 0001 Q2: Is Kanidm's cryptography FIPS-validated?

**Status:** complete for Plan 2 (2026-09-27): static inventory, build-time linked crates and FIPS-variant experiment. Runtime behaviour on a FIPS host: Plan 3.

## Finding (static)

Kanidm 1.11.2 links **no OpenSSL**. TLS and primitives use **rustls + aws-lc-rs (non-FIPS AWS-LC build)**, plus `ring` (listed in the lock but **not linked**, see below); password hashing uses RustCrypto `argon2`. None of Kanidm's cryptography passes through Rocky's FIPS-validated OpenSSL provider, **regardless of the host's FIPS mode**.

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

Measured on build1 (Rocky 9.8, FIPS mode, 2026-09-27) with `cargo tree -e normal` over exactly what we build and ship (`daemon`, `kanidm_tools`, `pam_kanidm`, `nss_kanidm`, `kanidm_unix_int --features unix,selinux`); 489 crates in total. The crypto crates **actually linked**:

| Family | Linked crates |
|---|---|
| AWS-LC (**non-FIPS** build) | `aws-lc-rs 1.18.0`, `aws-lc-sys 0.44.0`, via `rustls 0.23.43` |
| RustCrypto (not CMVP-validated) | `aes-gcm 0.10.3`, `argon2 0.5.3`, `blake2 0.10.6`, `ecdsa 0.16.9`, `hkdf 0.12.4`, `hmac 0.12.1` + `0.13.0-rc.5`, `md-5 0.10.6`, `p256 0.13.2`, `p384 0.13.1`, `pbkdf2 0.12.2` + `0.13.0-rc.9`, `rsa 0.9.10`, `sha1 0.10.7`, `sha2 0.10.9` + `0.11.0-rc.5` |
| OpenSSL | **none**. `openssl-probe` is linked, but it only locates the system CA-certificate files; it performs no cryptography |
| Not linked, although listed in `Cargo.lock` | `ring`, `tss-esapi` (TPM), `aes`, `cbc`, `ctr`, `p521` |

**Conclusion (build-time):** the static finding holds for the binaries we ship. TLS runs on a non-FIPS AWS-LC; hashing, signatures, HMAC, key derivation and password hashing run on RustCrypto. Nothing uses the host's FIPS-validated OpenSSL.

## FIPS-variant experiment (rustls → AWS-LC FIPS module)

**Outcome: it builds.** The variant is Kanidm 1.11.2 with one line added to the workspace `Cargo.toml` (`lab/kanidm/fips-variant.patch`: rustls feature `"fips"`).
- `cargo fetch` added exactly one crate, `aws-lc-fips-sys 0.14.2`; every other pin was unchanged.
- It built offline on build1 (FIPS mode) in ~8 min (kanidmd 401 s, kanidm 90 s), using the DVD's Go, cmake and perl.
- The inventory tool on the variant lock reports: `AWS-LC FIPS module present: yes`.

**What is inside the binary:** `strings kanidmd` shows **`AWS-LC FIPS 4.2.0`**.

`aws-lc-rs 1.18.0` selects its backend at compile time (`src/lib.rs`: `#[cfg(feature = "fips")] extern crate aws_lc_fips_sys as aws_lc;`). With the feature on, **every aws-lc-rs operation (so all of rustls' TLS) is routed to the AWS-LC FIPS module's code.** That says where the code runs, not that it runs in a validated, approved mode (see the checks below).

The non-FIPS `aws-lc-sys 0.44.0` is still compiled and linked. `reqwest` → `hyper-rustls` requests aws-lc-rs' default features, but nothing calls it any more. Removing it would need feature changes in those crates. It is dead code, and an assessor may still ask about it.

**What stays outside the FIPS module even in the variant:**

| Function | Implementation | Note |
|---|---|---|
| Password hashing | RustCrypto `argon2` | **Argon2 is not a FIPS-approved algorithm** at all; the FIPS-approved alternative is PBKDF2 |
| Hashes, HMAC, HKDF, PBKDF2, AES-GCM, ECDSA P-256/384, RSA used directly by Kanidm (tokens, WebAuthn/COSE, key objects) | RustCrypto crates | Not a CMVP-validated module |
| TLS (server and outbound HTTPS) | rustls → AWS-LC FIPS 4.2.0 | Runs in the module's code; **approved-mode operation unverified** (e.g. X25519 or ChaCha20-Poly1305 can run in the module but are not FIPS-approved for this use) |

**Before claiming validation**, the ISSO must check the following (not verifiable offline here):
1. That "AWS-LC FIPS 4.2.0" appears on the **NIST CMVP** validated or in-process list, and under what certificate.
2. That building it from source with `aws-lc-fips-sys` follows that certificate's **Security Policy** (build procedure, compiler, operating environment).
3. Whether rustls' `ServerConfig::fips()` reports true at runtime. That is a Plan 3 check.

**Implication for 3.13.11:** the variant routes **TLS** through the AWS-LC FIPS module's code with a one-line change, but Kanidm's own application cryptography, **including password hashing**, stays outside it. The honest SSP position today is: "TLS: AWS-LC FIPS 4.2.0 module built from source; CMVP certificate, Security Policy build conformance and approved-mode operation **unverified** (checks 1-3 above; Plan 3). Application crypto: not FIPS-validated → risk acceptance / POA&M", unless upstream Kanidm changes.
