# CMVP status of the cryptographic modules in the 0.1.0 repo (spec §9)

**Checked:** 2026-09-29, against the NIST CMVP validated-modules search, the certificate pages, their Security
Policies (SP), and the Modules-In-Process (MIP) list. This records what those sources say. Whether it is enough is
the ISSO's judgment.

| Our component | Module in our build | CMVP status found | Matches our build? |
|---|---|---|---|
| Kanidm TLS: kanidmd, CLI, unixd (`kanidm-*-1.11.2-2.chp`) | **AWS-LC FIPS 4.2.0** (`aws-lc-fips-sys 0.14.2`, built from source by Cargo) | **Not on an active certificate.** Active AWS-LC certificates cover *other* versions: #5146 = "AWS-LC FIPS 1.29.1" (dynamic, validated 2026-01-26, sunset 2031-01-25); #5429 = "AWS-LC FIPS 2.0.0" (dynamic, 2026-07-20, sunset 2029-08-13); #5314 / #5298 = "AWS-LC 3" (static / dynamic, June 2026); #4816, #4631 older. **In process:** "AWS-LC 4 Cryptographic Module (dynamic)", *Comment Resolution – CMVP*, 2026-09-16; "(static)", *Comment Resolution – Lab*, 2026-08-14. | **No**: 4.2.0 is at most *in process* (the MIP list shows no version; whether "AWS-LC 4" includes 4.2.0 is **not verified**). The certificates' caveats also require installation and configuration per SP §11.1 and approved-mode operation. **Not verified** for our Cargo source build. |
| step-ca / step-cli (`step-ca-0.30.2-2.chp`, `step-cli-0.31.0-2.chp`) | **Go Cryptographic Module v1.0.0**, snapshot `v1.0.0-c2097c7c` (`GOFIPS140=v1.0.0`, go1.26.8) | **Validated: certificate #5247**, Geomys LLC, "Go Cryptographic Module", FIPS 140-3 Level 1, initial 2026-04-27, updated 2026-07-07, sunset 2031-04-26. The SP covers "v1.0.0 and v1.0.1", and the module identified as the binary compiled from `v1.0.0-c2097c7c.zip`. Tested environments include **Linux 3.10+ through 7.x on x86-64**. A newer Geomys "Go Cryptographic Module" is in process (*Comment Resolution – CMVP*, 2026-09-10). | **Likely yes**: same snapshot, and Linux x86-64 is a tested environment. **Not verified:** the SP's full build and approved-mode conditions against our build (CGO off, `fips140=on`, not `only`). Caveat: "When operated in approved mode." |
| Rocky Linux 9 OS crypto (OpenSSL, used by the OS, sshd, curl, …) | Rocky 9.8 `openssl` FIPS provider (RESF packages) | Certificate **#5116**, Ctrl IQ, Inc., "Rocky Linux 9 OpenSSL FIPS Provider", FIPS 140-3 Level 1, validated 2026-01-06, sunset 2031-01-05. Other active Ctrl IQ certificates: Rocky 9 GnuTLS (#5496), Kernel Crypto API (#5452, #5113), Rocky 8+9 NSS (#5337), libgcrypt (#5117). | **Not verified:** which package builds and versions #5116 covers, and whether the stock RESF Rocky 9.8 packages on the ISO are those builds. Check the SP's version table before claiming it. |

## Still outside any FIPS module (POA&M, 3.13.11)

- Kanidm **Argon2** password hashing and **TOTP HMAC-SHA256** (RustCrypto), in every build (Plan 2/3 finding).
- The non-FIPS `aws-lc-sys` crate is still compiled into the Kanidm binaries as unused code (Plan 2 finding). An assessor may ask about it.

## Draft SSP text for ISSO #14 (for the ISSO to edit)

> **Kanidm (identity service and client daemon).** Network TLS for the Kanidm server, the Kanidm command-line
> tool and the client resolver daemon (`kanidm_unixd`) is performed by the AWS-LC FIPS 4.2.0 module, built from source.
> As of 2026-09-29, AWS-LC FIPS 4.2.0 is not on an active CMVP certificate; an "AWS-LC 4 Cryptographic Module" is on the
> Modules-In-Process list (Comment Resolution). Kanidm's application cryptography (Argon2 password hashing and TOTP
> HMAC-SHA256) is implemented outside any FIPS-validated module. Both are tracked as POA&M items against 3.13.11 until
> a validated module covers them or compensating controls are accepted.
>
> **step-ca (internal PKI).** step-ca and the step CLI are built with the Go Cryptographic Module v1.0.0 (CMVP
> certificate #5247) and run in FIPS 140-3 mode (`GODEBUG=fips140=on`). Conformance of the build to the module's
> Security Policy is to be confirmed.

## Sources (checked 2026-09-29)
- CMVP search, module name "AWS-LC", "Go Cryptographic" and "Rocky" (active): csrc.nist.gov validated-modules search
- Certificates: [#5146](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5146), [#5429](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5429), [#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314), [#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247), [#5116](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5116)
- Security Policies read for versions: 140sp5146.pdf (1.29.1), 140sp5429.pdf (2.0.0), 140sp5247.pdf (Go v1.0.0/v1.0.1, `v1.0.0-c2097c7c.zip`, Linux x86-64)
- [Modules In Process list](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list)
