# Kanidm 1.11.2-2.chp build record (ISO Plan 1 Task 5): FIPS TLS variant

**Date:** 2026-09-29 · **Builder:** build1 (192.168.100.20), VM on aero, lab bridge only

## Build host
| Item | Value |
|---|---|
| OS / kernel | Rocky Linux 9.8 (local DVD) / 5.14.0-687.10.1.el9_8.0.1.x86_64 |
| FIPS / SELinux | `FIPS mode is enabled.` / Enforcing |
| fapolicyd | **permissive** for this build (ISSO-approved 2026-09-29, `lab/vm-deviations.md`); reverted with a reboot after Task 7 |
| Size | 6 vCPU / 8 GB |
| Toolchain | Rust 1.96.0 (`/opt/rust-1.96`, signed standalone installer, Plan 2) |

## Inputs (sha256 pinned in `lab/inputs/MANIFEST.txt`, re-checked on build1)
- `kanidm-1.11.2.tar.gz`: `a8ed31203e5f8c036b9cb261c85ddac19291bc6ca16981495495cd9621c56529`
- `kanidm-1.11.2-fips-vendor.tar.gz`: `ae5bf81a424358f99c634354bdef3d4af20763ef18ea577d424124a7d3d39e59` (Plan 2 variant: rustls `"fips"` in the workspace `Cargo.toml`, its `Cargo.lock`, matching vendor set)
- `client-fips.patch` (this directory), applied by `build.sh`

## Finding: the one-line variant covered only the server

With only the Plan 2 variant, `check-fips.sh` found `AWS-LC FIPS 4.2.0` in `kanidmd` but **not** in `kanidm` (CLI) or
`kanidm_unixd`. Their TLS comes through `kanidm_client` → `reqwest` → `hyper-rustls` (`aws-lc-rs` backend), and
rustls' `"fips"` feature was on only for crates that use the **workspace** rustls, which `kanidm_client` did not. So
the client side of every unixd→server TLS session ran on the non-FIPS AWS-LC.

**Fix (user-approved 2026-09-29, ISSO #14):** `client-fips.patch` adds `rustls = { workspace = true }` to
`libs/client/Cargo.toml`. Cargo's feature unification then builds the single rustls/aws-lc-rs in the unixd and CLI
graphs with `"fips"`. `cargo update --offline --workspace` reported *Locking 0 packages*. The only `Cargo.lock` change is
the new `kanidm_client → rustls` edge: no crate added, removed or re-versioned, and nothing new downloaded.

A second, unrelated problem: the first `check-fips.sh` reported `kanidmd` as NOT FIPS as well. That was a false negative,
because `strings | grep -q` under `pipefail` fails on SIGPIPE. It is fixed by grepping a saved `strings` dump.

## Build (`build.sh`, from a fresh patched tree)
| Target | Seconds |
|---|---|
| kanidmd | 288 |
| kanidm | 98 |
| pam_kanidm | 1 |
| nss_kanidm | 1 |
| unixd (kanidm_unixd, kanidm_unixd_tasks, kanidm-unix) | 91 |
| ssh (kanidm_ssh_authorizedkeys, _direct) | 36 |

(The target cache from Plan 2's variant experiment was reused. A cold build is about 12 minutes.)

### Binary sha256 (build tree, before rpmbuild strips them)
```
83f24246ac2d9324806571fe5a16f0a53740e617233b8a4fa78764670bd07c97  kanidmd
4cc5af1a3f58c6f5d26bd7d629bbebdf15e67d097fcabb4bbd91ca02a17d2546  kanidm
a39a5fe6c3f37020ff27b48fe857a904dab04b448b387956c62766b183c35d56  kanidm_unixd
170947f1cb4b841718a527d8f29a79d3af0ba79969d7d0e4d5f150255e71918d  kanidm_unixd_tasks
70aa7161fb7abef54dfa14b8c8ecf522a1132cd3235b7cc1f498d304dc8956e8  kanidm-unix
13d4bf30fe745f1144e846decb1156b87756d220b7698e56ff0dfb6483006b7d  kanidm_ssh_authorizedkeys
3ccf0151f1420887b818151a042ff35e6840907f1527c82348b111c95abd14fc  kanidm_ssh_authorizedkeys_direct
6139176f9fc8f55ec653b89d011300fcb09e6acc0054941cf347e9354c5c1dac  libpam_kanidm.so
a6ec8b9a183caa500438552051f00df4edba8ce51371c6f3285cc3f6ebdb317e  libnss_kanidm.so
```

## Packages (`kanidm.spec`, `build-rpms.sh`), unsigned here; signed in Task 8
| RPM | Files | sha256 |
|---|---|---|
| kanidm-server-1.11.2-2.chp.el9.x86_64.rpm | 59 | `e7f20b7e729064b96e11dbd8d4e45a801465ec53035ca5cbc201a932cd37e5ee` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64.rpm | 12 | `9e4719e4db7177dfc4d6e8927f73ea27451d93efa7581dc97ed3a2ff3070171f` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64.rpm | 26 | `0621ceaab77c7f539200f0f6bc327642053adc9b63cab05ef510ff6e2cc42bbd` |

- `check-rpms.sh`: `RPMS OK: all expected files packaged and owned (1.11.2-2.chp.el9)`. Each package gained
  `/usr/share/licenses/kanidm/LICENSE.md` (MPL-2.0).
- `check-fips.sh` (on the binaries **inside the RPMs**): `FIPS OK` for `usr/sbin/kanidmd`, `usr/bin/kanidm` and
  `usr/sbin/kanidm_unixd`, giving `FIPS VARIANT OK`.
- rpmbuild strips the binaries (kanidmd 241 MB → 62 MB); the `AWS-LC FIPS 4.2.0` marker survives stripping.
- Copied to `aero:/data/chp-release/built/`.

What this does **not** establish: CMVP validation, conformance to the module's Security Policy build procedure, or
approved-mode operation at run time. Those are recorded in `appliance/release/CMVP-STATUS.md` (Task 8). Argon2 and
TOTP HMAC stay in RustCrypto (POA&M).
