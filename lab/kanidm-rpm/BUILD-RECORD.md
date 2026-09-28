# Kanidm 1.11.2 lab build record (Plan 2)

**Date:** 2026-09-27 · **Builder:** build1 (192.168.100.20), VM on aero (`br-lab`, no route off the lab)

## Build host
| Item | Value |
|---|---|
| OS | Rocky Linux 9.8 from the local DVD (kickstart `lab/kickstart/build1.ks.in`) |
| Kernel | 5.14.0-687.10.1.el9_8.0.1.x86_64 |
| FIPS | enabled (`fips=1` at install; `fips-mode-setup --check`) |
| SELinux | enforcing |
| Hardening | OpenSCAP CUI profile at install; dc2 tailoring (`user.max_user_namespaces` left default) |
| fapolicyd | **permissive** during the build (ISSO-approved deviation, `lab/vm-deviations.md`) |
| Size | 12 vCPU / 16 GB / 80 GB |
| Toolchain | Rust 1.96.0 (signed standalone installer, `/opt/rust-1.96`); gcc 11.5.0, clang 21.1.8, cmake 3.31.8, rpm-build 4.16.1.3 (DVD) |

## Inputs (sha256 in `lab/inputs/MANIFEST.txt`, re-verified on build1)
`kanidm-1.11.2.tar.gz`, `kanidm-1.11.2-vendor.tar.gz`, `rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz`

## Build (`lab/kanidm/build.sh`)
- `KANIDM_BUILD_PROFILE=release_linux`, `cargo build --locked`, `[net] offline = true`
- Features: unixd `unix,selinux`; **no `tpm`**

| Target | Seconds |
|---|---|
| kanidmd | 393 |
| kanidm | 90 |
| pam_kanidm | 39 |
| nss_kanidm | 6 |
| unixd (kanidm_unixd, kanidm_unixd_tasks, kanidm-unix) | 135 |
| ssh (kanidm_ssh_authorizedkeys, _direct) | 59 |
| **Total** | **722 (~12 min)** |

### Binary sha256
```
d9974b65d12194a8f2b8e682aafbab9f1caa495f444b576e341cf900cc14d570  kanidmd
05bb669cc8c4ab4dd0534561965970ade02ee82ef501c4f4a307aa1943391688  kanidm
ff8cddda3f4592612eaa890524eaad8dc25b441c85420030a2ecffba01e8d729  kanidm_unixd
0fde87c5d33b1455de16f08af6d57d45ba7b16861b9322b18c4c76f285b9ab1a  kanidm_unixd_tasks
4cad1681029435f6c275c13ba77f9b3f5bab744d3191f192eafc7d1ec68ab087  kanidm-unix
d282ce403896bc09896545b552a8d5cb5f65f206c6a46d9e5f697523e05ea1e6  kanidm_ssh_authorizedkeys
c9f317af00f62e0a9f113ca8d7af35429b2101eff124ef6718f0ec2799466d83  kanidm_ssh_authorizedkeys_direct
2be6f12d7723a1beac4fa67e2179252f74f12d1ca81b73e7767d4e67d08b85ff  libpam_kanidm.so
bfb90dfd3ac8eee8faf6e9e024ec00d00d80228985d73a5a7b93ba1d72dbb7c8  libnss_kanidm.so
```

## Packages (`lab/kanidm-rpm/kanidm.spec`, `build-rpms.sh`)
| RPM | Files | sha256 |
|---|---|---|
| kanidm-server-1.11.2-1.lab.el9.x86_64.rpm | 55 | `1069ab3723f1195e7208dae9a3b3dc2a090714802f20102cbe150246bce61e99` |
| kanidm-clients-1.11.2-1.lab.el9.x86_64.rpm | 11 | `3f9aed357e613f86c1913dc206f661d20613677fd28c19c84d3c1ffeaef6ead4` |
| kanidm-unixd-1.11.2-1.lab.el9.x86_64.rpm | 19 | `65d85b2cb72e305beb7fefcc465d0e023b65f66f41de0248b98114c029682f31` |

- Expected-file check (`expected-files.txt`): all present.
- `rpm -K`: digests OK. The packages are unsigned by design (lab).
- rpmlint 1.11: **0 errors, 29 warnings** (unstripped binaries, no documentation, MPL-2.0 missing from rpmlint's licence list, URL unreachable offline, spelling).
- `systemd-analyze verify`: only "binary not found" (the packages are not installed on build1).
- Published to aero `lab-local` (`/data/lab-inputs/rpms`, createrepo_c); `dnf repoquery --repo lab-local` lists all three.
