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
| kanidm-server-1.11.2-1.lab.el9.x86_64.rpm | 58 | `a04bd11e389afe1bef5e8714be6e0458802c27193dca7b65454a9c5541d66be9` |
| kanidm-clients-1.11.2-1.lab.el9.x86_64.rpm | 11 | `f98c998d1eb8858a2cc1b4a50b6065a47a96298e13cb5aa71899ab10b9a7d655` |
| kanidm-unixd-1.11.2-1.lab.el9.x86_64.rpm | 25 | `11946de2f433b7ab0ade5ecacb6e91eb0ccbd02e12238ceae9ee2c0da24e1325` |

(Rebuilt after the final review, fix I3: `/etc/kanidm` and `/usr/share/kanidm` directories are now owned by every package that uses them, and `kanidm_ssh_authorizedkeys` moved from `-clients` to `-unixd`, because it asks unixd. The rebuild needed fapolicyd permissive again, ISSO-approved; restored to enforcing and rebooted.)

- `check-rpms.sh`: every path in `expected-files.txt` is packaged, and every ownership rule in `expected-by-package.txt` holds.
- `rpm -K`: digests OK. The packages are unsigned by design (lab).
- rpmlint 1.11: **0 errors, 31 warnings** (unstripped binaries 9, no man pages 7, spelling 5, no documentation 3, URL unreachable offline 3, MPL-2.0 missing from rpmlint's licence list 3, no-soname on the NSS module 1).
- `systemd-analyze verify`: only "binary not found" (the packages are not installed on build1).
- Published to aero `lab-local` (`/data/lab-inputs/rpms`, createrepo_c); `dnf repoquery --repo lab-local` lists all three.
