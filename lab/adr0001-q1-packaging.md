# ADR 0001 Q1: Can Kanidm be built and packaged for Rocky 9, offline?

**Date:** 2026-09-27 · **Plan:** `docs/superpowers/plans/2026-09-27-plan2-kanidm-build-package.md` · **Build record:** `lab/kanidm/…` scripts + `lab/kanidm-rpm/BUILD-RECORD.md`

## 1. Answer

**Yes.** Kanidm 1.11.2 was built from pinned, hash-verified source on a **FIPS-mode, SELinux-enforcing, CUI-hardened Rocky 9.8** machine with **no network route off the lab** in about **12 minutes** (12 vCPU). It was packaged as three RPMs (`kanidm-server`, `kanidm-clients`, `kanidm-unixd`) that pass an explicit file-list check and rpmlint with 0 errors. The recipe is fully scripted and repeatable (kickstart → VM → build → RPM → lab repo).

**One condition matters for dc2:** the CUI profile's **fapolicyd** application allow-list blocks the build outright (see §4, D1). Building on a production-hardened host needs either an ISSO-approved relaxation on a dedicated build machine (what we did) or a targeted trust policy. It follows that **Kanidm should reach dc2 as RPMs built elsewhere, not be compiled on dc2.** fapolicyd trusts RPM-installed files, so packaged binaries are **expected** to run under enforcement, while hand-copied ones are blocked (observed on build1). The expectation is proven only by the Plan 3 install test.

## 2. Environment

| Item | Value |
|---|---|
| Build VM | build1, installed unattended from the Rocky 9.8 DVD by `lab/kickstart/build1.ks.in` (derived from dc2's `anaconda-ks.cfg`) |
| Posture | `fips=1`; SELinux enforcing; OpenSCAP CUI profile applied at install; dc2 tailoring mirrored; root locked |
| Network | 192.168.100.20/24, **no default route, no DNS**; cargo `net.offline = true` |
| Toolchain | Rust 1.96.0 (signed standalone installer; the DVD's Rust 1.92 is below Kanidm's MSRV); gcc/clang/cmake/rpm-build from the DVD |
| Deviations | `lab/vm-deviations.md` (no LUKS, lab IP, NOPASSWD sudo, **fapolicyd permissive during the build**) |

## 3. Procedure (all in this repo)

1. `lab/host/b7-vm-build1.sh`: unattended install (≈7 min), then a `golden` snapshot.
2. `lab/vm/push-build1.sh`: copies the inputs and re-verifies their sha256 on build1.
3. `lab/kanidm/build.sh`: the Makefile's `release/*` targets with `KANIDM_BUILD_PROFILE=release_linux`, `--locked`, unixd `+selinux`.
4. `lab/kanidm-rpm/build-rpms.sh` + `kanidm.spec`: binary-repack RPMs, then the expected-file check.
5. Copied to aero's `lab-local` repo (createrepo_c).

## 4. Defects found (in order of discovery)

| # | Where | Symptom | Cause | Fix / ruling |
|---|---|---|---|---|
| D1 | build1 (CUI **fapolicyd**) | `rustc: Operation not permitted` | fapolicyd (CUI profile; also in dc2's kickstart) denies executables not installed by RPM. A Rust build runs **86 freshly compiled build-script programs** and loads **49 compiler plug-in libraries**. With the **16 files** of the Rust toolchain, **none are in the trust database** | ISSO approved `permissive = 1` on build1 for the build only (logged, reverted afterwards). **Reverting needs a reboot:** after `permissive = 0` and a service restart, `rustc`, which had run while permissive, still executed, while never-run untrusted programs were blocked; after a reboot it was blocked too. **Packaging needs it too:** with enforcement restored, `rpmbuild`'s staging `cp` could not even *read* the freshly built `libpam_kanidm.so`/`libnss_kanidm.so` (`Operation not permitted`). The CUI rules deny opening untrusted shared libraries for any purpose. Note: permissive mode writes **no** audit records, so the count above comes from the build tree, not the audit log |
| D2 | kickstart | Installer crashed: `Invalid IPv6 address 'ignore'` | `network --ipv6=ignore` passes `ksvalidator` but NetworkManager rejects it | `--noipv6`. **Lesson:** ksvalidator checks syntax only; a kickstart is proven only by an install |
| D3 | kickstart / CUI | `user.max_user_namespaces = 0` although dc2's tailoring unselects that rule | The CUI profile applied **at install** writes the sysctl file, and it is copied into the **initramfs** before `%post` runs | `%post` deletes the file **and** runs `dracut -f --regenerate-all`. **Relevant to dc2:** tailoring a rule out *after* an install-time profile does not undo it; the file and the initramfs copy remain |
| D4 | aero libvirt | `Unable to open file …build1-install.log: Permission denied` | SELinux: qemu may not write to `default_t` under `/data/libvirt` | Serial log to `/var/log/libvirt/qemu/` (`virt_log_t`) |
| D5 | RPM spec | rpmlint `postin/postun-without-ldconfig` | The NSS module in `/usr/lib64` needs the linker cache refreshed | `/sbin/ldconfig` in `%post`/`%postun` of `kanidm-unixd` |

**No problem** was found with: the vendored crate set (the build never needed the network), the build profile (all `release_linux` paths are compiled in; checked with `strings`), the `selinux` feature (unixd links `libselinux`), or FIPS mode breaking gcc/clang/cmake/rpmbuild.

### Against the ADR's known spike defects

| Spike defect | Plan 2 status |
|---|---|
| #1 build-profile flag | **Avoided:** `KANIDM_BUILD_PROFILE=release_linux` is set by the script, and the compiled-in paths are verified before packaging |
| #2 `StateDirectory` missing from units | **Avoided:** the upstream `platform/opensuse` units already declare `StateDirectory` (and `DynamicUser`) |
| #3 nsswitch ordering | Client configuration, so **Plan 3** |
| #4 separate POSIX password | Account configuration, so **Plan 3** |
| #5 (unconfirmed) | Not reproduced in the build; still open for Plan 3 |

## 5. Choices made

- **Profile** `release_linux`: `/etc/kanidm/{server.toml,config,unixd}`, UI at `/usr/share/kanidm/ui/hpkg` (from `server/core/static`, as upstream's container does).
- **Features:** unixd `unix,selinux`; **no `tpm`** (clients only; `tpm2-tss-devel` isn't on the DVD; virtual-TPM test deferred to Plan 3).
- **Units:** upstream `platform/opensuse/*.service`, unmodified.
- **Packaging:** binary repack (build once, package the outputs). The packages are unsigned: a lab repo on an isolated network, with integrity from the recorded sha256. **For dc2, sign the RPMs** with an organisational key, so `gpgcheck` stays on (see aero's `ensure_gpgcheck_never_disabled` finding).
- rpmlint warnings accepted for the lab: 29 (e.g. unstripped binaries, no docs).

**FIPS variant** (Q2 experiment): a one-line `Cargo.toml` change (rustls `fips`) also builds offline under the same conditions (~8 min for kanidmd + kanidm) and routes TLS through **AWS-LC FIPS 4.2.0**. So the build procedure does not block a FIPS-module build (the variant was built, not packaged). See `adr0001-q2-fips.md` for what remains outside the module.

## 6. Timings

~7 min unattended install; **~12 min** full Kanidm build (kanidmd 393 s, kanidm 90 s, pam 39 s, nss 6 s, unixd 135 s, ssh 59 s); RPM packaging < 1 min. This is the recurring cost of every Kanidm upgrade.

## 7. What Plan 3 must verify at runtime

- `kanidmd` starts under FIPS + SELinux enforcing + **fapolicyd enforcing**, installed from these RPMs. That proves the "RPMs are trusted" claim.
- The SELinux context for `DynamicUser` services and `/var/lib/private/kanidm`, and for the home directories unixd creates.
- nsswitch ordering (#3), POSIX password (#4), whatever #5 turns out to be.
- TLS with a step-ca certificate. Runtime FIPS behaviour of the non-FIPS AWS-LC (see `adr0001-q2-fips.md`).
- Virtual-TPM experiments: `swtpm`, the Kanidm `tpm` feature, LUKS + `clevis` TPM2 unlock.
