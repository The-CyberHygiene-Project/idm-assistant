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

## 8. Runtime (Plan 3, 2026-09-27): the RPMs installed and running on dc2-hardened VMs

**Result:** our RPMs install from the lab repo and run on **srv1** (Kanidm server) and **client2** (unixd, PAM/NSS). Both VMs have FIPS on, SELinux enforcing, the CUI profile, and **fapolicyd enforcing throughout**. **fapolicyd logged 0 denials** on both. The Plan 2 expectation holds: RPM-installed binaries are trusted and run; hand-copied ones would be blocked.

The end-to-end chain works:
- BIND;
- step-ca, which issues Kanidm's TLS certificate over ACME, with auto-renewal proven (the served serial changes);
- Kanidm;
- client2 login over SSH with the POSIX password, and with an SSH certificate from the separate SSH CA.

### Runtime defects (continuing the numbering)

| # | Where | Symptom | Cause | Fix |
|---|---|---|---|---|
| D6 | kanidmd unit | `Configuration Parse Failure: Permission denied` | the upstream unit uses `DynamicUser`; `server.toml` was root-only | `server.toml` 0644 (it holds no secrets) |
| D7 | kanidmd unit | `Unable to read metadata for TLS chain … /run/credentials/kanidmd.service/… Permission denied` | `LoadCredential=` was unreachable inside **this** unit on systemd 252 (`/run/credentials` mode 000). It works for kanidm-unixd and in minimal tests, including one with kanidmd's capability and directory options. Root cause not isolated | a root pre-start step (`ExecStartPre=+install -o kanidmd -m 0400 …`) copies the chain and key into the unit's own `RuntimeDirectory` |
| D8 | srv1 | Kanidm CLI: `Failed to parse config … Permission denied` | root-written files came out 0600 under the CUI profile (the CLI config; the CA anchor copied with `cp` kept step's 0600) | explicit `install -m 0644` / `chmod 0644` for non-secret config and public certificates |
| D9 | client2 NSS | Kanidm users log in without their Kanidm groups (`id` shows only the primary group), so group-based login rules and sudo break | the CUI authselect profile pins **`initgroups: files`** | put `kanidm` first on `initgroups` too (tested patcher) |
| D10 | SSH CA | `Certificate invalid: name is not a listed principal` | unixd names users by SPN (`user@idm.kanidm.lab.test`), and sshd matches principals against that | sign certificates for both forms (`sign-user-cert.sh`). Alternative for dc2: unixd `uid_attr_map = "name"` for short names |
| — | client2 SELinux | **360 AVC denials** (`lab/selinux/client2-avc-enrol.txt`): 254 `sock_file write` on `var_run_t` (`sshd_t`, `chkpwd_t`, `systemd_logind_t`, `auditd_t`) and 106 `connectto` (`init_t` → `unconfined_service_t`), all on `/run/kanidm-unixd/sock` | Kanidm ships no SELinux policy (upstream says so); the socket is generic `var_run_t` and unixd runs unconfined | **ISSO option A:** the lab-only module `lab/selinux/kanidm_lab.te` gives the socket directory its own type, usable only by `nsswitch_domain`: **narrow**. The `connectto` rule is **broad**: every `nsswitch_domain` may connect to *any* `unconfined_service_t` stream socket whose file it can reach; SELinux can't tie `connectto` to one socket while unixd is unconfined. A proper fix confines unixd in its own domain; that's out of lab scope and belongs in the ISSO's dc2 decision. 0 AVCs afterwards. Upstream's alternative (`semanage permissive -a unconfined_service_t`) was not used |

**Client configuration choices:**
- a copy of the **CUI `hardening` authselect profile**, not stock `sssd`, so `with-faillock` and `without-nullok` are kept and verified by the script;
- `pam_kanidm` directly before `pam_unix` in auth, account and session;
- NSS order `kanidm files systemd` (upstream: Kanidm first, systemd last);
- the unixd service-account token passed via the upstream-documented `LoadCredential` (works for unixd).

An operator error of mine, caught and fixed within minutes: the first client run selected the new profile **without** its features, briefly re-allowing `nullok`. The script now refuses to continue if any feature is lost.

**On a CHP-kit host (Plan 4, client1):** the same RPMs and enrolment work. Three more client-side facts:
- (1) In the **stock `sssd` authselect profile**, `pam_localuser [default=1]` skips the next line for non-local users. A `pam_kanidm` placed directly before `pam_unix` is never reached by Kanidm users. The enrolment patcher now places it where no jump can skip it (tested).
- (2) `pam_kanidm` also authenticates **local** accounts, through unixd's system provider (`/etc/shadow`).
- (3) Kanidm homes are **UUID-named** directories with an SPN-named alias (`home_root_t`; `restorecon` would relabel it `user_home_dir_t`).

Details: `lab/chp-findings.md`.

**Minor:** unixd warns at every start, "DB folder /var/cache/kanidm-unixd has 'everyone' permission bits in the mode". The upstream unit's `UMask=0027` doesn't cover the `CacheDirectory` it creates. Worth a `CacheDirectoryMode=0750` drop-in on dc2.

**Virtual TPM + LUKS/clevis:** see `lab/tpm-luks-experiment.md` (unattended unlock works; PCR-mismatch refusal proven; lab PCRs are all-zero under SeaBIOS).

### ADR spike defects, status after Plan 3

| Spike defect | Status |
|---|---|
| #1 build profile | avoided (Plan 2) |
| #2 `StateDirectory` | avoided (upstream units) |
| #3 nsswitch ordering | **confirmed as a real risk and more than ordering:** upstream order used for passwd/group, *and* the CUI profile's `initgroups: files` must also change (D9) |
| #4 separate POSIX password | **confirmed:** Linux login accepts only the POSIX ("unix") password; the Kanidm primary password is refused |
| #5 | candidates from this run: D7 (credentials in the kanidmd unit) and D10 (SPN principal names) |

### SELinux (for the ISSO, spec §9 question 2)

The **server-side** daemons (kanidmd, step-ca) run as `unconfined_service_t`, so SELinux does not confine them. There are 0 AVCs because they are *unconfined*, not because a policy allows them. The **client-side** denials are real and block logins until a policy is loaded (see the table).
