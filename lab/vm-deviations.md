# Lab VMs: deviations from dc2's kickstart

| VM | Deviation | Why |
|---|---|---|
| build1 | install from local DVD (`cdrom`), not `url` to the internet | lab is offline |
| build1 | **no LUKS** on the logical volumes | unattended boot of a disposable build VM (LUKS + virtual-TPM unlock via clevis is a Plan 3 experiment) |
| build1 | static 192.168.100.20/24, no default route, no DNS | lab network |
| build1 | `rootpw --lock`; `itadmin` SSH-key login + passwordless sudo | Mac drives the build over SSH |
| build1 | chrony → 192.168.100.1 (aero) | lab time source |
| build1 | minimal environment + compilers (dc2 is graphical-server) | build host only; never runs identity services |
| build1 | 12 vCPU / 16 GB during Plan 2 (spec: 6 / 8) | only VM on aero; shortens the compile. **Reverted** 2026-09-27: back to 6 vCPU / 8 GB (snapshot `built`) |
| build1 | **fapolicyd `permissive = 1`** during Plan 2 builds (ISSO-approved 2026-09-27); still logs every would-be denial | CUI fapolicyd blocks the non-RPM Rust toolchain and every build-script binary cargo creates. **Reverted** 2026-09-27 (`permissive = 0`, restart **and reboot**: executables allowed while permissive kept running after the restart until the reboot). Re-applied once more (ISSO-approved) for the post-review RPM rebuild, then restored to enforcing and rebooted |
| srv1, client2 | installed from `lab/kickstart/base.ks.in` (derived from build1's kickstart): same FIPS/CUI/tailoring/sudo/chrony choices; smaller LVM layout (/var grows) | 30–60 GB lab disks |
| srv1, client2 | `lab-local` repo with `gpgcheck=0` (DVD repos keep gpgcheck=1); vendor online repos disabled | our lab RPMs are unsigned (ISSO-approved 2026-09-27); integrity from BUILD-RECORD sha256 |
| client2 | software TPM 2.0 (swtpm, `tpm-crb`) and a second 2 GB disk (`vdb`) for the LUKS/clevis experiment | Plan 3 Task 11 (swtpm was already on aero as a libvirt dependency) |
| client2 | **lab-only SELinux module `kanidm_lab`** (+ fcontext `/var/run/kanidm-unixd(/.*)?` → `kanidm_unixd_var_run_t`); ISSO option A, 2026-09-27 | Kanidm ships no SELinux policy; 315 AVCs blocked NSS/PAM clients from the unixd socket. Revert: `semodule -r kanidm_lab; semanage fcontext -d '/var/run/kanidm-unixd(/.*)?'` |
| client2 | authselect `custom/kanidm` = copy of the CUI `custom/hardening` profile + Kanidm (features with-faillock, without-nullok kept) | Kanidm client integration; revert: `authselect select custom/hardening with-faillock without-nullok` |
| srv1 | `expect` installed (DVD) | scripted Kanidm CLI logins; not a compiler |
| srv1, client2 | snapshots `os-ready`, `golden`; `lab/reset.sh` reverts to golden **and restarts chronyd** (a reverted VM's clock is rewound; chrony flags the jump "too variable") | repeatable scenarios |
| client1 | UEFI (OVMF secboot, MS keys enrolled, q35/SMM) + swtpm; 512 GB **thin** disk (`--check disk_size=off`); CHP-kit preconditions only (no CUI at install: the kit applies it); root LUKS2 bound to vTPM PCR 7 on first real boot | CHP kit test (spec §4.5); unattended lab reboots |
| client1 | `itadmin ALL=(ALL) NOPASSWD: ALL` (kickstart `%post`, as on the other VMs) | lab automation. **It bypasses the CHP kit's sudo MFA; the kit's IDA-03 does not detect it (K10)** |
| client1 | pty serial console with file log (all new VMs via `vm-lib.sh`) | answer LUKS prompts via `virsh console` |
| aero | `expect` installed (DVD) | `luks-console-unlock.exp` |
| all | `sysctl_user_max_user_namespaces` left as dc2 tailoring has it (unselected) | mirror dc2 |
| build1 | **fapolicyd `permissive = 1`** for ISO Plan 1 builds (Kanidm FIPS-variant RPMs, step-ca/step-cli from source), ISSO-approved 2026-09-29 | same cause as Plan 2 (non-RPM toolchains and build scripts are untrusted). To be reverted (`permissive = 0`, restart **and reboot**) after ISO Plan 1 Task 7 |
