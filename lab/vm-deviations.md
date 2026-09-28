# Lab VMs: deviations from dc2's kickstart

| VM | Deviation | Why |
|---|---|---|
| build1 | install from local DVD (`cdrom`), not `url` to the internet | lab is offline |
| build1 | **no LUKS** on the logical volumes | unattended boot of a disposable build VM (LUKS + virtual-TPM unlock via clevis is a Plan 3 experiment) |
| build1 | static 192.168.100.20/24, no default route, no DNS | lab network |
| build1 | `rootpw --lock`; `itadmin` SSH-key login + passwordless sudo | Mac drives the build over SSH |
| build1 | chrony → 192.168.100.1 (aero) | lab time source |
| build1 | minimal environment + compilers (dc2 is graphical-server) | build host only; never runs identity services |
| build1 | 12 vCPU / 16 GB during Plan 2 (spec: 6 / 8) | only VM on aero; shortens the compile |
| build1 | **fapolicyd `permissive = 1`** during Plan 2 builds (ISSO-approved 2026-09-27); still logs every would-be denial | CUI fapolicyd blocks the non-RPM Rust toolchain and every build-script binary cargo creates. **Revert:** `permissive = 0` + restart fapolicyd after the build |
| all | `sysctl_user_max_user_namespaces` left as dc2 tailoring has it (unselected) | mirror dc2 |
