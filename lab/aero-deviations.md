# aero: deviations from the standard workstation build

aero is a disposable, offline lab asset (no CUI, lab cable only). Fidelity settings
(FIPS, SELinux enforcing, CUI profile) are kept. Every convenience change is listed here.

| Date | Change | Why | How to revert |
|---|---|---|---|
| 2026-09-26 | Wi-Fi radio disabled (`nmcli radio wifi off`) | lab must be offline | `nmcli radio wifi on` |
| 2026-09-26 | `/etc/sudoers.d/90-itadmin-lab`: `itadmin ALL=(ALL) NOPASSWD: ALL` | Mac drives setup over SSH; approved by the ISSO | `rm /etc/sudoers.d/90-itadmin-lab` |
| 2026-09-27 | ALL non-lab dnf repos disabled (Rocky baseos/appstream/extras + claude-code, cuda-rhel10-x86_64, epel, epel-cisco-openh264, google-chrome, rpmfusion-free/nonfree-updates, wazuh; list saved in `/etc/yum.repos.d/.lab-disabled-repos`); lab-baseos/appstream (DVD loop-mounted via fstab) + lab-local added | aero is offline; online repos make dnf fail | set `enabled=1` in the listed .repo files; remove `lab.repo` and the fstab DVD line |

**Observed on the standard build (not changed):** aero had a `cuda-rhel10-x86_64` repo enabled on a Rocky **9** host (EL10 CUDA repo on EL9), which looks like a misconfiguration worth checking on the other workstations. A Wazuh agent repo is present (the agent will be offline in the lab).
