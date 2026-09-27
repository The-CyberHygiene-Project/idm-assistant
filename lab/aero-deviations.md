# aero: deviations from the standard workstation build

aero is a disposable, offline lab asset (no CUI, lab cable only). Fidelity settings
(FIPS, SELinux enforcing, CUI profile) are kept. Every convenience change is listed here.

| Date | Change | Why | How to revert |
|---|---|---|---|
| 2026-09-26 | Wi-Fi radio disabled (`nmcli radio wifi off`) | lab must be offline | `nmcli radio wifi on` |
| 2026-09-26 | `/etc/sudoers.d/90-itadmin-lab`: `itadmin ALL=(ALL) NOPASSWD: ALL` | Mac drives setup over SSH; approved by the ISSO | `rm /etc/sudoers.d/90-itadmin-lab` |
