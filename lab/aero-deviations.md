# aero: deviations from the standard workstation build

aero is a disposable, offline lab asset (no CUI, lab cable only). Fidelity settings
(FIPS, SELinux enforcing, CUI profile) are kept. Every convenience change is listed here.

| Date | Change | Why | How to revert |
|---|---|---|---|
| 2026-09-26 | Wi-Fi radio disabled (`nmcli radio wifi off`) | lab must be offline | `nmcli radio wifi on` |
| 2026-09-26 | `/etc/sudoers.d/90-itadmin-lab`: `itadmin ALL=(ALL) NOPASSWD: ALL` | Mac drives setup over SSH; approved by the ISSO | `rm /etc/sudoers.d/90-itadmin-lab` |
| 2026-09-27 | ALL non-lab dnf repos disabled (Rocky baseos/appstream/extras + claude-code, cuda-rhel10-x86_64, epel, epel-cisco-openh264, google-chrome, rpmfusion-free/nonfree-updates, wazuh; list saved in `/etc/yum.repos.d/.lab-disabled-repos`); lab-baseos/appstream (DVD loop-mounted via fstab) + lab-local added | aero is offline; online repos make dnf fail | set `enabled=1` in the listed .repo files; remove `lab.repo` and the fstab DVD line |

**Observed on the standard build (not changed):** aero had a `cuda-rhel10-x86_64` repo enabled on a Rocky **9** host (EL10 CUDA repo on EL9), this was the user's own experiment to enable GPU AI on aero (note: Rocky 9 needs NVIDIA's rhel9 repo, not rhel10). A Wazuh agent repo is present (the agent will be offline in the lab).
| 2026-09-27 | enp49s0 enslaved to bridge br-lab (192.168.100.1/24); "Profile 1" autoconnect off | lab VMs share the cable subnet | `nmcli con delete br-lab-port br-lab; nmcli con mod "Profile 1" connection.autoconnect yes; nmcli con up "Profile 1"` |
| 2026-09-27 | chrony: CUI `port 0` commented out; `allow 192.168.100.0/24` + `local stratum 10` added; ntp opened in firewalld (zone public) | aero is the lab's only time source | restore `port 0`, remove the two added lines, `firewall-cmd --permanent --remove-service=ntp` |
| 2026-09-27 | clock set once from the Mac (`date -s`), was 13.4 s slow; RTC left in local-time mode as found | TOTP/TLS tests compare against the Mac | none needed |

## OpenSCAP CUI profile result (2026-09-27, report-only; `lab/reports/aero-cui-20260927-0029.html`)
98 pass · **5 fail** · 35 not applicable · 1401 not selected.

| Failing rule | Explained by |
|---|---|
| `chronyd_client_only` | lab deviation: aero serves NTP (above) |
| `ensure_gpgcheck_never_disabled` | lab deviation: `lab-local` repo is unsigned (inputs sha256-verified on the Mac) |
| `grub2_password` | **standard build** (pre-existing; not changed) |
| `service_usbguard_enabled` | **standard build** (pre-existing; USB NIC may depend on it) |
| `sysctl_user_max_user_namespaces` | **standard build** (pre-existing) |

Note: the NOPASSWD sudo deviation is not flagged. The CUI profile doesn't select a NOPASSWD rule.
