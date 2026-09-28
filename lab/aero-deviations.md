# aero: deviations from the standard workstation build

aero is a disposable, offline lab asset (no CUI, lab cable only). Fidelity settings
(FIPS, SELinux enforcing, CUI profile) are kept. **Every** change is listed here, with its revert.

| Date | Step | Change | Why | How to revert |
|---|---|---|---|---|
| 2026-09-26 | manual | Wi-Fi radio disabled (`nmcli radio wifi off`) | lab must be offline | `nmcli radio wifi on` |
| 2026-09-26 | manual | `/etc/sudoers.d/90-itadmin-lab`: `itadmin ALL=(ALL) NOPASSWD: ALL` | Mac drives setup over SSH; approved by the ISSO | `rm /etc/sudoers.d/90-itadmin-lab` |
| 2026-09-27 | b1 | ALL non-lab dnf repos disabled **by ID** via `dnf config-manager` (baseos, appstream, extras, claude-code, cuda-rhel10-x86_64, epel, epel-cisco-openh264, google-chrome, rpmfusion-free/nonfree-updates, wazuh). IDs recorded in `/etc/yum.repos.d/.lab-disabled-repos` | aero is offline; online repos make dnf fail | `dnf config-manager --set-enabled $(cat /etc/yum.repos.d/.lab-disabled-repos)` |
| 2026-09-27 | b1 | `/etc/yum.repos.d/lab.repo` (lab-baseos, lab-appstream from the DVD; lab-local, unsigned) | offline package source | `rm /etc/yum.repos.d/lab.repo` |
| 2026-09-27 | b1 | fstab line: `/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso` loop-mounted ro at `/data/lab-inputs/dvd` | DVD as a repo | `umount /data/lab-inputs/dvd`; delete the fstab line |
| 2026-09-27 | b1 | packages installed: `createrepo_c`, `createrepo_c-libs` | index lab-local | `dnf remove createrepo_c` |
| 2026-09-27 | b2 | packages installed: `qemu-kvm libvirt virt-install qemu-img libvirt-client policycoreutils-python-utils` (+ dependencies) | KVM host | `dnf history undo <b2 transaction id>` (see `dnf history`) |
| 2026-09-27 | b2 | enabled `virtqemud.socket virtnetworkd.socket virtstoraged.socket`; libvirt `default` NAT network stopped and autostart disabled | lab uses br-lab only | `systemctl disable --now` the three sockets; `virsh net-autostart default` |
| 2026-09-27 | b3 | SELinux fcontext rule `/data/libvirt/images(/.*)?` → `virt_image_t`; libvirt pool `default` at `/data/libvirt/images` (autostart) | VM storage on the LUKS `/data` volume | `semanage fcontext -d "/data/libvirt/images(/.*)?"`; `virsh pool-destroy default; virsh pool-undefine default` |
| 2026-09-27 | b4 | enp49s0 enslaved to bridge br-lab (192.168.100.1/24); "Profile 1" autoconnect off | lab VMs share the cable subnet | `nmcli con delete br-lab-port br-lab; nmcli con mod "Profile 1" connection.autoconnect yes; nmcli con up "Profile 1"` |
| 2026-09-27 | b5 | chrony: CUI `port 0` commented out; `allow 192.168.100.0/24` + `local stratum 10` added; ntp opened in firewalld (zone public) | aero is the lab's only time source | restore `port 0`, remove the two added lines, `firewall-cmd --permanent --zone=public --remove-service=ntp` |
| 2026-09-27 | manual | clock set once from the Mac (`date -s`), was 13.4 s slow; RTC left in local-time mode as found | TOTP/TLS tests compare against the Mac | none needed |
| 2026-09-27 | b8 | `lab-repo.service`: python3 http.server (DynamicUser) bound to 192.168.100.1:8080 serving /data/lab-inputs read-only; 8080/tcp opened in firewalld zone public | VMs install from the DVD + lab-local repo over the bridge | `systemctl disable --now lab-repo; rm /etc/systemd/system/lab-repo.service; firewall-cmd --permanent --zone=public --remove-port=8080/tcp; firewall-cmd --reload` |

## Observed on the standard build (not changed)
- A `cuda-rhel10-x86_64` repo was enabled. This was the user's own experiment to enable GPU AI on aero
  (note: Rocky 9 needs NVIDIA's rhel9 repo, not rhel10).
- A Wazuh agent repo is present (the agent will be offline in the lab).

## OpenSCAP CUI profile result (2026-09-27, report-only; `lab/reports/aero-cui-20260927-0029.html`)
98 pass · **5 fail** · 35 not applicable · 1401 not selected.

| Failing rule | Explained by |
|---|---|
| `chronyd_client_only` | lab deviation: aero serves NTP (b5) |
| `ensure_gpgcheck_never_disabled` | lab deviation: `lab-local` repo is unsigned (inputs sha256-verified on the Mac) |
| `grub2_password` | **standard build** (pre-existing; not changed) |
| `service_usbguard_enabled` | **standard build** (pre-existing; USB NIC may depend on it) |
| `sysctl_user_max_user_namespaces` | **standard build** (pre-existing) |

Note: the NOPASSWD sudo deviation is not flagged. The CUI profile doesn't select a NOPASSWD rule.
