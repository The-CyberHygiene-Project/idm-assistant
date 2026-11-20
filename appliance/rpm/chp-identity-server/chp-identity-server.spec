Name:           chp-identity-server
Version:        0.1.2
Release:        4.chp%{?dist}
Summary:        CyberHygiene identity-server role (Kanidm, step-ca, SSH CA, BIND) with an unattended first boot
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        server-firstboot.sh
Source1:        chp-server-firstboot.service
Source2:        cert-renew-kanidm.sh
Source3:        cert-renew-kanidm.service
Source4:        cert-renew-kanidm.timer
Source5:        kanidmd-tls.conf
Source6:        kanidm-login.exp
Source7:        30-kanidm-cert.sh
Source8:        31-renew-timer.sh
Source9:        40-escrow-pending.sh
Source10:       LICENSE
Source11:       chp-server-cui-tailoring.xml
Requires:       chp-base, chp-site >= 0.14.0-8, chp-identity-client >= 0.2.4-3, kanidm-server, kanidm-clients, step-ca, step-cli, bind, bind-utils, idm-collect
Requires:       expect, python3, curl, openssl, firewalld, policycoreutils, openssh
BuildRequires:  systemd-rpm-macros

%description
The identity-server role. On the first boot (chp-server-firstboot.service) it configures, from /etc/chp: BIND (the site
zone), step-ca (the ROOT key moved to /root/chp-escrow-pending for chp-site export-client to take offline), an ACME
certificate for Kanidm with a renewal timer that falls back to ACME re-issue, kanidmd (with a one-way domain guard), the
Kanidm admin recovery secrets (to the pending directory), the read-only collector token, and the SSH CA. Adds the
server monitor checks.

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_libexecdir}/chp/server-firstboot
install -Dm0644 %{SOURCE1} %{buildroot}%{_unitdir}/chp-server-firstboot.service
install -Dm0755 %{SOURCE2} %{buildroot}%{_libexecdir}/chp/cert-renew-kanidm
install -Dm0644 %{SOURCE3} %{buildroot}%{_unitdir}/cert-renew-kanidm.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_unitdir}/cert-renew-kanidm.timer
install -Dm0644 %{SOURCE5} %{buildroot}%{_unitdir}/kanidmd.service.d/chp-tls.conf
install -Dm0755 %{SOURCE6} %{buildroot}%{_libexecdir}/chp/kanidm-login.exp
install -Dm0755 %{SOURCE7} %{buildroot}%{_prefix}/lib/chp/monitor.d/30-kanidm-cert.sh
install -Dm0755 %{SOURCE8} %{buildroot}%{_prefix}/lib/chp/monitor.d/31-renew-timer.sh
install -Dm0755 %{SOURCE9} %{buildroot}%{_prefix}/lib/chp/monitor.d/40-escrow-pending.sh
install -Dm0644 %{SOURCE10} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -Dm0644 %{SOURCE11} %{buildroot}%{_datadir}/chp/scap/chp-server-cui-tailoring.xml

%post
%systemd_post chp-server-firstboot.service cert-renew-kanidm.timer
%preun
%systemd_preun chp-server-firstboot.service cert-renew-kanidm.timer

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_libexecdir}/chp/server-firstboot
%{_libexecdir}/chp/cert-renew-kanidm
%{_libexecdir}/chp/kanidm-login.exp
%{_unitdir}/chp-server-firstboot.service
%{_unitdir}/cert-renew-kanidm.service
%{_unitdir}/cert-renew-kanidm.timer
%dir %{_unitdir}/kanidmd.service.d
%{_unitdir}/kanidmd.service.d/chp-tls.conf
%{_prefix}/lib/chp/monitor.d/30-kanidm-cert.sh
%{_prefix}/lib/chp/monitor.d/31-renew-timer.sh
%{_prefix}/lib/chp/monitor.d/40-escrow-pending.sh
%dir %{_datadir}/chp/scap
%{_datadir}/chp/scap/chp-server-cui-tailoring.xml

%changelog
* Fri Nov 20 2026 The CyberHygiene Project - 0.1.2-4.chp
- First boot step `time` (Task 12, owner decision 2026-11-20), after bind: `chp-site time-sync --role server` (the
  server serves NTP to the site subnet only; firewalld 123/udp from SUBNET only, the owner-approved exception to
  "no new network port"). Requires chp-site >= 0.14.0-8 and chp-identity-client >= 0.2.4-3.
- /usr/share/chp/scap/chp-server-cui-tailoring.xml (owner decisions 2026-11-20): the server's CUI profile, tailored
  to unselect exactly chronyd_client_only (the server serves NTP to the site LAN) and sysctl_user_max_user_namespaces
  (the existing ISO deviation, its reason quoted from docs/dc2-planning/dc2-cui-tailoring.xml), each with its own
  reason; for scans with --tailoring-file. Workstations keep the stock profile.

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.2-3.chp
- cert-renew-kanidm.sh takes the shared ACME lock /run/chp-acme.lock (flock, up to 300 s) around opening port 80,
  so it and chp-documents' cert-renew-nextcloud never hold :80 open at once.

* Sun Nov 01 2026 The CyberHygiene Project - 0.1.2-2.chp
- kanidm-login.exp pauses 400 ms before sending the password: sending it the instant the prompt appears can lose it
  to the CLI's switch to hidden input (expect then times out).

* Thu Oct 29 2026 The CyberHygiene Project - 0.1.2-1.chp
- Security bundle W2: server first boot: the security step (chp-site security enable --firstboot when SECURITY_ADDONS=yes).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.1-1.chp
- unixd-tokens step (login groups chp_users/chp_admins, one read-only unixd token per host) and self-client step (the server becomes its own Kanidm client, ISO Plan 4a).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-5.chp
- cache-key first-boot step (chp-site revoke fan-out, ISSO #28); carries the 0.1.0-4 collector login retry.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-4.chp
- Retry the idm_admin login (5 x, 60 s each) while Kanidm settles after recover.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-3.chp
- Domain guard before any step and in renewal (set once Kanidm runs); collector resume without grep -q; logout; failed-renewal alert.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-2.chp
- kanidmd scripting recover-account; HOME for the kanidm CLI; 4 h certificate monitor threshold.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release: unattended server first boot, renewal with ACME fallback, server monitor checks.
