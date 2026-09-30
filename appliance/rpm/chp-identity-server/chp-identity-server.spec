Name:           chp-identity-server
Version:        0.1.0
Release:        1.chp%{?dist}
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
Requires:       chp-base, chp-site, kanidm-server, kanidm-clients, step-ca, step-cli, bind, bind-utils, idm-collect
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

%changelog
* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release: unattended server first boot, renewal with ACME fallback, server monitor checks.
