Name:           chp-identity-client
Version:        0.2.1
Release:        1.chp%{?dist}
Summary:        CyberHygiene identity-client role (Kanidm unixd, authselect, sshd, forced-command accounts)
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        client-enrol.sh
Source1:        client-accounts.sh
Source2:        diag-collect.sh
Source4:        client-firstboot.sh
Source5:        chp-client-firstboot.service
Source6:        unixd.toml.in
Source7:        sshd-10-chp.conf
Source8:        sshd-99-chp-exceptions.conf
Source9:        chp_kanidm.pp
Source10:       50-authselect.sh
Source11:       51-sshd.sh
Source12:       52-kanidm-tls.sh
Source13:       LICENSE
Source14:       49-client-enrolled.sh
Source15:       53-ga.sh
Requires:       chp-base, chp-site >= 0.5.1, google-authenticator, kanidm-unixd, kanidm-clients, idm-collect, step-cli
Requires:       authselect, policycoreutils, policycoreutils-python-utils, openssh-server, openssl, curl, python3, sudo, shadow-utils
Requires(post): policycoreutils, policycoreutils-python-utils
Requires(postun): policycoreutils, policycoreutils-python-utils
BuildRequires:  systemd-rpm-macros

%description
The identity-client role (spec section 7). On the first boot (chp-client-firstboot.service) client-enrol makes this host a
Kanidm client of the site, from /etc/chp: the step-ca root checked against its pinned SHA-256, kanidm-unixd with this
host's own read-only token, authselect custom/kanidm built from the host's CUI profile with every feature kept, the sshd
drop-ins (certificate + keyboard-interactive; key-only for chpadmin/diag/chpcache), the diag and chpcache forced-command
accounts and the chp_admins sudo rule. The identity server runs the same enrolment on itself (--role server). Ships the
chp_kanidm SELinux module (ISSO #12) and the authselect, sshd and Kanidm-TLS monitor checks.

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_libexecdir}/chp/client-enrol
install -Dm0755 %{SOURCE1} %{buildroot}%{_libexecdir}/chp/client-accounts
install -Dm0755 %{SOURCE2} %{buildroot}%{_libexecdir}/chp/diag-collect
install -Dm0755 %{SOURCE4} %{buildroot}%{_libexecdir}/chp/client-firstboot
install -Dm0644 %{SOURCE5} %{buildroot}%{_unitdir}/chp-client-firstboot.service
install -Dm0644 %{SOURCE6} %{buildroot}%{_datadir}/chp/client/unixd.toml.in
install -Dm0644 %{SOURCE7} %{buildroot}%{_datadir}/chp/client/sshd-10-chp.conf
install -Dm0644 %{SOURCE8} %{buildroot}%{_datadir}/chp/client/sshd-99-chp-exceptions.conf
install -Dm0644 %{SOURCE9} %{buildroot}%{_datadir}/selinux/packages/chp_kanidm.pp
install -Dm0755 %{SOURCE10} %{buildroot}%{_prefix}/lib/chp/monitor.d/50-authselect.sh
install -Dm0755 %{SOURCE11} %{buildroot}%{_prefix}/lib/chp/monitor.d/51-sshd.sh
install -Dm0755 %{SOURCE12} %{buildroot}%{_prefix}/lib/chp/monitor.d/52-kanidm-tls.sh
install -Dm0644 %{SOURCE13} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -Dm0755 %{SOURCE14} %{buildroot}%{_prefix}/lib/chp/monitor.d/49-client-enrolled.sh
install -Dm0755 %{SOURCE15} %{buildroot}%{_prefix}/lib/chp/monitor.d/53-ga.sh
install -d -m 0700 %{buildroot}%{_sharedstatedir}/google-authenticator

%post
semodule -i %{_datadir}/selinux/packages/chp_kanidm.pp
restorecon -R /run/kanidm-unixd 2>/dev/null || :
%systemd_post chp-client-firstboot.service

%preun
%systemd_preun chp-client-firstboot.service

%postun
if [ $1 -eq 0 ]; then
  semodule -r chp_kanidm 2>/dev/null || :
fi

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_libexecdir}/chp/client-enrol
%{_libexecdir}/chp/client-accounts
%{_libexecdir}/chp/diag-collect
%{_libexecdir}/chp/client-firstboot
%{_unitdir}/chp-client-firstboot.service
%dir %{_datadir}/chp/client
%{_datadir}/chp/client/unixd.toml.in
%{_datadir}/chp/client/sshd-10-chp.conf
%{_datadir}/chp/client/sshd-99-chp-exceptions.conf
%{_datadir}/selinux/packages/chp_kanidm.pp
%{_prefix}/lib/chp/monitor.d/49-client-enrolled.sh
%{_prefix}/lib/chp/monitor.d/50-authselect.sh
%{_prefix}/lib/chp/monitor.d/51-sshd.sh
%{_prefix}/lib/chp/monitor.d/52-kanidm-tls.sh
%{_prefix}/lib/chp/monitor.d/53-ga.sh
%dir %attr(0700,root,root) %{_sharedstatedir}/google-authenticator

%changelog
* Thu Oct 01 2026 The CyberHygiene Project - 0.2.1-1.chp
- unixd reports SHORT names (uid_attr_map/gid_attr_map = name): sudo's PAM user and GA token paths match the login name (Plan 4b proof); 53-ga alerts if allow_local_account_override is set (final review I1).

* Thu Oct 01 2026 The CyberHygiene Project - 0.2.0-1.chp
- Second factor (ISO Plan 4b): requires google-authenticator and chp-site >= 0.5.1 (GA PAM lines via authselect-patch, ga-enrol, pam-test); owns /var/lib/google-authenticator (0700); 53-ga monitor. No chp_ga module: the policy's var_auth_t covers it (measured: 0 AVC).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-5.chp
- Trust refusal logs what the CA serves (or that it is unreachable); enrolment refuses without chp_kanidm and checks the socket label; 49-client-enrolled monitor; the first-boot unit retries every 5 min (final review).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-4.chp
- chp_kanidm: systemd (init_t) may create/remove the unixd runtime directory and sockets (denied on stop in the proof).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-3.chp
- chp_kanidm.fc names /var/run/kanidm-unixd: Rocky's file_contexts.subs_dist maps /run to /var/run, so a /run rule never matched; the module carries the context (no semanage).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-2.chp
- chp_kanidm.fc: raw SELinux context (gen_context() is a refpolicy macro; semodule rejected the module at install).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (ISO Plan 4a): client enrolment, chp_kanidm policy, forced-command accounts, client monitors.
