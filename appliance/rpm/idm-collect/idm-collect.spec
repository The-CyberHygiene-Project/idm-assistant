Name:           idm-collect
Version:        0.1.0
Release:        4.chp%{?dist}
Summary:        Read-only identity diagnostics collector (The CyberHygiene Project)
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        idm-collect
Source1:        redact.sed
Source2:        LICENSE
Requires:       bash, curl, sed, gawk, openssl, chrony, openssh-server, authselect, policycoreutils, audit, glibc-common

%description
idm-collect prints one idm-report/1 JSON document describing the identity stack (Kanidm, unixd, step-ca trust,
SSH CA, sshd, SELinux, time). It changes nothing on the host; secrets are redacted before output.
Site data (KANIDM_URL, CA_ANCHOR) is read from /etc/idm-collect/collect.conf; a missing or invalid value is
reported as a collect.conf error instead of a network or trust fault.

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_sbindir}/idm-collect
install -Dm0644 %{SOURCE1} %{buildroot}%{_datadir}/idm-collect/redact.sed
install -dm0700 %{buildroot}%{_sysconfdir}/idm-collect
install -Dm0644 %{SOURCE2} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_sbindir}/idm-collect
%dir %{_datadir}/idm-collect
%{_datadir}/idm-collect/redact.sed
%dir %attr(0700,root,root) %{_sysconfdir}/idm-collect

%changelog
* Sat Oct 03 2026 The CyberHygiene Project - 0.1.0-4.chp
- name record (getent, source, resolvers, resolver_state) and server own_addresses.

* Sat Oct 03 2026 The CyberHygiene Project - 0.1.0-3.chp
- faillock section for --user: lockout limit, lock time and each failure (unknown = null).

* Tue Sep 29 2026 The CyberHygiene Project - 0.1.0-2.chp
- Unusable collect.conf values are reported as collect.conf errors; TLS probe skipped and trust null without them.

* Tue Sep 29 2026 The CyberHygiene Project - 0.1.0-1.chp
- First packaged release: /usr/sbin path, config-driven Kanidm URL.
