Name:           idm-collect
Version:        0.1.0
Release:        1.chp%{?dist}
Summary:        Read-only identity diagnostics collector (The CyberHygiene Project)
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        idm-collect
Source1:        redact.sed
Source2:        LICENSE
Requires:       curl, sed, gawk, openssl, chrony, openssh-server, authselect, policycoreutils, audit, glibc-common

%description
idm-collect prints one idm-report/1 JSON document describing the identity stack (Kanidm, unixd, step-ca trust,
SSH CA, sshd, SELinux, time). It changes nothing on the host; secrets are redacted before output.
Site data (the Kanidm URL) is read from /etc/idm-collect/collect.conf.

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
* Tue Sep 29 2026 The CyberHygiene Project - 0.1.0-1.chp
- First packaged release: /usr/sbin path, config-driven Kanidm URL.
