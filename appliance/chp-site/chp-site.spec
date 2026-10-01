Name:           chp-site
Version:        0.2.2
Release:        1.chp%{?dist}
Summary:        CyberHygiene site files tool and installer gate
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        chp-site.pyz
Source1:        chp.repo
Source2:        RPM-GPG-KEY-cyberhygiene
Source3:        LICENSE
Source4:        chp-site.sh
Requires:       python3, openssl, util-linux

%description
chp-site validates the site files (site.conf, hosts, client.conf) and writes client.conf on the identity server.
It also ships the project signing key and a disabled repo definition for signed update tarballs.

%install
install -Dm0644 %{SOURCE0} %{buildroot}%{_datadir}/chp-site/chp-site.pyz
install -Dm0755 %{SOURCE4} %{buildroot}%{_bindir}/chp-site
install -Dm0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/yum.repos.d/chp.repo
install -Dm0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
install -dm0755 %{buildroot}%{_sharedstatedir}/chp/repo
install -Dm0644 %{SOURCE3} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_bindir}/chp-site
%dir %{_datadir}/chp-site
%{_datadir}/chp-site/chp-site.pyz
%config(noreplace) %{_sysconfdir}/yum.repos.d/chp.repo
%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
%dir %{_sharedstatedir}/chp
%dir %{_sharedstatedir}/chp/repo

%changelog
* Wed Sep 30 2026 The CyberHygiene Project - 0.2.2-1.chp
- Escrow write fsync'd and read back from the device before shredding; only a storage-only pinned stick; stick always re-blocked.

* Wed Sep 30 2026 The CyberHygiene Project - 0.2.1-1.chp
- export-client allows only the pinned site stick through USBGuard, temporarily; pre records the stick identity.

* Wed Sep 30 2026 The CyberHygiene Project - 0.2.0-1.chp
- get/render for server config; export-client moves the server's pending recovery secrets to the stick
  (write, sync, read back, then shred); final-review fixes from 0.1.0.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release: validate, pre, export-client; project key; disabled local repo definition.
