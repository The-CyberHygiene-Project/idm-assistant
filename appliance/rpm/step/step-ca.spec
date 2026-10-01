%global debug_package %{nil}
Name:           step-ca
Version:        0.30.2
Release:        3.chp%{?dist}
Summary:        step-ca internal certificate authority (built from source, Go FIPS 140-3 module)
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/smallstep/certificates
Source0:        step-ca-%{version}-staged.tar.gz
Source1:        step-ca.sysusers
Requires:       step-cli
BuildRequires:  systemd-rpm-macros
%{?sysusers_requires_compat}

%description
step-ca %{version} built offline from source with CGO disabled and Go's FIPS 140-3 module selected at build time.
The unit runs it with GODEBUG=fips140=on. It is installed disabled; the identity-server role configures and enables it.

%prep
%setup -q -n staged

%install
install -Dm0755 step-ca %{buildroot}%{_bindir}/step-ca
install -Dm0644 step-ca.service %{buildroot}%{_unitdir}/step-ca.service
install -Dm0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/step-ca.conf
install -Dm0644 LICENSE-step-ca %{buildroot}%{_datadir}/licenses/step-ca/LICENSE

%pre
%sysusers_create_compat %{SOURCE1}

%post
%systemd_post step-ca.service
%preun
%systemd_preun step-ca.service
%postun
%systemd_postun_with_restart step-ca.service

%files
%license %{_datadir}/licenses/step-ca/LICENSE
%{_bindir}/step-ca
%{_unitdir}/step-ca.service
%{_sysusersdir}/step-ca.conf

%changelog
* Tue Sep 29 2026 The CyberHygiene Project - 0.30.2-3.chp
- %pre creates the step user (sysusers file as Source1; the sysusers file trigger does not run in Anaconda).

* Tue Sep 29 2026 The CyberHygiene Project - 0.30.2-2.chp
- Built from source (vendored modules, pinned Go), GOFIPS140 module; unit with GODEBUG=fips140=on; sysusers.
