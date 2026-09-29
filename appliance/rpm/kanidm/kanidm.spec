# Binary repack of an offline build (lab/kanidm/build.sh). Paths follow KANIDM_BUILD_PROFILE=release_linux.
%global debug_package %{nil}
Name:           kanidm
Version:        1.11.2
Release:        2.chp%{?dist}
Summary:        Kanidm identity management (FIPS TLS variant, Rocky 9 compatible)
License:        MPL-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/kanidm/kanidm
Source0:        kanidm-%{version}-fips-staged.tar.gz
BuildRequires:  systemd-rpm-macros

%description
Kanidm %{version} built offline from source for EL9 with rustls' "fips" feature: TLS runs in the
AWS-LC FIPS 4.2.0 module. Application cryptography (Argon2 password hashing, TOTP HMAC) stays in
RustCrypto (outside any FIPS module; POA&M). Built without TPM support.

%package server
Summary: Kanidm identity server (kanidmd)
%description server
The Kanidm server daemon and its web UI assets.

%package clients
Summary: Kanidm command-line tools
%description clients
The kanidm CLI and kanidm_ssh_authorizedkeys_direct (asks the server directly).

%package unixd
Summary: Kanidm UNIX integration (PAM/NSS, unixd)
Requires: %{name}-clients = %{version}-%{release}
%description unixd
The kanidm_unixd resolver daemon and its tasks helper, the kanidm-unix tool,
kanidm_ssh_authorizedkeys (asks unixd, so it works offline from the cache),
the PAM module pam_kanidm.so and the NSS module libnss_kanidm.so.2.

%prep
%setup -q -n staged

%install
install -Dm0755 bin/kanidmd                          %{buildroot}%{_sbindir}/kanidmd
install -Dm0755 bin/kanidm                           %{buildroot}%{_bindir}/kanidm
install -Dm0755 bin/kanidm_ssh_authorizedkeys        %{buildroot}%{_sbindir}/kanidm_ssh_authorizedkeys
install -Dm0755 bin/kanidm_ssh_authorizedkeys_direct %{buildroot}%{_sbindir}/kanidm_ssh_authorizedkeys_direct
install -Dm0755 bin/kanidm_unixd                     %{buildroot}%{_sbindir}/kanidm_unixd
install -Dm0755 bin/kanidm_unixd_tasks               %{buildroot}%{_sbindir}/kanidm_unixd_tasks
install -Dm0755 bin/kanidm-unix                      %{buildroot}%{_sbindir}/kanidm-unix
install -Dm0755 bin/libpam_kanidm.so                 %{buildroot}%{_libdir}/security/pam_kanidm.so
install -Dm0755 bin/libnss_kanidm.so                 %{buildroot}%{_libdir}/libnss_kanidm.so.2
mkdir -p %{buildroot}%{_datadir}/kanidm/ui/hpkg
cp -a ui/. %{buildroot}%{_datadir}/kanidm/ui/hpkg/
install -Dm0644 units/kanidmd.service            %{buildroot}%{_unitdir}/kanidmd.service
install -Dm0644 units/kanidm-unixd.service       %{buildroot}%{_unitdir}/kanidm-unixd.service
install -Dm0644 units/kanidm-unixd-tasks.service %{buildroot}%{_unitdir}/kanidm-unixd-tasks.service
install -dm0755 %{buildroot}%{_sysconfdir}/kanidm
install -Dm0644 LICENSE.md %{buildroot}%{_datadir}/licenses/kanidm/LICENSE.md
install -Dm0644 examples/server.toml %{buildroot}%{_datadir}/kanidm/examples/server.toml
install -Dm0644 examples/unixd       %{buildroot}%{_datadir}/kanidm/examples/unixd
install -Dm0644 examples/kanidm      %{buildroot}%{_datadir}/kanidm/examples/config

%post server
%systemd_post kanidmd.service
%preun server
%systemd_preun kanidmd.service
%postun server
%systemd_postun_with_restart kanidmd.service
%post unixd
/sbin/ldconfig
%systemd_post kanidm-unixd.service kanidm-unixd-tasks.service
%preun unixd
%systemd_preun kanidm-unixd.service kanidm-unixd-tasks.service
%postun unixd
/sbin/ldconfig
%systemd_postun_with_restart kanidm-unixd.service kanidm-unixd-tasks.service

%files server
%license %{_datadir}/licenses/kanidm/LICENSE.md
%{_sbindir}/kanidmd
%dir %{_datadir}/kanidm
%dir %{_datadir}/kanidm/ui
%dir %{_datadir}/kanidm/examples
%{_datadir}/kanidm/ui/hpkg
%{_datadir}/kanidm/examples/server.toml
%{_unitdir}/kanidmd.service
%dir %{_sysconfdir}/kanidm

%files clients
%license %{_datadir}/licenses/kanidm/LICENSE.md
%{_bindir}/kanidm
%{_sbindir}/kanidm_ssh_authorizedkeys_direct
%dir %{_sysconfdir}/kanidm
%dir %{_datadir}/kanidm
%dir %{_datadir}/kanidm/examples
%{_datadir}/kanidm/examples/config

%files unixd
%license %{_datadir}/licenses/kanidm/LICENSE.md
%{_sbindir}/kanidm_unixd
%{_sbindir}/kanidm_ssh_authorizedkeys
%dir %{_sysconfdir}/kanidm
%dir %{_datadir}/kanidm
%dir %{_datadir}/kanidm/examples
%{_sbindir}/kanidm_unixd_tasks
%{_sbindir}/kanidm-unix
%{_libdir}/security/pam_kanidm.so
%{_libdir}/libnss_kanidm.so.2
%{_unitdir}/kanidm-unixd.service
%{_unitdir}/kanidm-unixd-tasks.service
%{_datadir}/kanidm/examples/unixd

%changelog
* Tue Sep 29 2026 The CyberHygiene Project - 1.11.2-2.chp
- FIPS TLS variant (rustls "fips", AWS-LC FIPS 4.2.0) for server and unixd; licence file; vendor.

* Sun Sep 27 2026 idm-assistant lab <lab@lab.test> - 1.11.2-1.lab
- Offline lab build on FIPS Rocky 9.8 (Plan 2)
