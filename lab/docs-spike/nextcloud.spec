# nextcloud.spec - ISO 0.7.0 Plan 1 SPIKE package (throwaway; Plan 2 writes the product package).
# NextCloud server (GPG-verified tarball) + the app-store apps the design needs (signature-verified, fetch-inputs.sh) +
# the spike's own chp_foldertag app (built on the Mac: aero's fapolicyd denies reading untrusted PHP, see SPIKE-NEXTCLOUD.md), laid out for a read-only code tree that fapolicyd trusts through the rpm database:
#   /usr/lib/nextcloud          code (NOT /usr/share: fapolicyd-filter.conf drops /usr/share from the trust database
#                               except *.php/*.js/..., so occ and every *.mjs would be untrusted and denied)
#                               (root:root, read-only; NextCloud never writes here: app store off)
#   /etc/nextcloud              config.php (apache, httpd_sys_rw_content_t), symlinked from /usr/lib/nextcloud/config
#   /data/nextcloud/data        user files (apache, httpd_sys_rw_content_t; not packaged, made by setup.sh)
%global ncver 35.0.3
%global debug_package %{nil}
%global __brp_mangle_shebangs %{nil}
%global __os_install_post %{nil}
%undefine __brp_python_bytecompile

Name:           nextcloud-chp
Version:        %{ncver}
Release:        0.spike5%{?dist}
Summary:        NextCloud server with bundled apps for the CHP document store (SPIKE build)
License:        AGPL-3.0-or-later
URL:            https://nextcloud.com
BuildArch:      noarch
AutoReqProv:    no
Source0:        nextcloud-%{ncver}.tar.bz2
Source1:        groupfolders-23.0.1.tar.gz
Source2:        files_accesscontrol-6.0.1.tar.gz
Source3:        user_oidc-8.13.0.tar.gz
Source4:        chp_foldertag.tar.gz
Source5:        nextcloud-httpd.conf
Source6:        nextcloud-fpm.conf
Source7:        nextcloud-cron.service
Source8:        nextcloud-cron.timer
Source9:        occ
Source10:       nextcloud-egress.nft
Source11:       chp-nextcloud-egress.service
Requires:       httpd >= 2.4, mod_ssl, php-fpm >= 8.3, php-cli >= 8.3, php-common >= 8.3
Requires:       php-gd, php-mbstring, php-intl, php-xml, php-pgsql, php-process, php-bcmath, php-gmp, php-opcache
Requires:       php-pecl-zip, php-pecl-apcu, php-pdo
Requires:       postgresql-server >= 16
Requires(post): policycoreutils-python-utils

%description
SPIKE build of NextCloud %{ncver} for the CyberHygiene appliance (ISO 0.7.0 Plan 1). Bundled apps: groupfolders
(team folders), files_accesscontrol, user_oidc, chp_foldertag; the app store is off. Not for release.

%prep
%setup -q -n nextcloud
for s in %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4}; do tar -xzf "$s" -C apps; done

%build

%install
install -d %{buildroot}%{_prefix}/lib/nextcloud %{buildroot}%{_sysconfdir}/nextcloud
cp -a . %{buildroot}%{_prefix}/lib/nextcloud/
# config lives in /etc/nextcloud (writable by apache); the tarball's config/ files move there
mv %{buildroot}%{_prefix}/lib/nextcloud/config/* %{buildroot}%{_sysconfdir}/nextcloud/
cp -a %{buildroot}%{_prefix}/lib/nextcloud/config/.htaccess %{buildroot}%{_sysconfdir}/nextcloud/ 2>/dev/null || true
rm -rf %{buildroot}%{_prefix}/lib/nextcloud/config
ln -s %{_sysconfdir}/nextcloud %{buildroot}%{_prefix}/lib/nextcloud/config
mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d %{buildroot}%{_sysconfdir}/php-fpm.d %{buildroot}%{_unitdir} %{buildroot}%{_bindir}
install -m 0644 %{SOURCE5} %{buildroot}%{_sysconfdir}/httpd/conf.d/nextcloud.conf
install -m 0644 %{SOURCE6} %{buildroot}%{_sysconfdir}/php-fpm.d/nextcloud.conf
install -m 0644 %{SOURCE7} %{buildroot}%{_unitdir}/nextcloud-cron.service
install -m 0644 %{SOURCE8} %{buildroot}%{_unitdir}/nextcloud-cron.timer
install -m 0755 %{SOURCE9} %{buildroot}%{_bindir}/occ
mkdir -p %{buildroot}%{_sysconfdir}/nftables
install -m 0600 %{SOURCE10} %{buildroot}%{_sysconfdir}/nftables/chp-nextcloud-egress.nft.in
install -m 0644 %{SOURCE11} %{buildroot}%{_unitdir}/chp-nextcloud-egress.service
install -d -m 0750 %{buildroot}%{_localstatedir}/log/nextcloud

%post
semanage fcontext -a -t httpd_sys_rw_content_t '%{_sysconfdir}/nextcloud(/.*)?' 2>/dev/null || :
semanage fcontext -a -t httpd_sys_rw_content_t '/data/nextcloud(/.*)?' 2>/dev/null || :
semanage fcontext -a -t httpd_log_t '%{_localstatedir}/log/nextcloud(/.*)?' 2>/dev/null || :
semanage fcontext -a -t httpd_sys_content_t '%{_prefix}/lib/nextcloud(/.*)?' 2>/dev/null || :
restorecon -R %{_prefix}/lib/nextcloud %{_sysconfdir}/nextcloud %{_localstatedir}/log/nextcloud >/dev/null 2>&1 || :
if [ $1 -eq 1 ]; then systemctl preset nextcloud-cron.timer >/dev/null 2>&1 || :; fi

%preun
if [ $1 -eq 0 ]; then systemctl --no-reload disable --now nextcloud-cron.timer >/dev/null 2>&1 || :; fi

%files
%defattr(-,root,root,-)
%license COPYING
%{_prefix}/lib/nextcloud
%dir %attr(0750,apache,apache) %{_sysconfdir}/nextcloud
%config(noreplace) %attr(0640,apache,apache) %{_sysconfdir}/nextcloud/*
%config(noreplace) %attr(0640,apache,apache) %{_sysconfdir}/nextcloud/.htaccess
%config(noreplace) %{_sysconfdir}/httpd/conf.d/nextcloud.conf
%config(noreplace) %{_sysconfdir}/php-fpm.d/nextcloud.conf
%{_unitdir}/nextcloud-cron.service
%{_unitdir}/nextcloud-cron.timer
%{_unitdir}/chp-nextcloud-egress.service
%config(noreplace) %{_sysconfdir}/nftables/chp-nextcloud-egress.nft.in
%{_bindir}/occ
%dir %attr(0750,apache,apache) %{_localstatedir}/log/nextcloud

%changelog
* Thu Nov 12 2026 CyberHygiene Project lab - 35.0.3-0.spike5
- chp_foldertag 0.2.0: refuse copy/move out of contained team folders (prototype)

* Thu Nov 12 2026 CyberHygiene Project lab - 35.0.3-0.spike4
- egress rules (template) + unit packaged; chp:foldertag:check for groupfolders separate storages

* Thu Nov 12 2026 CyberHygiene Project lab - 35.0.3-0.spike3
- code tree /usr/share/nextcloud -> /usr/lib/nextcloud (fapolicyd trust filter); httpd_sys_content_t on it

* Thu Nov 12 2026 CyberHygiene Project lab - 35.0.3-0.spike2
- drop php-sodium (not in Rocky 9: libsodium is EPEL-only); NextCloud lists it as recommended, not required

* Thu Nov 12 2026 CyberHygiene Project lab - 35.0.3-0.spike1
- Spike build (ISO 0.7.0 Plan 1 Task 1)
