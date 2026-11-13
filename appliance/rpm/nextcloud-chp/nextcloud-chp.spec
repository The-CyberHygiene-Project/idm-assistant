# nextcloud-chp: NextCloud server for the CHP document store, with the bundled apps it needs and our chp_foldertag.
# Inputs are verified on the Mac (fetch-inputs.sh -> MANIFEST.txt); built on the build VM chp-build (build-rpm.sh).
# Layout (read-only code tree that fapolicyd trusts through the rpm database):
#   /usr/lib/nextcloud     code, root:root, never written by NextCloud (app store off). NOT /usr/share: fapolicyd's
#                          filter keeps only some file types of /usr/share in its trust database, so occ and every
#                          *.mjs would be untrusted and denied.
#   /etc/nextcloud         config (apache, httpd_sys_rw_content_t); /usr/lib/nextcloud/config is a symlink to it
#   /var/log/nextcloud     nextcloud.log + audit.log (apache, httpd_log_t)
#   /data/nextcloud/data   user files: NOT in this package (made by chp-site documents enable on the /data mount)
# Web server, PHP-FPM pool, cron, egress, backup and monitor files are in chp-documents, not here.
%global ncver 35.0.3
%global groupfolders_ver 23.0.1
%global files_accesscontrol_ver 6.0.1
%global user_oidc_ver 8.13.0
%global foldertag_ver 1.0.0
%global debug_package %{nil}
%global __brp_mangle_shebangs %{nil}
%global __os_install_post %{nil}
%undefine __brp_python_bytecompile

Name:           nextcloud-chp
Version:        %{ncver}
Release:        1.chp%{?dist}
Summary:        NextCloud server with the bundled apps for the CyberHygiene document store
# NextCloud and its bundled apps: AGPL-3.0-or-later (their 3rdparty trees carry further permissive licences);
# chp_foldertag: Apache-2.0 (this repository's licence)
License:        AGPL-3.0-or-later AND Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
AutoReqProv:    no
Source0:        nextcloud-%{ncver}.tar.bz2
Source1:        groupfolders-%{groupfolders_ver}.tar.gz
Source2:        files_accesscontrol-%{files_accesscontrol_ver}.tar.gz
Source3:        user_oidc-%{user_oidc_ver}.tar.gz
Source4:        chp_foldertag.tar.gz
Source5:        occ
Source6:        LICENSE
Requires:       php-cli >= 8.3, php-common >= 8.3
Requires:       php-gd, php-mbstring, php-intl, php-xml, php-pgsql, php-process, php-bcmath, php-gmp, php-opcache
Requires:       php-pecl-zip, php-pecl-apcu, php-pdo
# the apache user and group (owners of /etc/nextcloud and /var/log/nextcloud) come from httpd-filesystem
Requires(pre):  httpd-filesystem
Requires(post): policycoreutils-python-utils
Requires(posttrans): util-linux

%description
NextCloud %{ncver} for the CyberHygiene appliance's document store (DOCUMENTS=yes on the server). Bundled apps:
groupfolders %{groupfolders_ver} (team folders), files_accesscontrol %{files_accesscontrol_ver}, user_oidc
%{user_oidc_ver} (Kanidm sign-in), and chp_foldertag %{foldertag_ver} (tag by folder, copy/move out of CUI, FCI and
Archive refused except CUI <-> Archive, audit events). The app store and update checks are switched off by chp-site;
nothing here reaches the internet. chp-site documents enable installs and configures it.

%prep
%setup -q -n nextcloud
for s in %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4}; do tar -xzf "$s" -C apps; done
# the bundled app versions must be the pinned ones (MANIFEST.txt; fetch-inputs.sh verified their signatures)
for p in groupfolders:%{groupfolders_ver} files_accesscontrol:%{files_accesscontrol_ver} user_oidc:%{user_oidc_ver} chp_foldertag:%{foldertag_ver}; do
  a=${p%%:*}; v=${p#*:}
  got=$(sed -n 's|.*<version>\(.*\)</version>.*|\1|p' "apps/$a/appinfo/info.xml" | head -1)
  [ "$got" = "$v" ] || { echo "app $a is version '$got', expected $v"; exit 1; }
done
cp %{SOURCE6} LICENSE.chp_foldertag

%build

%install
install -d %{buildroot}%{_prefix}/lib/nextcloud %{buildroot}%{_sysconfdir}/nextcloud
cp -a . %{buildroot}%{_prefix}/lib/nextcloud/
rm -f %{buildroot}%{_prefix}/lib/nextcloud/LICENSE.chp_foldertag
# config lives in /etc/nextcloud (writable by apache). CAN_INSTALL is dropped: chp-site installs with occ, and the
# web installer must never be reachable on an uninstalled server.
rm -f %{buildroot}%{_prefix}/lib/nextcloud/config/CAN_INSTALL
mv %{buildroot}%{_prefix}/lib/nextcloud/config/config.sample.php %{buildroot}%{_prefix}/lib/nextcloud/config/.htaccess \
   %{buildroot}%{_sysconfdir}/nextcloud/
rmdir %{buildroot}%{_prefix}/lib/nextcloud/config
ln -s %{_sysconfdir}/nextcloud %{buildroot}%{_prefix}/lib/nextcloud/config
install -d %{buildroot}%{_bindir}
install -m 0755 %{SOURCE5} %{buildroot}%{_bindir}/occ
install -d -m 0750 %{buildroot}%{_localstatedir}/log/nextcloud

%post
semanage fcontext -a -t httpd_sys_rw_content_t '%{_sysconfdir}/nextcloud(/.*)?' 2>/dev/null || :
semanage fcontext -a -t httpd_sys_rw_content_t '/data/nextcloud(/.*)?' 2>/dev/null || :
semanage fcontext -a -t httpd_log_t '%{_localstatedir}/log/nextcloud(/.*)?' 2>/dev/null || :
semanage fcontext -a -t httpd_sys_content_t '%{_prefix}/lib/nextcloud(/.*)?' 2>/dev/null || :
restorecon -R %{_prefix}/lib/nextcloud %{_sysconfdir}/nextcloud %{_localstatedir}/log/nextcloud >/dev/null 2>&1 || :

%posttrans
# A changed NextCloud or app version leaves NextCloud answering 503 ("upgrade required") until occ upgrade runs.
# Run it only on a server where NextCloud is installed (occ status says "installed":true); on a fresh install,
# the ISO build or a server without documents, there is nothing to upgrade. %%posttrans, not %%post: on an update
# the old package's files are only removed after %%post, and occ upgrade must see the new tree alone.
if [ -s %{_sysconfdir}/nextcloud/config.php ] && [ -x /usr/bin/php ] && \
   %{_bindir}/occ status --output=json 2>/dev/null | grep -q '"installed":true'; then
  if %{_bindir}/occ upgrade --no-interaction >/dev/null 2>&1; then
    echo "nextcloud-chp: occ upgrade done"
  else
    echo "nextcloud-chp: occ upgrade FAILED; NextCloud answers 503 until 'occ upgrade' succeeds" >&2
  fi
fi
:

%files
%defattr(-,root,root,-)
%license COPYING
%license LICENSE.chp_foldertag
%{_prefix}/lib/nextcloud
%dir %attr(0750,apache,apache) %{_sysconfdir}/nextcloud
%config(noreplace) %attr(0640,apache,apache) %{_sysconfdir}/nextcloud/config.sample.php
%config(noreplace) %attr(0640,apache,apache) %{_sysconfdir}/nextcloud/.htaccess
%{_bindir}/occ
%dir %attr(0750,apache,apache) %{_localstatedir}/log/nextcloud

%changelog
* Fri Nov 13 2026 The CyberHygiene Project - 35.0.3-1.chp
- First product build (ISO 0.7.0 Plan 2 Task 3): NextCloud 35.0.3, groupfolders 23.0.1, files_accesscontrol 6.0.1,
  user_oidc 8.13.0, chp_foldertag 1.0.0 (policy from app config, CUI <-> Archive allowed, audit events, trash and
  version copy-out refused, folder guard while the database refuses MD5)
- occ upgrade in %%posttrans only when NextCloud is installed; no web, cron or egress files (chp-documents has them)
