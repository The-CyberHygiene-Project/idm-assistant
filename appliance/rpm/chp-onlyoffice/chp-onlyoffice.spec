# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
Name:           chp-onlyoffice
Version:        0.1.0
Release:        1.chp%{?dist}
Summary:        CyberHygiene workstation editor: ONLYOFFICE without AI Tools or vendor calls, the workstation egress table, the autosave sweep, linger off
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        onlyoffice-ai-off.sh
Source1:        DesktopEditors.conf
Source2:        chp-workstation-egress.nft
Source3:        chp-workstation-egress.service
Source4:        chp-onlyoffice-sweep.service
Source5:        chp-onlyoffice-sweep.timer
Source6:        logind-chp-docs.conf
Source7:        50-chp-no-linger.rules
Source8:        README.md
Source9:        LICENSE
# the vendor RPM, re-signed with the project key (appliance/release/VENDOR.txt pins it); x2t makes the reader PDFs
Requires:       onlyoffice-desktopeditors = 10.0.0
# pdftotext/pdfinfo: chp-site doc's marking check of reader PDFs (chp_site.marking)
Requires:       poppler-utils
# chp-site onlyoffice (enable, sweep, egress-render) and the doc commands of Plan 3
Requires:       chp-site >= 0.14.0-5
Requires:       nftables, systemd, polkit, chrony, python3, util-linux
BuildRequires:  systemd-rpm-macros

%description
The workstation half of the document workflow's editor (ISO 0.7.0 Plan 3 Task 8, the editor spike's gates):
- G4: ONLYOFFICE's AI Tools plugin is removed after install and after every vendor install or upgrade; system-wide
  defaults turn off the update check, cloud portals, plugins and the start page's AI entries.
- G3: an nftables table for the whole workstation: only the site server and the site resolver (DNS 53 only; DoT,
  DoH and DNS to anyone else refused, IPv4 and IPv6).
- G2: an hourly sweep of ONLYOFFICE's auto-recovery copies (CUI) of sessions closed or abandoned for 12 h.
- Ruling F3: logout ends the user's processes, and linger stays off (polkit refuses enabling it).
Nothing is enabled by installing it: `chp-site onlyoffice enable` (client enrolment's "docs" step when
DOCUMENTS=yes) renders the addresses and starts the units. See /usr/share/doc/chp-onlyoffice/README.md (POA&M items).

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_libexecdir}/chp/onlyoffice-ai-off
install -Dm0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/xdg/onlyoffice/DesktopEditors.conf
install -Dm0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/nftables/chp-workstation-egress.nft
install -Dm0644 %{SOURCE3} %{buildroot}%{_unitdir}/chp-workstation-egress.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_unitdir}/chp-onlyoffice-sweep.service
install -Dm0644 %{SOURCE5} %{buildroot}%{_unitdir}/chp-onlyoffice-sweep.timer
install -Dm0644 %{SOURCE6} %{buildroot}%{_sysconfdir}/systemd/logind.conf.d/50-chp-docs.conf
install -Dm0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/polkit-1/rules.d/50-chp-no-linger.rules
install -Dm0644 %{SOURCE8} %{buildroot}%{_docdir}/%{name}/README.md
install -Dm0644 %{SOURCE9} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%post
%systemd_post chp-workstation-egress.service chp-onlyoffice-sweep.timer
%{_libexecdir}/chp/onlyoffice-ai-off || :

%posttrans
%{_libexecdir}/chp/onlyoffice-ai-off || :

# every install, reinstall or upgrade of the vendor package lays the AI Tools plugin down again: remove it at once
%triggerin -- onlyoffice-desktopeditors
%{_libexecdir}/chp/onlyoffice-ai-off || :

%preun
%systemd_preun chp-workstation-egress.service chp-onlyoffice-sweep.timer chp-onlyoffice-sweep.service

%postun
%systemd_postun chp-onlyoffice-sweep.timer
# on upgrade the table is reloaded from the (possibly new) shipped file; the unit has no ExecStop (fail closed), so
# only removing the package deletes the table
%systemd_postun_with_restart chp-workstation-egress.service
if [ "$1" -eq 0 ]; then /usr/sbin/nft delete table inet chp_workstation_egress >/dev/null 2>&1 || :; fi

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%{_libexecdir}/chp/onlyoffice-ai-off
%config(noreplace) %{_sysconfdir}/xdg/onlyoffice/DesktopEditors.conf
%{_sysconfdir}/nftables/chp-workstation-egress.nft
%ghost %attr(0644,root,root) %{_sysconfdir}/chp/workstation-egress-addr.nft
%{_unitdir}/chp-workstation-egress.service
%{_unitdir}/chp-onlyoffice-sweep.service
%{_unitdir}/chp-onlyoffice-sweep.timer
%{_sysconfdir}/systemd/logind.conf.d/50-chp-docs.conf
%{_sysconfdir}/polkit-1/rules.d/50-chp-no-linger.rules

%changelog
* Thu Nov 19 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (ISO 0.7.0 Plan 3 Task 8): AI Tools removal (%%post, %%posttrans, trigger on
  onlyoffice-desktopeditors), /etc/xdg preseed, the workstation egress table (site server + site resolver only;
  DoT/DoH refused), the hourly autosave sweep (12 h, no live session, as the user; journal tag chp-doc-sweep),
  logind KillUserProcesses=yes and the polkit no-linger rule. Requires onlyoffice-desktopeditors = 10.0.0,
  poppler-utils, chp-site >= 0.14.0-5.
