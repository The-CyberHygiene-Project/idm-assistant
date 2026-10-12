Name:           chp-integrity
Version:        0.1.0
Release:        1.chp%{?dist}
Summary:        CyberHygiene file integrity: AIDE baseline, daily check, monitor alerts
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        aide.conf
Source1:        aide-check.sh
Source2:        aide-baseline.sh
Source3:        chp-aide-check.service
Source4:        chp-aide-check.timer
Source5:        chp-aide-baseline.service
Source6:        60-aide-result.sh
Source7:        61-aide-stale.sh
Source8:        62-aide-pin.sh
Source9:        LICENSE
Requires:       aide, chp-base, chp-site >= 0.7.0, coreutils, util-linux, rpm
BuildRequires:  systemd-rpm-macros

%description
Core 0.2.0 file integrity (spec 2026-10-12): the CHP aide.conf (Rocky stock + SSG remediation + CHP additions), the first
baseline after first boot (or at package install on an existing host), a daily check whose result the CHP monitor
alerts on, and a reminder until the baseline's hash is pinned to the site stick. Baselines change only through
chp-site aide-accept (ISSO or BASELINE_DELEGATES, audited).

%install
install -Dm0600 %{SOURCE0} %{buildroot}%{_datadir}/chp-integrity/aide.conf
install -Dm0755 %{SOURCE1} %{buildroot}%{_libexecdir}/chp/aide-check
install -Dm0755 %{SOURCE2} %{buildroot}%{_libexecdir}/chp/aide-baseline
install -Dm0644 %{SOURCE3} %{buildroot}%{_unitdir}/chp-aide-check.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_unitdir}/chp-aide-check.timer
install -Dm0644 %{SOURCE5} %{buildroot}%{_unitdir}/chp-aide-baseline.service
install -Dm0755 %{SOURCE6} %{buildroot}%{_prefix}/lib/chp/monitor.d/60-aide-result.sh
install -Dm0755 %{SOURCE7} %{buildroot}%{_prefix}/lib/chp/monitor.d/61-aide-stale.sh
install -Dm0755 %{SOURCE8} %{buildroot}%{_prefix}/lib/chp/monitor.d/62-aide-pin.sh
install -dm0755 %{buildroot}%{_sharedstatedir}/chp/aide
install -dm0700 %{buildroot}%{_localstatedir}/log/aide
install -Dm0644 %{SOURCE9} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

# /etc/aide.conf belongs to the aide package; ours replaces it (the original is kept as .chp-orig once), and is put
# back if an aide update ever writes its own.
%triggerin -- aide
if [ -f /etc/aide.conf ] && ! cmp -s %{_datadir}/chp-integrity/aide.conf /etc/aide.conf; then
  [ -e /etc/aide.conf.chp-orig ] || cp -p /etc/aide.conf /etc/aide.conf.chp-orig
  install -m 0600 %{_datadir}/chp-integrity/aide.conf /etc/aide.conf
fi

%post
%systemd_post chp-aide-check.timer chp-aide-baseline.service
# An EXISTING host (a 0.1.0 install getting this package): its first boot is long done. Build the baseline now
# (asynchronously, so dnf is not held for minutes), mark it "package-install", start the daily timer.
if [ $1 -eq 1 ] && { [ -e /var/lib/chp/firstboot/server.done ] || [ -e /var/lib/chp/firstboot/client.done ]; }; then
  touch %{_sharedstatedir}/chp/aide/installed-on-existing-host
  systemctl enable --now chp-aide-check.timer >/dev/null 2>&1 || :
  systemctl enable chp-aide-baseline.service >/dev/null 2>&1 || :
  systemctl start --no-block chp-aide-baseline.service >/dev/null 2>&1 || :
fi

%preun
%systemd_preun chp-aide-check.timer chp-aide-baseline.service

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%dir %{_datadir}/chp-integrity
%attr(0600,root,root) %{_datadir}/chp-integrity/aide.conf
%{_libexecdir}/chp/aide-check
%{_libexecdir}/chp/aide-baseline
%{_unitdir}/chp-aide-check.service
%{_unitdir}/chp-aide-check.timer
%{_unitdir}/chp-aide-baseline.service
%{_prefix}/lib/chp/monitor.d/60-aide-result.sh
%{_prefix}/lib/chp/monitor.d/61-aide-stale.sh
%{_prefix}/lib/chp/monitor.d/62-aide-pin.sh
%dir %attr(0755,root,root) %{_sharedstatedir}/chp/aide
%dir %attr(0700,root,root) %{_localstatedir}/log/aide

%changelog
* Mon Oct 12 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (core 0.2.0 Plan A): aide.conf, aide-check + timer, aide-baseline, monitor checks 60/61/62.
