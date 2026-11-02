Name:           chp-security
Version:        0.2.0
Release:        1.chp%{?dist}
Summary:        CyberHygiene security add-on: Wazuh monitor checks, alert forwarder, retention and YARA scanning
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        70-wazuh-service.sh
Source1:        71-wazuh-agents.sh
Source2:        72-wazuh-disk.sh
Source3:        chp-wazuh-alerts.service
Source4:        chp-wazuh-retention.service
Source5:        chp-wazuh-retention.timer
Source6:        wazuh-retention.sh
Source7:        wazuh-manager.override.conf
Source8:        wazuh-agent.override.conf
Source9:        LICENSE
Source10:       chp-yara-scan
Source11:       chp-yara-fullscan.service
Source12:       chp-yara-fullscan.timer
Source13:       73-yara-scan.sh
Source14:       chp-yara-recent.service
Source15:       chp-yara-recent.timer
Requires:       chp-site >= 0.10.0, chp-base, yara, chp-yara-rules
BuildRequires:  systemd-rpm-macros

%description
Security bundle part 1 (spec 2026-10-27): monitor checks for the Wazuh services, agents and data directory; the
chp-wazuh-alerts forwarder unit (chp-site wazuh-forward); daily alert-log retention; and drop-ins so Wazuh never
starts without its bind-mounted data directory. Part 2 (YARA spec 2026-11-01): the Wazuh active-response wrapper
chp-yara-scan (scan only, alert only), the weekly chp-yara-fullscan timer and monitor check 73. Wazuh itself is
configured by chp-site security enable.

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_prefix}/lib/chp/monitor.d/70-wazuh-service.sh
install -Dm0755 %{SOURCE1} %{buildroot}%{_prefix}/lib/chp/monitor.d/71-wazuh-agents.sh
install -Dm0755 %{SOURCE2} %{buildroot}%{_prefix}/lib/chp/monitor.d/72-wazuh-disk.sh
install -Dm0644 %{SOURCE3} %{buildroot}%{_unitdir}/chp-wazuh-alerts.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_unitdir}/chp-wazuh-retention.service
install -Dm0644 %{SOURCE5} %{buildroot}%{_unitdir}/chp-wazuh-retention.timer
install -Dm0755 %{SOURCE6} %{buildroot}%{_libexecdir}/chp/wazuh-retention
install -Dm0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/systemd/system/wazuh-manager.service.d/chp.conf
install -Dm0644 %{SOURCE8} %{buildroot}%{_sysconfdir}/systemd/system/wazuh-agent.service.d/chp.conf
install -dm0755 %{buildroot}%{_sharedstatedir}/chp/wazuh
install -Dm0644 %{SOURCE9} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -Dm0750 %{SOURCE10} %{buildroot}/var/ossec/active-response/bin/chp-yara-scan
install -Dm0644 %{SOURCE11} %{buildroot}%{_unitdir}/chp-yara-fullscan.service
install -Dm0644 %{SOURCE12} %{buildroot}%{_unitdir}/chp-yara-fullscan.timer
install -Dm0644 %{SOURCE14} %{buildroot}%{_unitdir}/chp-yara-recent.service
install -Dm0644 %{SOURCE15} %{buildroot}%{_unitdir}/chp-yara-recent.timer
install -Dm0755 %{SOURCE13} %{buildroot}%{_prefix}/lib/chp/monitor.d/73-yara-scan.sh
install -dm0700 %{buildroot}%{_sharedstatedir}/chp/yara

%post
%systemd_post chp-wazuh-alerts.service chp-wazuh-retention.timer chp-yara-fullscan.timer chp-yara-recent.timer
systemctl daemon-reload >/dev/null 2>&1 || :

%preun
%systemd_preun chp-wazuh-alerts.service chp-wazuh-retention.timer chp-yara-fullscan.timer chp-yara-recent.timer

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_prefix}/lib/chp/monitor.d/70-wazuh-service.sh
%{_prefix}/lib/chp/monitor.d/71-wazuh-agents.sh
%{_prefix}/lib/chp/monitor.d/72-wazuh-disk.sh
%{_unitdir}/chp-wazuh-alerts.service
%{_unitdir}/chp-wazuh-retention.service
%{_unitdir}/chp-wazuh-retention.timer
%{_libexecdir}/chp/wazuh-retention
%{_sysconfdir}/systemd/system/wazuh-manager.service.d/chp.conf
%{_sysconfdir}/systemd/system/wazuh-agent.service.d/chp.conf
%dir %attr(0755,root,root) %{_sharedstatedir}/chp/wazuh
%attr(0750,root,root) /var/ossec/active-response/bin/chp-yara-scan
%{_unitdir}/chp-yara-fullscan.service
%{_unitdir}/chp-yara-fullscan.timer
%{_unitdir}/chp-yara-recent.service
%{_unitdir}/chp-yara-recent.timer
%{_prefix}/lib/chp/monitor.d/73-yara-scan.sh
%dir %attr(0700,root,root) %{_sharedstatedir}/chp/yara

%changelog
* Sun Nov 01 2026 The CyberHygiene Project - 0.2.0-1.chp
- Security bundle part 2 (Plan Y1): YARA. Active-response wrapper chp-yara-scan, weekly chp-yara-fullscan timer,
  monitor check 73-yara-scan; requires yara and chp-yara-rules. Clients: chp-yara-recent timer (every 5 minutes,
  spec §10).

* Tue Oct 27 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (security bundle Plan W1): monitor checks 70/71/72, alert forwarder unit, retention, mount drop-ins.
