Name:           chp-security
Version:        0.3.0
Release:        1.chp%{?dist}
Summary:        CyberHygiene security add-on: Wazuh monitor checks, alert forwarder, retention, YARA and Suricata
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
Source11:       chp-yara-fullscan.service
Source12:       chp-yara-fullscan.timer
Source13:       73-yara-scan.sh
Source14:       chp-yara-recent.service
Source15:       chp-yara-recent.timer
Source16:       74-suricata.sh
Requires:       chp-site >= 0.11.0, chp-base, yara, chp-yara-rules, suricata, chp-suricata-rules
BuildRequires:  systemd-rpm-macros

%description
Security bundle part 1 (spec 2026-10-27): monitor checks for the Wazuh services, agents and data directory; the
chp-wazuh-alerts forwarder unit (chp-site wazuh-forward); daily alert-log retention; and drop-ins so Wazuh never
starts without its bind-mounted data directory. Part 2 (YARA spec 2026-11-01, §10): the chp-yara-recent timer (every 5 minutes) and
the weekly chp-yara-fullscan timer (scan only, alert only), and monitor check 73. Part 3 (Suricata spec 2026-11-04):
monitor check 74 and the Suricata and chp-suricata-rules dependencies. Wazuh and Suricata themselves are configured by
chp-site security enable.

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
install -Dm0644 %{SOURCE11} %{buildroot}%{_unitdir}/chp-yara-fullscan.service
install -Dm0644 %{SOURCE12} %{buildroot}%{_unitdir}/chp-yara-fullscan.timer
install -Dm0644 %{SOURCE14} %{buildroot}%{_unitdir}/chp-yara-recent.service
install -Dm0644 %{SOURCE15} %{buildroot}%{_unitdir}/chp-yara-recent.timer
install -Dm0755 %{SOURCE13} %{buildroot}%{_prefix}/lib/chp/monitor.d/73-yara-scan.sh
install -Dm0755 %{SOURCE16} %{buildroot}%{_prefix}/lib/chp/monitor.d/74-suricata.sh
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
%{_unitdir}/chp-yara-fullscan.service
%{_unitdir}/chp-yara-fullscan.timer
%{_unitdir}/chp-yara-recent.service
%{_unitdir}/chp-yara-recent.timer
%{_prefix}/lib/chp/monitor.d/73-yara-scan.sh
%{_prefix}/lib/chp/monitor.d/74-suricata.sh
%dir %attr(0700,root,root) %{_sharedstatedir}/chp/yara

%changelog
* Thu Nov 05 2026 The CyberHygiene Project - 0.3.0-1.chp
- Security bundle part 3 (Plan S1): Suricata IDS. Monitor check 74-suricata (running, stats fresh, drops under 1 %);
  requires suricata and chp-suricata-rules. Log rotation = EPEL's file, rewritten by chp-site with RETENTION_DAYS.

* Tue Nov 03 2026 The CyberHygiene Project - 0.2.0-2.chp
- Final-review fixes (Y1): unit time limits (TimeoutStartSec), monitor 73 also checks the 5-minute scan.

* Sun Nov 01 2026 The CyberHygiene Project - 0.2.0-1.chp
- Security bundle part 2 (Plan Y1): YARA. chp-yara-recent timer (every 5 minutes, every host, spec §10), weekly
  chp-yara-fullscan timer, monitor check 73-yara-scan; requires yara and chp-yara-rules.

* Tue Oct 27 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (security bundle Plan W1): monitor checks 70/71/72, alert forwarder unit, retention, mount drop-ins.
