Name:           chp-security
Version:        0.1.0
Release:        1.chp%{?dist}
Summary:        CyberHygiene security add-on: Wazuh monitor checks, alert forwarder and retention
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
Requires:       chp-site >= 0.8.0, chp-base
BuildRequires:  systemd-rpm-macros

%description
Security bundle part 1 (spec 2026-10-27): monitor checks for the Wazuh services, agents and data directory; the
chp-wazuh-alerts forwarder unit (chp-site wazuh-forward); daily alert-log retention; and drop-ins so Wazuh never
starts without its bind-mounted data directory. Wazuh itself is configured by chp-site security enable.

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

%post
%systemd_post chp-wazuh-alerts.service chp-wazuh-retention.timer
systemctl daemon-reload >/dev/null 2>&1 || :

%preun
%systemd_preun chp-wazuh-alerts.service chp-wazuh-retention.timer

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

%changelog
* Tue Oct 27 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (security bundle Plan W1): monitor checks 70/71/72, alert forwarder unit, retention, mount drop-ins.
