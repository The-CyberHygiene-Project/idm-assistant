Name:           chp-base
Version:        0.1.0
Release:        2.chp%{?dist}
Summary:        CyberHygiene common first boot (TPM binding) and monitor framework
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        firstboot-common.sh
Source1:        monitor.sh
Source2:        chp-firstboot-common.service
Source3:        chp-monitor.service
Source4:        chp-monitor.timer
Source5:        10-restorecon.sh
Source6:        20-clock.sh
Source7:        LICENSE
Requires:       chp-site, clevis, clevis-luks, clevis-dracut, clevis-systemd, tpm2-tools, cryptsetup, policycoreutils, chrony, util-linux
BuildRequires:  systemd-rpm-macros

%description
First boot on every CyberHygiene host: bind the root LUKS volume to the TPM (PCR 7) using a one-time key left by the
installer (its slot is removed afterwards), restore SELinux labels on the identity paths, and remove the installer's
kickstart copies. Also the monitor framework: a timer runs /usr/lib/chp/monitor.d/*, logs alerts and calls ALERT_HOOK.

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_libexecdir}/chp/firstboot-common
install -Dm0755 %{SOURCE1} %{buildroot}%{_libexecdir}/chp/monitor
install -Dm0644 %{SOURCE2} %{buildroot}%{_unitdir}/chp-firstboot-common.service
install -Dm0644 %{SOURCE3} %{buildroot}%{_unitdir}/chp-monitor.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_unitdir}/chp-monitor.timer
install -Dm0755 %{SOURCE5} %{buildroot}%{_prefix}/lib/chp/monitor.d/10-restorecon.sh
install -Dm0755 %{SOURCE6} %{buildroot}%{_prefix}/lib/chp/monitor.d/20-clock.sh
install -dm0700 %{buildroot}%{_sharedstatedir}/chp/firstboot
install -Dm0644 %{SOURCE7} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%post
%systemd_post chp-firstboot-common.service chp-monitor.timer
%preun
%systemd_preun chp-firstboot-common.service chp-monitor.timer

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%dir %{_libexecdir}/chp
%{_libexecdir}/chp/firstboot-common
%{_libexecdir}/chp/monitor
%{_unitdir}/chp-firstboot-common.service
%{_unitdir}/chp-monitor.service
%{_unitdir}/chp-monitor.timer
%dir %{_prefix}/lib/chp
%dir %{_prefix}/lib/chp/monitor.d
%{_prefix}/lib/chp/monitor.d/10-restorecon.sh
%{_prefix}/lib/chp/monitor.d/20-clock.sh
%dir %attr(0700,root,root) %{_sharedstatedir}/chp/firstboot

%changelog
* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-2.chp
- Kill the one-time LUKS slot in batch mode; a retry skips re-binding; retry hints say restart.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release: first-boot TPM binding via a one-time LUKS key, restorecon, ks shred; monitor framework.
