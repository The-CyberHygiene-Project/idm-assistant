Name:           chp-base
Version:        0.1.0
Release:        8.chp%{?dist}
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
Source8:        05-firstboot.sh
Source9:        76-disk-space.sh
Source10:       80-fapolicyd.sh
Source11:       fapolicyd-fsmark.sh
Source12:       fapolicyd-fsmark.conf
Source13:       66-chp-fsmark.rules
Requires:       fapolicyd
Requires:       mokutil
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
install -Dm0755 %{SOURCE8} %{buildroot}%{_prefix}/lib/chp/monitor.d/05-firstboot.sh
install -Dm0755 %{SOURCE5} %{buildroot}%{_prefix}/lib/chp/monitor.d/10-restorecon.sh
install -Dm0755 %{SOURCE6} %{buildroot}%{_prefix}/lib/chp/monitor.d/20-clock.sh
install -Dm0755 %{SOURCE9} %{buildroot}%{_prefix}/lib/chp/monitor.d/76-disk-space.sh
install -Dm0755 %{SOURCE10} %{buildroot}%{_prefix}/lib/chp/monitor.d/80-fapolicyd.sh
install -Dm0755 %{SOURCE11} %{buildroot}%{_libexecdir}/chp/fapolicyd-fsmark
install -Dm0644 %{SOURCE12} %{buildroot}%{_sysconfdir}/chp/fapolicyd-fsmark.conf
install -Dm0644 %{SOURCE13} %{buildroot}%{_sysconfdir}/fapolicyd/rules.d/66-chp-fsmark.rules
install -dm0700 %{buildroot}%{_sharedstatedir}/chp/firstboot
install -dm0700 %{buildroot}%{_sharedstatedir}/chp/monitor
install -Dm0644 %{SOURCE7} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%post
%systemd_post chp-firstboot-common.service chp-monitor.timer
%preun
%systemd_preun chp-firstboot-common.service chp-monitor.timer

%posttrans
# Apply the fapolicyd allow_filesystem_mark flag (shipped OFF = no change); idempotent. No restart inside the transaction: a change leaves /var/lib/chp/fapolicyd-restart-pending for a later step.
CHP_NO_RESTART=1 /bin/bash %{_libexecdir}/chp/fapolicyd-fsmark || :

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
%{_prefix}/lib/chp/monitor.d/05-firstboot.sh
%{_prefix}/lib/chp/monitor.d/10-restorecon.sh
%{_prefix}/lib/chp/monitor.d/20-clock.sh
%{_prefix}/lib/chp/monitor.d/76-disk-space.sh
%{_prefix}/lib/chp/monitor.d/80-fapolicyd.sh
%{_libexecdir}/chp/fapolicyd-fsmark
%dir %{_sysconfdir}/chp
%config(noreplace) %{_sysconfdir}/chp/fapolicyd-fsmark.conf
%config(noreplace) %{_sysconfdir}/fapolicyd/rules.d/66-chp-fsmark.rules
%dir %attr(0700,root,root) %{_sharedstatedir}/chp/firstboot
%dir %attr(0700,root,root) %{_sharedstatedir}/chp/monitor

%changelog
* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-8.chp
- Check 80: a service stuck activating/reloading past 30 min alerts; an unapplied allow_filesystem_mark restart (pending marker) alerts; case-insensitive Permissive parse.
- fapolicyd-fsmark: atomic conf rewrite (same mode/owner/label), clears a stale pending marker once the daemon restarted, clear message on write failure.

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-7.chp
- Check 80: runtime Permissive: line first, conf fallback, "cannot determine mode" alert, transient activating/reloading, missing unit alerts; Requires fapolicyd.
- fapolicyd-fsmark: no restart in the transaction (pending marker), never takes over an admin-set value, changed only on a successful write.

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-6.chp
- Monitor check 80: fapolicyd not running or in permissive mode (alerts once per state change, again after 24 h).
- allow_filesystem_mark mechanism: flag /etc/chp/fapolicyd-fsmark.conf (FSMARK=0, shipped OFF), /usr/libexec/chp/fapolicyd-fsmark, empty rules file 66-chp-fsmark.rules.

* Thu Nov 12 2026 The CyberHygiene Project - 0.1.0-5.chp
- Monitor check 76: mount points with spaces, partial df output, lvextend hint only on LVM, clock-step and garbage-state handling.

* Mon Nov 09 2026 The CyberHygiene Project - 0.1.0-4.chp
- Monitor check 76: any XFS file system at or above 85% full (alerts once per crossing, again after 24 h).

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-3.chp
- Secure Boot gate before the TPM binding; monitor check for a failed first boot / TPM binding / leftover one-time key.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-2.chp
- Kill the one-time LUKS slot in batch mode; a retry skips re-binding; retry hints say restart.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release: first-boot TPM binding via a one-time LUKS key, restorecon, ks shred; monitor framework.
