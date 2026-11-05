Name:           chp-site
Version:        0.11.0
Release:        2.chp%{?dist}
Summary:        CyberHygiene site files tool and installer gate
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        chp-site.pyz
Source1:        chp.repo
Source2:        RPM-GPG-KEY-cyberhygiene
Source3:        LICENSE
Source4:        chp-site.sh
Source5:        RPM-GPG-KEY-WAZUH
Source9:        RPM-GPG-KEY-EPEL-9
Requires:       python3, openssl, util-linux

%description
chp-site validates the site files (site.conf, hosts, client.conf) and writes client.conf on the identity server.
It also ships the project signing key and a disabled repo definition for signed update tarballs.

%install
install -Dm0644 %{SOURCE0} %{buildroot}%{_datadir}/chp-site/chp-site.pyz
install -Dm0755 %{SOURCE4} %{buildroot}%{_bindir}/chp-site
install -Dm0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/yum.repos.d/chp.repo
install -Dm0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
install -Dm0644 %{SOURCE5} %{buildroot}%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-WAZUH
install -Dm0644 %{SOURCE9} %{buildroot}%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9
install -dm0755 %{buildroot}%{_sharedstatedir}/chp/repo
install -Dm0644 %{SOURCE3} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_bindir}/chp-site
%dir %{_datadir}/chp-site
%{_datadir}/chp-site/chp-site.pyz
%config(noreplace) %{_sysconfdir}/yum.repos.d/chp.repo
%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-WAZUH
%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9
%dir %{_sharedstatedir}/chp
%dir %{_sharedstatedir}/chp/repo

%changelog
* Thu Nov 05 2026 The CyberHygiene Project - 0.11.0-2.chp
- Ships the pinned EPEL 9 key; security enable checks its fingerprint and imports it with Wazuh's before dnf (the S1
  lab proof found dnf refusing the EPEL-signed suricata, hiredis and hyperscan without it).

* Thu Nov 05 2026 The CyberHygiene Project - 0.11.0-1.chp
- Security bundle part 3 (Plan S1): security enable installs Suricata and chp-suricata-rules, writes the IDS-only
  config for this host's site interface (HOME_NET = SUBNET), the service drop-in, log rotation with RETENTION_DAYS,
  and (server) the Wazuh severity rules; both roles forward eve.json alerts to Wazuh.

* Tue Nov 03 2026 The CyberHygiene Project - 0.10.0-2.chp
- Final-review fixes (Y1): byte-safe scan lists, names with line breaks scanned one by one, failed yara runs not
  recorded as success, /run/user watched, exit status 1 on errors.

* Sun Nov 01 2026 The CyberHygiene Project - 0.10.0-1.chp
- Security bundle part 2 (Plan Y1): chp-site yara-scan (--recent every 5 minutes, --full weekly; alert only);
  security enable installs YARA and its rules and starts both timers. Wazuh file monitoring and active response stay
  off (YARA spec §10).

* Fri Oct 30 2026 The CyberHygiene Project - 0.9.0-3.chp
- W2 final review I1: a client's staged agent key is shredded only after the agent runs, and a retried first boot
  reuses the installed key, so a failed security step can always be retried.

* Thu Oct 29 2026 The CyberHygiene Project - 0.9.0-2.chp
- W2 lab: a client's first boot waits (up to 2 min) for the agent's first sync, so AIDE's first baseline includes it.

* Thu Oct 29 2026 The CyberHygiene Project - 0.9.0-1.chp
- Security bundle W2: SECURITY_ADDONS / SECURITY_ALERT_LEVEL site keys; security enable --firstboot (pending
  folder on the server, staged key on clients; no USB); export-client moves Wazuh agent keys; pre stages a client's key
  and the ISO's repo path.

* Wed Oct 28 2026 The CyberHygiene Project - 0.8.0-3.chp
- Final review: security enable locks the Wazuh API's default logins with random passwords (never stored); manager
  update_check off; agent upgrade module off; forwarder never crash-loops (odd alerts, hook errors), checkpoints per
  alert and drains the old file on rotation; key check uses a private GnuPG home; AIDE explains Wazuh-signed files.

* Tue Oct 27 2026 The CyberHygiene Project - 0.8.0-2.chp
- Lab proof: Wazuh 4.14's API wants host as a list (a scalar stopped wazuh-apid); a failed step is now a clear
  message naming the command, not a traceback.

* Tue Oct 27 2026 The CyberHygiene Project - 0.8.0-1.chp
- Security bundle: security enable|status, alerts, wazuh-forward; ships Wazuh's signing key
  (pinned 0DCFCA5547B19D2A6099506096B3EE5F29111145).

* Sun Oct 25 2026 The CyberHygiene Project - 0.7.3-1.chp
- validate: never runs a chp-templates renderer found next to the site folder (it could be any mounted volume);
  only CHP_TEMPLATES, an explicit path or /usr/share/chp-templates (Plan C3 final review).

* Sun Oct 25 2026 The CyberHygiene Project - 0.7.2-1.chp
- docs: render the site's SSP and POA&M from the site stick's profile.ini with the installed chp-templates renderer
  into /var/lib/chp/docs/<UTC timestamp>/ (root-only, never overwritten).

* Fri Oct 16 2026 The CyberHygiene Project - 0.7.1-1.chp
- stick-pin-hash: pin the plugged-in, still blocked site stick's USBGuard hash without allowing it; aide-baseline
  runs it before aide --init so the first stick use no longer alerts (quiet check 2026-10-16).

* Mon Oct 12 2026 The CyberHygiene Project - 0.7.0-1.chp
- aide-accept (ISSO or BASELINE_DELEGATES; audited; explained/unexplained summary), aide-pin, aide-verify-pin;
  export-client pins the server's AIDE baseline; BASELINE_DELEGATES in site.conf (core 0.2.0, spec 2026-10-12).

* Sat Oct 10 2026 The CyberHygiene Project - 0.6.1-1.chp
- pre: per-host random boot-loader password, escrowed on the site stick; kickstart gets only its PBKDF2 hash
  (ISSO 2026-10-10, CUI rule grub2_password).

* Sat Oct 10 2026 The CyberHygiene Project - 0.6.0-1.chp
- verify-repo: the installer checks the repo signature before installing (row 37).

* Thu Oct 01 2026 The CyberHygiene Project - 0.5.1-1.chp
- onboard refuses a person or group named like a local account/group (short names on the hosts; final review I1).

* Thu Oct 01 2026 The CyberHygiene Project - 0.5.0-1.chp
- Second factor (ISO Plan 4b): GA PAM lines in authselect-patch (Kanidm users; local accounts skip), ga-enrol USER [--reset] [--no-confirm] (host-local token, 5 scratch codes, audited), pam-test SERVICE USER (row 36).

* Wed Sep 30 2026 The CyberHygiene Project - 0.4.0-1.chp
- Per-client unixd tokens (pre stages the client's own; export-client moves them with read-back; client-token HOST), chp-site get with client.conf values, COLLECTOR_SSH_PUBKEY, authselect-patch, onboard adds chp_users (ISO Plan 4a).

* Wed Sep 30 2026 The CyberHygiene Project - 0.3.0-1.chp
- onboard / revoke / unexpire (spec 4.4; ISSO #28, #32); client.conf CACHE_PUBKEY; audit records before and after every change.

* Wed Sep 30 2026 The CyberHygiene Project - 0.2.2-1.chp
- Escrow write fsync'd and read back from the device before shredding; only a storage-only pinned stick; stick always re-blocked.

* Wed Sep 30 2026 The CyberHygiene Project - 0.2.1-1.chp
- export-client allows only the pinned site stick through USBGuard, temporarily; pre records the stick identity.

* Wed Sep 30 2026 The CyberHygiene Project - 0.2.0-1.chp
- get/render for server config; export-client moves the server's pending recovery secrets to the stick
  (write, sync, read back, then shred); final-review fixes from 0.1.0.

* Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release: validate, pre, export-client; project key; disabled local repo definition.
