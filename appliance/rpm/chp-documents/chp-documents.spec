Name:           chp-documents
Version:        0.1.0
Release:        8.chp%{?dist}
Summary:        CyberHygiene documents role: NextCloud units, egress containment, web/PHP config, backup, cert renewal, nightly tag check, checks 77-79 and 81
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        nextcloud-httpd.conf
Source1:        nextcloud-lan.inc
Source2:        nextcloud-fpm.conf
Source3:        nextcloud-egress.nft
Source4:        nextcloud-egress-addr.nft.example
Source5:        chp-nextcloud-egress.service
Source6:        nextcloud-egress-validate.sh
Source7:        nextcloud-bindsto.conf
Source8:        nextcloud-bindsto-httpd.conf
Source9:        nextcloud-httpd-stock-off.sh
Source10:       nextcloud-cron.service
Source11:       nextcloud-cron.timer
Source12:       chp-nextcloud-backup
Source13:       chp-nextcloud-backup.service
Source14:       chp-nextcloud-backup.timer
Source15:       cert-renew-nextcloud.sh
Source16:       chp-nextcloud-cert-renew.service
Source17:       chp-nextcloud-cert-renew.timer
Source18:       65-chp-nextcloud.rules
Source19:       chp-documents-lib.sh
Source20:       77-nextcloud-services.sh
Source21:       78-nextcloud-cert.sh
Source22:       79-nextcloud-egress.sh
Source23:       README.md
Source24:       LICENSE
Source25:       chp-documents-check.service
Source26:       chp-documents-check.timer
Source27:       81-documents-tags.sh
Source28:       nextcloud-login-rewrite.conf
Source29:       chp-docs-ledger.path
Source30:       chp-docs-ledger.service
Source31:       chp-docs-ledger-alert.service
Source32:       82-docs-ledger.sh
Requires:       nextcloud-chp >= 35.0.3-6, chp-base >= 0.1.0-12, httpd, mod_ssl, php-fpm, postgresql-server, nftables, rsync, step-cli, openssl
Requires:       python3, firewalld, policycoreutils, util-linux, chp-site >= 0.14.0-7
# poppler-utils: pdftotext/pdfinfo for the marking check of reader PDFs at publish (chp_site.marking, Plan 3 Task 5)
Requires:       poppler-utils
Requires(post): policycoreutils-python-utils
BuildRequires:  systemd-rpm-macros

%description
The documents role (ISO 0.7.0 Plan 2). SITE-INDEPENDENT: it ships web/PHP configuration, the egress table, units,
timers, backup, certificate renewal, a fapolicyd rule, the nightly tag check and share canary
(chp-documents-check.timer runs `chp-site documents check`) and monitor checks 77 (services), 78 (certificate),
79 (egress table), 81 (the nightly check's result) and 82 (the document ledger: appender, chain, quarantine,
unfinished publishes). Nothing is enabled by installing it; `chp-site documents enable` renders the site-specific pieces
and starts the units. Until then everything FAILS CLOSED: httpd denies all, the egress unit refuses to start.

Files that `chp-site documents enable` must render (see /usr/share/doc/chp-documents/README.md):
  /etc/httpd/conf.d/chp-nextcloud-lan.inc    "Require ip <SUBNET_CIDR>" (shipped: "Require all denied")
  /etc/chp/nextcloud-egress-addr.nft         "define CHP_NC_SERVER_IP = <SERVER_IP>", exactly one line (absent or invalid: egress unit won't start)
  /etc/hosts                                 NextCloud's own names (apache has no DNS)
  /etc/chp/documents.conf                    ENABLED=yes, FQDN=..., SERVER_IP=... (must equal the address file), optional
                                             DOCUMENTS_BACKUP_DAYS=... (absent: checks silent OK)
  /etc/pki/nextcloud/{chain,key}.pem         the certificate: cert-renew-nextcloud --issue
The NextCloud audit file and the Wazuh index are CUI-boundary records: see the README (retention, no forwarding off
the appliance).

%install
install -Dm0644 %{SOURCE0} %{buildroot}%{_sysconfdir}/httpd/conf.d/chp-nextcloud.conf
install -Dm0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/httpd/conf.d/chp-nextcloud-lan.inc
install -Dm0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/php-fpm.d/nextcloud.conf
install -Dm0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/nftables/chp-nextcloud-egress.nft
install -Dm0644 %{SOURCE4} %{buildroot}%{_docdir}/%{name}/nextcloud-egress-addr.nft.example
install -Dm0644 %{SOURCE5} %{buildroot}%{_unitdir}/chp-nextcloud-egress.service
install -Dm0755 %{SOURCE6} %{buildroot}%{_libexecdir}/chp/nextcloud-egress-validate
install -Dm0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/systemd/system/php-fpm.service.d/chp-egress.conf
install -Dm0644 %{SOURCE8} %{buildroot}%{_sysconfdir}/systemd/system/httpd.service.d/chp-egress.conf
install -Dm0755 %{SOURCE9} %{buildroot}%{_libexecdir}/chp/nextcloud-httpd-stock-off
install -Dm0644 %{SOURCE10} %{buildroot}%{_unitdir}/nextcloud-cron.service
install -Dm0644 %{SOURCE11} %{buildroot}%{_unitdir}/nextcloud-cron.timer
install -Dm0755 %{SOURCE12} %{buildroot}%{_sbindir}/chp-nextcloud-backup
install -Dm0644 %{SOURCE13} %{buildroot}%{_unitdir}/chp-nextcloud-backup.service
install -Dm0644 %{SOURCE14} %{buildroot}%{_unitdir}/chp-nextcloud-backup.timer
install -Dm0755 %{SOURCE15} %{buildroot}%{_libexecdir}/chp/cert-renew-nextcloud
install -Dm0644 %{SOURCE16} %{buildroot}%{_unitdir}/chp-nextcloud-cert-renew.service
install -Dm0644 %{SOURCE17} %{buildroot}%{_unitdir}/chp-nextcloud-cert-renew.timer
install -Dm0644 %{SOURCE18} %{buildroot}%{_sysconfdir}/fapolicyd/rules.d/65-chp-nextcloud.rules
install -Dm0644 %{SOURCE19} %{buildroot}%{_prefix}/lib/chp/chp-documents-lib.sh
install -Dm0755 %{SOURCE20} %{buildroot}%{_prefix}/lib/chp/monitor.d/77-nextcloud-services.sh
install -Dm0755 %{SOURCE21} %{buildroot}%{_prefix}/lib/chp/monitor.d/78-nextcloud-cert.sh
install -Dm0755 %{SOURCE22} %{buildroot}%{_prefix}/lib/chp/monitor.d/79-nextcloud-egress.sh
install -Dm0644 %{SOURCE23} %{buildroot}%{_docdir}/%{name}/README.md
install -Dm0644 %{SOURCE24} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -Dm0644 %{SOURCE25} %{buildroot}%{_unitdir}/chp-documents-check.service
install -Dm0644 %{SOURCE26} %{buildroot}%{_unitdir}/chp-documents-check.timer
install -Dm0755 %{SOURCE27} %{buildroot}%{_prefix}/lib/chp/monitor.d/81-documents-tags.sh
install -Dm0644 %{SOURCE28} %{buildroot}%{_sysconfdir}/httpd/conf.d/chp-nextcloud-login-rewrite.inc
install -dm0700 %{buildroot}%{_sysconfdir}/pki/nextcloud
install -dm0700 %{buildroot}%{_sharedstatedir}/chp/documents
# the root appender (chp-site doc-ledger, Plan 3 Task 4): its units, and its root-only folders under /var/lib/chp-docs
# (nextcloud-chp owns /var/lib/chp-docs root:apache 0750 with spool/ and out/; apache must not read these three)
install -Dm0644 %{SOURCE29} %{buildroot}%{_unitdir}/chp-docs-ledger.path
install -Dm0644 %{SOURCE30} %{buildroot}%{_unitdir}/chp-docs-ledger.service
install -Dm0644 %{SOURCE31} %{buildroot}%{_unitdir}/chp-docs-ledger-alert.service
install -Dm0755 %{SOURCE32} %{buildroot}%{_prefix}/lib/chp/monitor.d/82-docs-ledger.sh
install -dm0700 %{buildroot}%{_localstatedir}/lib/chp-docs/ledger %{buildroot}%{_localstatedir}/lib/chp-docs/quarantine \
  %{buildroot}%{_localstatedir}/lib/chp-docs/work %{buildroot}%{_localstatedir}/lib/chp-docs/unfinished

%post
%systemd_post chp-nextcloud-egress.service nextcloud-cron.timer chp-nextcloud-backup.timer chp-nextcloud-cert-renew.timer chp-documents-check.timer
%systemd_post chp-docs-ledger.path
# the ledger, quarantine and work folders keep the generic var_lib_t (never an httpd_* type: the web server's domain
# gets no access there), pinned so that no broader rule for /var/lib/chp-docs can relabel them; DAC: root 0700
semanage fcontext -a -t var_lib_t '%{_localstatedir}/lib/chp-docs/(ledger|quarantine|work|unfinished)(/.*)?' 2>/dev/null || :
restorecon -R %{_localstatedir}/lib/chp-docs/ledger %{_localstatedir}/lib/chp-docs/quarantine \
  %{_localstatedir}/lib/chp-docs/work %{_localstatedir}/lib/chp-docs/unfinished >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
# the fapolicyd rule takes effect at the next rules load / fapolicyd restart (chp-site documents enable restarts it
# and reads fapolicyd-cli --check-status)
if [ -x /usr/sbin/fagenrules ]; then /usr/sbin/fagenrules --load >/dev/null 2>&1 || :; fi

%preun
%systemd_preun chp-nextcloud-egress.service nextcloud-cron.timer chp-nextcloud-backup.timer chp-nextcloud-cert-renew.timer chp-documents-check.timer
%systemd_preun chp-docs-ledger.path chp-docs-ledger.service

%postun
%systemd_postun nextcloud-cron.timer chp-nextcloud-backup.timer chp-nextcloud-cert-renew.timer chp-documents-check.timer
%systemd_postun chp-docs-ledger.path
# on upgrade the egress table is reloaded from the (possibly new) shipped file
%systemd_postun_with_restart chp-nextcloud-egress.service

# a httpd or mod_ssl update can bring back the stock listeners: switch them off again at once
%triggerin -- httpd, mod_ssl
%{_libexecdir}/chp/nextcloud-httpd-stock-off >/dev/null 2>&1 || :

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/nextcloud-egress-addr.nft.example
%config(noreplace) %{_sysconfdir}/httpd/conf.d/chp-nextcloud.conf
%config(noreplace) %{_sysconfdir}/httpd/conf.d/chp-nextcloud-lan.inc
%{_sysconfdir}/httpd/conf.d/chp-nextcloud-login-rewrite.inc
%config(noreplace) %{_sysconfdir}/php-fpm.d/nextcloud.conf
%{_sysconfdir}/nftables/chp-nextcloud-egress.nft
%ghost %attr(0644,root,root) %{_sysconfdir}/chp/nextcloud-egress-addr.nft
%{_unitdir}/chp-nextcloud-egress.service
%{_libexecdir}/chp/nextcloud-egress-validate
%{_sysconfdir}/systemd/system/php-fpm.service.d/chp-egress.conf
%{_sysconfdir}/systemd/system/httpd.service.d/chp-egress.conf
%{_libexecdir}/chp/nextcloud-httpd-stock-off
%{_unitdir}/nextcloud-cron.service
%{_unitdir}/nextcloud-cron.timer
%{_sbindir}/chp-nextcloud-backup
%{_unitdir}/chp-nextcloud-backup.service
%{_unitdir}/chp-nextcloud-backup.timer
%{_libexecdir}/chp/cert-renew-nextcloud
%{_unitdir}/chp-nextcloud-cert-renew.service
%{_unitdir}/chp-nextcloud-cert-renew.timer
%{_sysconfdir}/fapolicyd/rules.d/65-chp-nextcloud.rules
%{_prefix}/lib/chp/chp-documents-lib.sh
%{_prefix}/lib/chp/monitor.d/77-nextcloud-services.sh
%{_prefix}/lib/chp/monitor.d/78-nextcloud-cert.sh
%{_prefix}/lib/chp/monitor.d/79-nextcloud-egress.sh
%{_prefix}/lib/chp/monitor.d/81-documents-tags.sh
%{_prefix}/lib/chp/monitor.d/82-docs-ledger.sh
%{_unitdir}/chp-documents-check.service
%{_unitdir}/chp-documents-check.timer
%dir %attr(0700,root,root) %{_sysconfdir}/pki/nextcloud
%dir %attr(0700,root,root) %{_sharedstatedir}/chp/documents
%{_unitdir}/chp-docs-ledger.path
%{_unitdir}/chp-docs-ledger.service
%{_unitdir}/chp-docs-ledger-alert.service
%dir %attr(0700,root,root) %{_localstatedir}/lib/chp-docs/ledger
%dir %attr(0700,root,root) %{_localstatedir}/lib/chp-docs/quarantine
%dir %attr(0700,root,root) %{_localstatedir}/lib/chp-docs/work
%dir %attr(0700,root,root) %{_localstatedir}/lib/chp-docs/unfinished

%changelog
* Thu Nov 19 2026 The CyberHygiene Project - 0.1.0-8.chp
- ISO 0.7.0 Plan 3 Task 11a: the NextCloud vhost limits request bodies on chp_ledger's OCS route
  (/ocs/v1.php and /ocs/v2.php .../apps/chp_ledger/) to 96 MiB: the 64 MiB decoded publish cap is at most 85.33 MiB
  of base64, plus the JSON. The nightly backup copies the document ledger FIRST, under its shared lock, turns
  maintenance mode on and only then releases the lock (revises -7): no publish straddles the switch, and the
  appender waits for one rsync of the ledger and the switch, not the whole backup. Check 82 counts every quarantine entry (a held spool link or folder too).
  Requires chp-site >= 0.14.0-7 (the appender's set-aside and held files), nextcloud-chp >= 35.0.3-6 (chp_ledger
  1.0.1).

* Thu Nov 19 2026 The CyberHygiene Project - 0.1.0-7.chp
- ISO 0.7.0 Plan 3 (one release for the plan): the root appender's units (chp-docs-ledger.path/.service and the
  OnFailure alert) and its root-only folders (Task 4); monitor check 82 (Task 9): chp-docs-ledger.path active,
  chp-site doc-ledger verify, quarantine empty, no unfinished publish (doc-ledger pending: the durable records in
  /var/lib/chp-docs/unfinished, root 0700, var_lib_t; the ISSO resolves). The nightly backup copies the ledger
  under its shared lock, taken before maintenance mode and held until it is off (no publish runs in maintenance
  mode). Check 82: exit 1 without a PENDING line alerts; busy runs keep the state and alert after 4 in a row.
  Requires chp-site >= 0.14.0-6, nextcloud-chp >= 35.0.3-6 (chp_ledger).

* Sat Nov 14 2026 The CyberHygiene Project - 0.1.0-6.chp
- nextcloud-cron.service (lab round 3, D11): ExecStartPre=+/usr/sbin/nft ... runs as root (as apache it failed, "you
  must be root", and no background job ever ran); the job itself still runs as apache.
- Check 77 also alerts when the last nextcloud-cron.service run failed, and when NextCloud's core/lastcron (written by
  cron.php after each run) is older than 30 min, or absent 30 min after enable.
- chp-nextcloud-backup restore (D10): runs chp-site documents trust after occ maintenance:data-fingerprint (which
  rewrites config.php), so config.php's fapolicyd trust entry matches again; restore fails if it does not.
- README: restart verification (D6), background-job check, SSP/POA&M notes (OIDC code in the audit log url,
  fapolicyd 1.4.3-3 exit). Requires chp-site >= 0.14.0-4, chp-base >= 0.1.0-12, nextcloud-chp >= 35.0.3-5.

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-5.chp
- chp-nextcloud-backup: only directories named as UTC stamps are copies or partials (nothing else under
  /backup/nextcloud is touched); a lock that cannot be opened records FAILED (check 77 alerts)

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-4.chp
- chp-nextcloud-backup: only a directory with a MANIFEST (now written last, by rename) is a copy; a killed run's
  partial directory is neither the --link-dest base nor counted toward the 2 kept copies and is deleted at the
  start of the next run; one backup at a time (lock); README: du -sk overestimates hardlinked incrementals
- check 79: when the expected table cannot be built (unshare/nft) the alert says so and names the error
- Requires chp-site >= 0.14.0 (documents and doc commands)

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-3.chp
- Nightly tag check and share canary (Plan 2 Task 6): chp-documents-check.timer (03:10, after the backup) runs
  `chp-site documents check` (SQL outside chp_foldertag; app policy, team folders, config.php trust entry, public
  link and internal share canary on a CUI file); monitor check 81 reads its result
  (/var/lib/chp/documents/check.json): alerts once per new failure, again after 24 h, and when the result is missing
  or older than 26 h; DEGRADED (database MD5) shown, not alerted. ExecStopPost=chp-site documents canary-off
  (the canary account is never left enabled); no Persistent= catch-up. Requires chp-site >= 0.13.0.

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-2.chp
- Review fixes: check 79 builds the expected table from the shipped files in a throwaway netns every run (no
  snapshot to bless) and validates the rendered address file (one line, IPv4, = SERVER_IP), which the egress unit also
  refuses to load otherwise; backup is a --link-dest incremental, prunes (min 2 copies) or fails loudly (check 77) on a
  full /backup; suppressed alerts print "still failing"; rule 65 without ftype=; scriptlets; stock listeners/cgi-bin
  off on httpd/mod_ssl update; LAN Require in <Location>; state under /var/lib/chp/documents; UMask on backup;
  shared ACME lock and FQDN one-way door.

* Fri Nov 13 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (ISO 0.7.0 Plan 2 Task 4): NextCloud httpd (8443, LAN include fails closed) and php-fpm pool, no-DNS egress
  table with BindsTo + pre-check drop-ins and a load-time snapshot, cron and backup timers, ACME certificate renewal,
  fapolicyd rule 65, monitor checks 77-79.
