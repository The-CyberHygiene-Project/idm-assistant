Name:           chp-site
Version:        0.14.0
Release:        13.chp%{?dist}
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
* Fri Nov 27 2026 The CyberHygiene Project - 0.14.0-13.chp
- P3-D16: the document ledger's journal line (the one the Wazuh decoder reads) carries at most the first 400 bytes of an
  entry's reason, cut on a UTF-8 boundary and ending "...[truncated; full text in the ledger]", so the level-12 alert for
  rule 100643 (ISSO override) always expands the user and the path (a ~2000-byte reason left them as raw $(dstuser) and
  $(path)). The ledger keeps the whole reason. If the line is still too long, the notes are shortened before the reason.
  Nothing else changed.

* Sun Nov 22 2026 The CyberHygiene Project - 0.14.0-12.chp
- ISO 0.7.0 Plan 3 Task 14 (the final review's fix wave), the ledger appender: control characters refused in reason
  and notes (as chp_ledger 1.0.3 does); a journal line that logger --size would cut silently is shortened (reason and
  notes, then other long text, by size and sha256) or, if it still cannot fit, goes to stderr; OccStore turns a
  database failure (SiteError, psql timeout 45 s) into a store error (refused or undone, never quarantined); an
  unexpected error after an incomplete undo keeps "UNDO INCOMPLETE"; canonical reads opened component by component
  with O_NOFOLLOW, regular files only, at most 64 MiB; pending reads the journal before the lock; deeply nested JSON
  is "not valid JSON"; a reader PDF cannot be checked out, created or published as a document of its own; new Wazuh
  rule 100656 (quarantine purged, level 7), start-marker-clear-failed level 7; the daily review no longer lists the
  document workflow's alerts as NextCloud intrusions (publications and overrides come from the ledger; the
  appender's faults are kind "documents").
- Marking: the wrong-banner search of a docx header/footer reads text boxes, shapes, hidden runs, every
  AlternateContent branch, DrawingML text and VML watermarks; section properties only where Word reads them (others,
  and one on a deleted paragraph mark, are a problem; insert refuses); header/footer relationships and parts must be
  headers and footers; Markdown required banners from LF/CR lines (the wrong banner in both readings); names at most
  255 UTF-8 bytes and one CUI_/FCI_ prefix; xlsx insert never replaces a first-page footer's left section.
- doc: a kept request id answered 409 that the server holds nothing for is dropped with a refusal; doc logout
  --forget; the runtime dir must be /run/user/<uid>; doc mark help says CUI/FCI marks.
* Sat Nov 21 2026 The CyberHygiene Project - 0.14.0-11.chp
- ISO 0.7.0 Plan 3 Task 13d (P3-D15, lab logs/226): onlyoffice egress-recovered treats a missing Wazuh agent state
  file as a stopped agent when the agent is installed (wazuh-agent package or its systemd unit): the recovery report
  is held, sent after 60 min anyway with the ALERT, as for a stale file. A state file that cannot be read holds it
  too, with a note. Only a host with no agent at all reports at once. Review: only rpm's clean "is not installed"
  means no agent (a locked rpmdb, a missing rpm, a hang past 30 s or any other failure holds the report), the
  wazuh-agentd binary counts as installed, and a garbled (non-UTF-8) state file holds with a note, not a crash.
* Fri Nov 20 2026 The CyberHygiene Project - 0.14.0-10.chp
- ISO 0.7.0 Plan 3 Task 13a (the 11c lab defects). doc commands: NextCloud's 502/503/504 before anything is sent
  (maintenance mode, the backup window) and a 401 while Kanidm is unreachable (probed at /status) are pending, exit 3
  (P3-D8, D9), as is Kanidm unreachable before a send; x2t gets m_nCsvTxtEncoding 46 for a Markdown document's text
  copy (D10); --notes/--reason over 2000 UTF-8 bytes are refused in plain words before sending (D13); doc login
  shows the sign-in end as a labelled estimate (login + 8 h) when Kanidm's introspection says inactive (D12) and
  refuses a NextCloud account with no groups (sign in once on the web: D3).
- appender: the loser of a publish race is told the current version changed, by whom and as which CR (D4); a spool
  file set aside once and still undeletable is remembered by identity, so it is not re-quarantined (D11).
- documents enable: after each fapolicyd trust update, php's read of config.php is polled (bounded) before the next
  occ call (D1); the nightly check alerts every Kanidm (user_oidc) account with no groups (D3); Wazuh rules 100633/
  100634 (chp_ledger's no-groups audit line, level 12) and 100635/100636 (a workstation's egress lock-down / render
  failure has ended, levels 12/7).
- onlyoffice: enable installs chp-templates where missing (D2); egress-lockdown and egress-recovered: one recovery
  line after a lock-down or render failure once the Wazuh agent is connected (D7); the address file is relabelled on
  every render (O5).
- marking: a lower-case or split sp-<category> after a cited document name is a banner in wide positions (12b minor).
- review fix round 1: Kanidm /status answers other than 5xx/429 mean Kanidm is up (the refusal stands); a checkout
  recorded before its download failed says so (exit 3, never "refused"); a recovery report needs an agent state
  written after the failure's END and goes anyway (with an ALERT) 60 min after it; undeletable strays are counted
  once; the no-groups check leaves disabled accounts out; 100634 is in chp_doc_refused/chp_account.

* Fri Nov 20 2026 The CyberHygiene Project - 0.14.0-9.chp
- ISO 0.7.0 Plan 3 Task 12b (marking check hardening, round-3 re-review): the wrong-banner search drops combining
  marks (accents, underlines, enclosing circles) in every format; in every format it also trims quotes, brackets and
  ellipses from both ends, reads "/ /" as "//", the word spelled out letter by letter (C-U-I, C.U.I.) as the word,
  and the phrase with hyphens or underscores between its words. Markdown: <br> and block tags split a line into
  the lines it renders as; footnote references and trailing {#id} attribute blocks are removed; an indented code
  block (4 columns after a blank line, outside a list) is exempt like a fenced one (the first and last lines stay
  banner positions). Every Markdown reading is linear in the line, and a judged line over 8192 characters is
  refused ("cannot be checked"), so a crafted file cannot stall the check or the publish. The required banner stays
  the exact ASCII text. In banner positions (every header/footer, the Markdown first and last lines) the other
  kind's word followed by white space and anything is a banner too ("CUI SP-PROPIN"; controller ruling), so
  "# CUI handling policy" can no longer open a non-CUI Markdown file. chp-documents and chp-identity-server now
  require this release. Review fix round 1: in banner positions the word followed by ANY non-alphanumeric character
  (CUI/SP-PROPIN, CUI_SP-PROPIN, CUI.X) counts; in the Markdown body / and the middle dots join the separators;
  indented text after a footnote definition, a definition line or an admonition head is judged (it renders as text).
  Fix round 2: pandoc "~" definitions and "===" tab heads open a container too; a document name after the word
  (CUI_SSP_v1.2, <title>_vX.Y, ASCII digits) is a citation, not a banner, in banner positions. Fix round 3: only the
  name token is carved out; what follows it is still a banner when it holds //, the word, the phrase or a capitals
  marking; an SP- title is no citation; Markdown and docx give the same verdict; ===+/===! tab heads are containers.
  Fix round 4: one Latin-confusables fold (Unicode confusables data, ICU 78.3) replaces the hand-made lookalike
  list in every wrong-banner check (never the required banner); the text after a cited name is read like a line
  start (C U I, cul, Cu1); a further document name in it is a citation (CUI_SSP_v1.2, CUI_POAM_v1.0 passes).

* Fri Nov 20 2026 The CyberHygiene Project - 0.14.0-8.chp
- ISO 0.7.0 Plan 3 Task 12 (owner decisions 2026-11-20):
- FCI is marked "FCI": in the CUI area an FCI_ document needs the banner FCI (top and bottom, the same places and
  false-pass defences as the CUI banner) and no CUI designation block; a CUI banner on an FCI_ document, an FCI
  banner on a CUI_ document, and either one in the non-CUI area are problems (the wrong banner is searched with
  lookalikes folded). marking.insert puts only the FCI banner into an FCI_ draft. `chp-site doc new <title> --fci`
  makes FCI_<title>_v0.1-DRAFT.<ext> from /usr/share/chp-templates/doc/fci/ for CUI/Compliance (no CUI site keys
  needed). The nightly tag check accepts the CUI tag on an FCI_ file in the CUI and Archive team folders (tagging is
  by folder; FCI_ controlled documents publish into CUI/Compliance).
- Time from the CHP server only: `chp-site time-sync --role server|client` (root; first boot runs it). The server
  serves NTP to the site subnet only (chrony allow <SUBNET>, local stratum 10, the CUI profile's port 0 off;
  firewalld 123/udp from <SUBNET> only: the owner-approved exception to "no new network port"). A workstation's
  chrony uses the server only. The client kickstart's timesource is the server; the workstation egress addresses
  give chronyd the server only (the any-address path for host names in NTP_UPSTREAM is gone).
- marking.insert now refuses, for CUI_ as well as FCI_ files, a file where nothing can be added but the check still
  fails (it used to answer "nothing to add").
- Review fix round 1: the wrong-banner search covers every Markdown line outside code fences (insert refuses a
  Markdown draft that carries the other banner, instead of wrapping the right one around it), docx header/footer
  text boxes, spelled-out forms ("FCI - Federal Contract Information", "Controlled Unclassified Information"), and
  folds format characters (zero-width, soft hyphen) and l/1 as i; the FCI block check matches `cui category:` with
  any spacing. time-sync: the server's chrony serves on SERVER_IP only (bindaddress); a workstation keeps maxpoll 16
  (taken from a pool line too, or added) and waits up to about a minute for sync (warning only). doc check labels
  the marks from the checker's reading of the name.
- Review fix round 2: in Markdown the wrong-banner search reads each line without its markup (headings, quotes,
  lists, HTML tags, emphasis/code wrappers, a hard-break backslash), and judges the body with the banner forms only
  (the word alone or spaced out, the word with //markings, the word or the spelled-out phrase with a separator and
  at most 4 words after it), so prose about CUI and FCI is no false alarm; the separator and phrase forms no longer
  read l/1 as i. The server's chrony also binds IPv6 to loopback only (bindaddress ::1).
- Review fix round 3 (controller design): each Markdown line is normalised before banner matching (HTML entities
  decoded, NBSP/Cf/comments/tags removed, link, image and reference syntax reduced to the text, backslash escapes
  removed, table rows split into cells, markers and surrounding brackets/punctuation stripped). A tail that starts
  with the spelled-out phrase or holds // counts at any length, in every format. The first and last non-blank
  Markdown lines use the wide forms (fail closed), and insert refuses on them. l/1 read as i again in the wide forms
  (all headers/footers, Markdown first/last); in the Markdown body only in CUl/FCl capitals; the phrase accepts l, i
  and 1 alike. The Markdown body's short tail is at most 3 words.

* Thu Nov 19 2026 The CyberHygiene Project - 0.14.0-7.chp
- ISO 0.7.0 Plan 3 Task 11a (pre-sign fold of the Tasks 2-10 reviews):
- doc-ledger: the server's marking check gets the current versions of the document's area folder, so superseded
  citations are reported; they never refuse and are named in the publish result.
- doc-ledger process never stops for good: when it cannot set up (site.conf or documents.conf unreadable) every
  spooled request is deleted and answered retry (never refused, never over a done/refused result), appender-failed
  journalled once until a start succeeds; a stray *.json in the spool is set aside (more than 5: one alert); a spool
  file that cannot be deleted is moved into quarantine and rewritten without its Bearer token (one that cannot be
  moved either is alerted once). purge-quarantine also removes held links and folders. A publish refused by occ
  because NextCloud is in maintenance mode (the nightly backup) is answered retry.
- doc-ledger: a logger failure goes to stderr (the unit's journal), never silently; verify (and export's verify.txt)
  report a ledger with entries but no ledger.head; an occ timeout whose process group cannot be killed is still an
  OccTimeout (unknown outcome).
- doc (workstation): on a kept request id a lasting 400/403/413 is refused and the id dropped only when the result
  look-up answers 404 (done/refused there is answered; queued, retry, 401, 5xx stay pending); 401/409/429/5xx stay
  pending; a proxy's 502/503/504 on the first POST is pending.
- documents enable warns when SECURITY_ALERT_LEVEL is above 12 (approvals and overrides would reach only the daily
  summary); a warning, never a refusal.

* Thu Nov 19 2026 The CyberHygiene Project - 0.14.0-6.chp
- ISO 0.7.0 Plan 3 Task 9: the document ledger's journal lines decoded (Wazuh decoder chp-docs-ledger, written by
  documents enable with the rules and rolled back with them) and alerted: approve and override 100642/100643 level 12,
  publish 100644 level 7, checkout/new level 3, quarantine, appender failure, publish-undo-failed and
  ledger-partial-line level 12, publish-undone and the ISSO's resolve level 7. 100629: a Kanidm sign-in adding an
  account to admin or cui-users pages. 100631: the workstation sweep's failures (level 7); 100632: a failed egress
  render at start (level 7, one line "EGRESS RENDER FAILED", the address file restorecon'd when replaced).
- doc-ledger pending|resolve: unfinished publishes (started and never ended, or undo incomplete) for monitor check 82;
  the ISSO's resolve is a chained ledger entry (kind resolve, cycle 0).
- Review fix 1: durable root-only records /var/lib/chp-docs/unfinished/<request id> (written before a publish's
  first write; journal rotation or a forged line cannot clear them); only root's journal lines are read (_UID=0);
  every ledger reader takes the shared lock (BUSY = exit 3); a review built while the ledger did not verify
  (ledger_ok false) never moves the overrides' "since" past its day, and its row is in Needs attention.
- Review fix 2: an existing unfinished record refuses a re-sent publish (only resolve removes it); doc-ledger
  pending/verify/resolve turn OS errors into exit 2; Wazuh 100655 (unfinished-record-failed, level 12) and
  unfinished-clear-failed in 100652 (level 7).
- The daily review: each publication of the day, and each ISSO override since the last signed review as "Needs
  attention" (read from the verified document ledger).
- documents check: every group reaching a Compliance/Superseded area has the read-only rule (Internal included, and
  groups mapped there by hand); Internal's advanced permissions and other area rules; chp_ledger enabled with the
  documents.conf area ids.

* Thu Nov 19 2026 The CyberHygiene Project - 0.14.0-5.chp
- ISO 0.7.0 Plan 3 (Tasks 1-8, one release for the plan's chp-site changes so far): documents enable's doc-workflow
  steps; doc-ledger (the root appender); doc (the workstation's controlled-document commands); marking; the template
  fill of doc new.
- onlyoffice enable|sweep|egress-render (Task 8): the workstation's editor (chp-onlyoffice), its egress table
  addresses from the site files, the hourly autosave sweep (12 h, no live session, as the user; tag chp-doc-sweep),
  linger off. Wazuh rules 100626 (sweep, level 3) and 100627 (workstation egress block, level 7) in the documents
  rules file, outside the review's NextCloud rows.

* Sat Nov 14 2026 The CyberHygiene Project - 0.14.0-4.chp
- documents enable (lab round 3, D6): the fapolicyd restart is proven: active at three samples over about 5 s, a
  parsed "Denied accesses" counter, then chp-base's fapolicyd-fsmark --verify; a fapolicyd found dead (the known
  1.4.3-3 "recvmesg failed" exit) is restarted once more; dead again, or no counter, fails the run loudly (check 80,
  POA&M) and keeps the restart mark for the next run. "Denied accesses: unknown" is never printed as success.
- documents enable: the AIDE note names what the run changed, and says no refresh is needed when nothing changed.
- documents trust (new, D10): config.php's fapolicyd trust entry made equal to the file and read back, no fapolicyd
  restart; chp-nextcloud-backup restore runs it after occ maintenance:data-fingerprint.
- Wazuh (D9): rule 100620 (egress block) is a child of the firewall rule 4100 that takes the kernel line first
  (it never fired); rule 100630 matches only "Auth result: Denied: incorrect totp" (one alert per wrong code, not 3).
  Both proven with wazuh-logtest on Wazuh 4.14.7.

* Sat Nov 14 2026 The CyberHygiene Project - 0.14.0-3.chp
- documents enable: /etc/nextcloud/config.php (a minimal empty config when absent) and its fapolicyd trust entry
  exist BEFORE the first occ call: maintenance:install reads back the config.php it writes, which fapolicyd denied
  (lab D3). A config.php left by a failed install gets its entry refreshed, so a re-run recovers.
- documents enable: appstore is no longer disabled (always enabled in NextCloud 35, lab D4); the store stays off by
  appstoreenabled=false; APPS_OFF never holds an always-enabled app (test). The office app is disabled (as the spike).
- Kanidm 1.11 `group get` of a missing group prints "No matching group '<name>'": read as absent, not an error.

* Fri Nov 13 2026 The CyberHygiene Project - 0.14.0-2.chp
- Wazuh static user field: NextCloud rules 100618 (nightly canary enable) and 100608 (canary refusal) match the audit
  user with <user>, not <field name="user"> (a static field; wazuh-analysisd -t refused the rule set, so documents
  enable rolled back). A test bans <field name=...> on any Wazuh static field in every generated rule set.

* Fri Nov 13 2026 The CyberHygiene Project - 0.14.0-1.chp
- Documents server role (ISO 0.7.0 Plan 2): DOCUMENTS / FILES_FQDN site keys, the files record and the apache hosts
  file; `chp-site documents enable|status|check|canary-off`: NextCloud enabled idempotently (team folders, Kanidm
  OIDC, tags and folder rules, egress address, fapolicyd trust for config.php, Wazuh rules with a checked
  rollback), the nightly tag check and share-link canary, and the DEGRADED database-MD5 state.
- Daily review: a NextCloud section (tag check, canary, DEGRADED state, the NextCloud Wazuh rule set incl. egress).
- Wazuh rollback after a failed rule check restores each piece on its own and names whatever was not rolled back.

* Wed Nov 11 2026 The CyberHygiene Project - 0.13.0-2.chp
- Daily review: a short-lived certificate is ATTENTION below 30 % of its lifetime left (was half), so a healthy
  24-hour Kanidm certificate no longer shows ATTENTION before its renewal point.

* Mon Nov 09 2026 The CyberHygiene Project - 0.13.0-1.chp
- 0.6.0 disk layout: sized layouts for servers (>= 900 GB) and workstations (>= 240 GB), /data and /backup volumes,
  DISK_NOTE line in the escrow file and in the install log for servers under 1.9 TB.
- Sign-off fixes: review sign needs a terminal; --date must be YYYY-MM-DD; --notes is at most 1000 characters with no
  control characters; a concurrent second signer is re-checked under the lock and refused; the build date uses the
  site's TIMEZONE, not the build machine's.

* Sun Nov 08 2026 The CyberHygiene Project - 0.12.0-3.chp
- Review report: host record counts and unknown alert sources shown as plain text (quiet-day finding)

* Sat Nov 07 2026 The CyberHygiene Project - 0.12.0-2.chp
- Final-review fixes (R1): ledger.head witness (a deleted or shortened ledger is reported, sign refuses); recovery
  steps in every ledger error; the signed hash covers report.md, report.html and data.json; a signed report missing
  within the year fails verify; bad or forged host records are skipped and counted (keyed by the delivering agent);
  Intrusions marked incomplete when its sources are STALE; a sysstat status item; untrusted text cleaned in report
  cells; host records never reach ALERT_HOOK; rule 100520 only from /var/log/chp-review.json; no 'not built' alert on
  the enable day; a never-run weekly YARA scan is OK for 8 days after enable.

* Sat Nov 07 2026 The CyberHygiene Project - 0.12.0-1.chp
- Security bundle part 4 (Plan R1): chp-site review (host-record, build, show, sign, export, verify, now, monitor);
  REVIEW_DELEGATES site key; security enable installs sysstat and the review timers; the forwarder groups YARA matches
  per rule.

* Fri Nov 06 2026 The CyberHygiene Project - 0.11.0-4.chp
- The weekly YARA scan skips /usr/share/chp-suricata-rules: ET Open's rules quote attack bytes, so YARA matched
  chp-suricata.rules (ISO 0.5.0 lab), a level-12 false alarm every Sunday on hosts with both add-ons.

* Fri Nov 06 2026 The CyberHygiene Project - 0.11.0-3.chp
- Final-review fixes (S1): the alert forwarder groups repeats per Suricata signature, not only per rule, so a second
  high-severity signature from a host is not held back (I-2); security enable checks RETENTION_DAYS before changing
  anything (M-2) and starts Suricata once, so its rules load once (M-3).

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
