# Proof record: ISO 0.7.0 Plan 2 Task 9 (NextCloud server role) on the iso5 lab

**Round 3 (2026-11-14) supersedes the status tables of rounds 1 and 2 below: see "Round 3" at the end.**

## Round 1

**Result: BLOCKED by a product defect.** `chp-site documents enable` (chp-site 0.14.0-1 from the owner-signed repo 0.12.0)
stops at its Wazuh step on every run, so NextCloud is never configured or started and almost every product proof in the
checklist could not run. The lab is left in a state from which a fixed chp-site can simply re-run `documents enable`.
Raw logs: `lab/docs-proof/logs/`. Drivers: `plan2.sh` (repo, docs-site, login, enable, fsmark), `fsmark-trial.sh`,
`proofs.py` (WebDAV/OCS product proofs, written, **not run yet**).

## Setup (done)

| Step | Result | Log |
|---|---|---|
| Shut down iso5-docs, iso5-dcli, chp-build (kept, not deleted) | aero free memory 15.2 GB free / 19.8 GB available afterwards (was 0 / 5) | (command output, this record) |
| Lab reset from ISO 0.6.0-rc2 (sha256 `0cb27c14...cac0` verified on aero), `SECURITY_ADDONS=yes` | prep, server (DISK_GB=1863, **8 GiB memory**, size guard 50), firstboot, export, client1 (120), client2 (512, guard 50), wazuh-on: **ALL PASS** | `01-prep.log`, `02-server-chain.log`, `03-clients-wazuh.log` |
| Size guards | active, never tripped; srv image 11 GB after first boot | |
| Signed repo 0.12.0 on every host (`dnf --refresh --enablerepo=chp upgrade`, gpgcheck=1, repo_gpgcheck=1) | srv: chp-site 0.14.0-1, chp-base 0.1.0-10, chp-identity-server 0.1.2-3; cli1/cli2: chp-site + chp-base. No fapolicyd restart pending, 0 denials on every host | `04-repo-0.12.0.log` |
| `DOCUMENTS=yes` on the stick's `site.conf` and the server's `/etc/chp/site.conf` | `chp-site validate`: OK | `05-docs-site.log` |
| `chp-site documents enable` (Kanidm session idm_admin, stick attached) | **FAILED, exit 2** at the Wazuh step (D1) | `06-documents-enable-1.log`, `07-enable-1-state.log` |
| AIDE refresh after enable | NOT RUN (enable did not finish) | |

## Product defects

**D1 (blocking): Wazuh refuses the NextCloud rules: `Field 'user' is static`.**

    chp-site: the Wazuh rule check (wazuh-analysisd -t) failed on the new NextCloud rules; the old rules are back and the
    manager was not restarted: wazuh-analysisd: ERROR: Failure to read rule 100618. Field 'user' is static.

`user` is a Wazuh static field (the JSON decoder puts NextCloud's `"user"` key there), so it must be matched with
`<user>`, not `<field name="user">`. Two places in `appliance/chp-site/chp_site/wazuh.py`: line 259 (rule 100618,
`<field name="user">^--$</field>`) and line 382 (rule 100608 in `canary_rules()`, `<field name="user">^chp-canary$</field>`;
it would fail the same way when the nightly check writes the canary rules).
**Syntax test of the candidate fix (logs/09):** the full NextCloud rule set plus a canary rule file, rendered from the
repo with only those two lines changed to `<user>…</user>`, copied under a scratch name into `/var/ossec/etc/rules`, gave
**no error from `wazuh-analysisd -t`**; the files were removed at once and the manager was not restarted. The scratch
names sorted like the real ones (`X.xml` before `X_canary.xml`), so the canary rule's `if_sid 100601` loaded after its
parent. So after the fix every other rule loads; their levels against real audit lines are still unproved.
The unit-test rule evaluator (`tests/test_chp_site_wazuh.py`) did not catch this: it is not Wazuh. A cheap guard: a test
that no rule uses `<field name=` with a Wazuh static field name (user, srcip, dstip, srcuser, dstuser, srcport, dstport,
protocol, action, id, url, data, extra_data, status, system_name, program_name, location).

What worked on the way (evidence that the failure path is sound):
- Steps start, packages (33 installed: nextcloud-chp 35.0.3-4, chp-documents 0.1.0-5, PHP 8.3.29 module, PostgreSQL
  16.13 module, httpd), mail (`mta=none`), hosts, dns, render, egress ran and were audited (`journalctl -t chp-site`).
- The rollback: no NextCloud rules file left in `/var/ossec/etc/rules`, `ossec.conf` without the NextCloud localfile,
  wazuh-manager still active and not restarted; `documents.conf` `ENABLED=no`; `documents status` says "enable has not
  finished … re-run"; the restart marker holds `fapolicyd httpd php-fpm` for the next run; php-fpm/httpd/postgresql
  not started or enabled; egress unit active; 0 AVCs, 0 fapolicyd denials (logs/07).

**D2: `allow_filesystem_mark = 1` makes fapolicyd 1.4.3 exit at once ("recvmesg failed"): fail-open.** (Item 11.)
On cli2 and srv (logs/12, /13): FSMARK=1, the shipped helper `/usr/libexec/chp/fapolicyd-fsmark` wrote the setting
and restarted fapolicyd (`helper-rc=0`, `active` right after), and fapolicyd died one second later:
`fapolicyd integrity is 0` / `recvmesg failed` / `status=1/FAILURE` (fapolicyd-1.4.3-3.el9). Nothing enforced file
execution until I rolled back. Consequences: (a) **no trust rules can make this work**: the daemon does not run, so the
trial has no denials to record, and `66-chp-fsmark.rules` stays empty; FSMARK=1 must **not** ship on this fapolicyd
(owner decision 1 needs revisiting: upstream bug or kernel/fanotify limit to research); (b) the helper reports success
without checking that fapolicyd stays up: it should wait a few seconds after the restart, check `is-active`, and
roll back to 0 (and say so) if the daemon died. **Check 80 did its job:** it alerted at the next monitor run (cli2
00:52:50Z, srv 00:55:37Z, about 80 s after the failure) and then held the repeat back. Rollback: FSMARK=0 + helper
(it removes its own setting; since fapolicyd was not active it did not restart it), then a manual
`systemctl reset-failed; start`: active, 0 denials, check 80 OK on both (logs/14). (Correction, round 2: the
stock `fapolicyd.conf` already has `allow_filesystem_mark = 0`, as untouched cli1 shows; the helper's undo restores it.)
**Owner decision §13 (2026-11-14): `allow_filesystem_mark` stays OFF in 0.7.0; checklist item 11 is dropped.**

## Observations (not defects of this release, or lab-caused)

- **O1 (lab artifact):** files written by `documents enable` run from a transient systemd unit (my driver) get
  `etc_runtime_t` instead of `etc_t` (`/etc/chp/documents.conf`, `nextcloud-egress-addr.nft`, `/etc/hosts`); monitor's
  SELinux-label check alerted. Proved lab-caused (logs/15: a file made from the root shell gets `etc_t`, from a
  `systemd-run` unit `etc_runtime_t`). Relabelled with `restorecon`; `plan2.sh enable` now runs the command under the
  root shell's context (`runcon unconfined_u:unconfined_r:unconfined_t`). Suggestion: enable could `restorecon` every
  file it writes, so it is correct whoever runs it.
- **O2 (existing since 0.4):** `chp-wazuh-alerts` has `Requires=wazuh-manager`: a stop + start of the manager (as
  `prove.sh wazuh-on-neg` does) leaves the forwarder stopped; the monitor alerted ("chp-wazuh-alerts is not running").
  A restart of the manager is fine. Lab script fixed (wazuh-on-neg now starts the forwarder again and checks it);
  product: consider `PartOf=`/`Upholds=` or `BindsTo=` + `WantedBy=wazuh-manager.service`.

## Checklist status

| # | Item | Status | Evidence |
|---|---|---|---|
| S | Shut down docs/dcli/chp-build; reset lab; apply 0.12.0; DOCUMENTS=yes | DONE | logs/01-05 |
| S | `documents enable` | **FAILED (D1)** | logs/06, 07 |
| S | AIDE refresh after enable | NOT RUN (blocked by D1) | |
| 1 | OIDC sign-in, TOTP, groups, break-glass, row 36 | NOT RUN (blocked) | |
| 2 | Team folders, share off, reviewers | NOT RUN (blocked) | |
| 3 | Containment, CUI↔Archive, rename/trash/version, DavGuard | NOT RUN (blocked; `proofs.py` stages ready) | |
| 4 | Tagging incl. folder copy into Archive, ACL-hidden child, NFC/NFD | NOT RUN (blocked; stages ready) | |
| 5 | MD5/FIPS DEGRADED, FolderGuard, 100616 ignore fallback | NOT RUN (blocked) | |
| 6 | Egress | PARTLY: egress unit enabled and active after the failed run; refusal proofs NOT RUN | logs/07 |
| 7 | Mail off / no MTA | PARTLY: enable's MTA check ran, `mta=none`; the refusal with an MTA installed NOT RUN; NextCloud mail setting NOT RUN | logs/07 |
| 8 | Wazuh rules at their levels | **FAILED (D1)**; rule syntax with the 2-line fix: loads (logs/09); levels NOT RUN | logs/06, 09 |
| 9 | Nightly check + canary + break-on-purpose | NOT RUN (blocked) | |
| 10 | fapolicyd details | PARTLY: chp-documents `%post` `fagenrules --load` recompiled the rules (compiled.rules 17:44) **without** a fapolicyd restart (NRestarts=0, start time unchanged, the daemon only re-synced its trust DB for the rpm transaction): it does not violate "no restart in a scriptlet". Check 80 after two back-to-back installs (cli2, `dnf reinstall chp-site` then `chp-base`): fapolicyd stayed up, start time unchanged, no pending marker, **check 80 OK, 0 denials**. trust.d format / `--file update` / config.php sha256 across runs / .so download: NOT RUN (blocked) | logs/08, 11 |
| 11 | allow_filesystem_mark trial | **DROPPED** by owner decision §13 (after D2: fapolicyd exits with FSMARK=1). FSMARK=1 is not used: all three hosts run FSMARK=0 (stock `allow_filesystem_mark = 0`, no `chp-managed` marker, no restart-pending marker, fapolicyd active, chp-base 0.1.0-11) | logs/12, 13, 14, 24 |
| 12 | Backup + restore | NOT RUN (blocked) | |
| 13 | Daily review rows | NOT RUN (blocked) | |
| 14 | Reboot srv + client | NOT RUN (after enable) | |
| 15 | Gates | `wazuh-on-neg`: **PASS** (stray bind → `no:`, cleaned up; the real mount `match` in wazuh-on); CUI scan, regression 33/33, row 36: NOT RUN (the scan must follow a completed enable; the adapter, golden and regression follow the scan) | logs/03, 10 |
| 16 | groupfolders `--delete` cascade | NOT RUN (blocked) | |
| 17 | chp-canary disabled outside the window | NOT RUN (blocked) | |

## Lab state at the end of round 1 (for the resume)

- iso5-srv (8 GiB, 1863 GiB sparse), iso5-cli1 (120), iso5-cli2 (512): installed from 0.6.0-rc2, repo 0.12.0 applied,
  security on, no lab adapter, no golden snapshots, no fixtures (lab users) yet. Size guards active for srv and cli2.
- srv: NextCloud/PHP/PostgreSQL/httpd packages installed by the failed enable; `documents.conf ENABLED=no`;
  `/var/lib/chp/documents/restart-pending` = fapolicyd, httpd, php-fpm; egress unit active; chp-wazuh-alerts restarted.
- FSMARK=0 on srv and cli2 (helper's `allow_filesystem_mark = 0` line present); fapolicyd active, 0 denials.
- AIDE on srv/cli2 reports the upgrade, the packages and the trial (not accepted; accept after the real enable).
- iso5-docs, iso5-dcli, chp-build: shut off, intact.

**Resume:** after a fixed chp-site (D1) is signed into the repo: `plan2.sh repo` (REPO_V=…), `plan2.sh enable 2`, then the
checklist from the AIDE refresh on. D2 needs an owner decision (FSMARK cannot ship as is) before item 11 can close.

## Round 2 (2026-11-14): re-signed repo 0.12.0 (chp-site 0.14.0-2 = D1 fix, chp-base 0.1.0-11 = fsmark helper verifies)

| Step | Result | Log |
|---|---|---|
| Re-signed repo on all three hosts | upgrade = **chp-site 0.14.0-2 + chp-base 0.1.0-11 only** on srv, cli1, cli2 (confirmed); no pending marker; 0 denials | `17-repo-0.12.0-resigned.log` |
| FSMARK status | FSMARK=0 everywhere (see item 11) | `24-fsmark-off-status.log` |
| enable run 2 | first attempt from a transient unit with `runcon` refused (lab driver; logs/18 first lines); driver changed to run from the root console shell itself (detached), SELinux context `unconfined_t`, a test file gets `etc_t`. Then: **past the Wazuh step (D1 fixed: `chp_nextcloud_rules.xml` installed, manager active)**, database (PostgreSQL 16 initialised and started), then **FAILED at install (D3)** | `18-documents-enable-2.log`, `19-install-failure.log` |
| Lab workaround W1 | the operator command enable itself runs right after the install, run before it: `fapolicyd-cli --file add /etc/nextcloud/config.php --trust-file nextcloud; fapolicyd-cli --update` | `20-workaround-w1-trust.log` |
| enable run 3 | install, settings done; **FAILED at apps (D4)** | `21-documents-enable-3.log`, `22-apps-state.log` |
| Read-only pre-check of the next steps' occ commands | every option enable uses exists in this NextCloud (`user_oidc:provider` incl. `--mapping-groups`, `--group-provisioning`, `--group-whitelist-regex`, `--check-bearer`, `--send-id-token-hint`; `groupfolders:create/group/permissions/list`; `tag:add NAME restricted`; `security:certificates:import`; `user:add --password-from-env`) | `23-occ-help.log` |

**D3 (blocking): `occ maintenance:install` is denied by fapolicyd reading the config.php it just wrote.**
`fopen(/usr/lib/nextcloud/config/config.php): Failed to open stream: Operation not permitted at lib/private/Config.php#222`
(`/usr/lib/nextcloud/config` -> `/etc/nextcloud`). `config.php` is `text/x-php` (`%languages`) and untrusted, so rule
`deny_audit perm=any all : ftype=%languages` refuses php opening it. enable adds the path trust entry only **after**
`maintenance:install` (documents.py ~line 480-487); the install already re-reads the file. The spike hit the same denial
(SPIKE-NEXTCLOUD.md table row 2) and trusted the file before installing. Fix: before the install, create
`/etc/nextcloud/config.php` (e.g. `<?php $CONFIG = array();`, 0640 apache:apache) and add its trust entry, then
install; step 15a keeps the entry current. After a failed install the half-written config.php also breaks every later
occ call (`occ status` denied too) until it is trusted, so a re-run cannot recover by itself. fapolicyd counted 3
denials on srv from these attempts (`--check-status`; they stay counted until enable's fapolicyd restart).
Trust file format seen: header comments, then `/etc/nextcloud/config.php 886 <sha256>` (path size sha256).

**D4 (blocking): `occ app:disable appstore` fails: "appstore can't be disabled".** `appstore` is in NextCloud 35's
`core/shipped.json` `alwaysEnabled` list; enable's `APPS_OFF` contains it. Everything else in `APPS_OFF` was disabled and
every app in `APPS_ON` is enabled (logs/22). Fix: drop `appstore` from `APPS_OFF` (the app store is already off by
`appstoreenabled=false`), and do not count always-enabled apps in the "exact" re-list. alwaysEnabled in 35.0.3:
appstore, cloud_federation_api, dav, federatedfilesharing, files, lookup_server_connector, oauth2, profile,
provisioning_api, settings, sharing, theming, twofactor_backupcodes, viewer, workflowengine (none other is in APPS_OFF).

**Lab-script fix:** `plan2.sh` output through the root console (expect) is cut at about 2 KB; large logs are now fetched
(copied to chpadmin's home, read, removed).

**Lab state after round 2:** srv: NextCloud installed (config.php trusted by W1), settings applied, apps as in logs/22,
`documents.conf ENABLED=no`; NextCloud rules in Wazuh; php-fpm/httpd not started. Re-running enable after a D4 fix
continues from here (Kanidm, folders, tags, web, fapolicyd restart). Everything else as at the end of round 1.

### Before round 3 (Task 9c, 2026-11-14): D3 + D4 fixed, enable audited against iso5-srv

chp-site **0.14.0-3**: D3 (config.php and its trust entry before the first occ call; a re-run after a failed install
recovers), D4 (no always-enabled app in APPS_OFF). The read-only audit of every later command
(`enable-audit.md`) found two more, fixed in the same build: **D5** (blocking, would have stopped round 3 at the first
Kanidm call: Kanidm 1.11.2 `group get <missing>` prints `No matching group '<name>'`, which chp-site took for
unexpected output) and **A1** (the `office` app was left enabled; the spike disabled it). Repo 0.12.0 re-staged
(only chp-site changed; modules.yaml unchanged), dry-run on iso5-srv: upgrade = chp-site 0.14.0-3 only
(`stage-0.12.0-r3-logs/`). Resume after the owner re-signs: `plan2.sh repo`, then `plan2.sh enable 4`.

## Round 3 (2026-11-14): repo 0.12.0 r3 (chp-site 0.14.0-3: D3, D4, D5, office off)

**Result: `documents enable` SUCCEEDED (run 4, exit 0); most product proofs PASS; 6 new product defects (D6-D11),
two of them important (D9: the egress alert never fires; D11: NextCloud background jobs never run).**

| Step | Result | Log |
|---|---|---|
| Repo r3 on all three hosts | upgrade = **chp-site 0.14.0-3 only** on srv, cli1, cli2 (confirmed) | 25 |
| enable run 4 | continued from the round-2 state, exit 0, every step listed, `ENABLED=yes`. The new pre-install config.php path **did not run** (NextCloud was already installed, trusted by W1): a fresh-site enable is a Plan 4 item. The Kanidm group steps (D5 fix) ran: groups made | 26 |
| enable run 5 (idempotence) | exit 0; config.php sha256 **unchanged** (`567534e3…`) and **"fapolicyd: no restart needed"**, start time unchanged | 58-60 |
| AIDE | `aide-accept` after enable: 35,491 paths explained by 36 signed packages; 94 not explained, all from enable (documents.conf, hosts, httpd conf, trust.d/nextcloud, config.php, **oidc-secret**, **/etc/pki/nextcloud/key.pem**, units, selinux file contexts, users/groups for apache/postgres, ossec.conf, rules) or the lab (/root files); new baseline pinned to the stick | 31 |
| Gate 3: CUI scan, all three hosts, after enable | **108 pass / 2 fail on every host** (the two accepted AIDE rules); **no rule changed vs 0.6.0** (rule-by-rule diff); `deviations.py` **Gate 3: MET**; no DEVIATIONS.md entry needed. Results: `lab/docs-proof/scan-results/` | 32, 33 |
| adapter, nvram, snapspike | ALL PASS (after the scan) | 34 |
| Reboot (nvram stage reboots srv and cli2) | srv back: egress unit started **before** php-fpm and httpd (10:29:30.06 / .29 / .64), all NextCloud services active, 79 OK, 0 AVC, 0 denials | 35 |
| fixtures (lab01-06), golden (reset + 0 findings on both) | FIXTURES OK; golden ALL PASS | 36, 63 |

### Checklist (round 3)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | OIDC sign-in with TOTP through Kanidm | **PASS** (row 36 3/3: host sign-in unchanged): lab01-04 signed in by a scripted browser (NextCloud -> Kanidm /ui/login/begin -> totp -> pw -> consent -> NextCloud); groups mapped exactly: lab01 [chp-users, cui-users], lab02 [chp-users], lab03 [chp-users, doc-reviewers], lab04 [all three]; backend user_oidc. `/login` -> 302 to `/apps/user_oidc/login/1`; `/login?direct=1` shows the password form; break-glass `ncadmin` with the escrowed secret: 207; a wrong one 401. Kanidm 1.11.2 `oauth2 get`: `oauth2_jwt_legacy_crypto_enable` and `oauth2_allow_insecure_client_disable_pkce` are **absent** (= false) on the new client; `oauth2_prefer_short_username: true`. Escrow file keys: `NEXTCLOUD_ADMIN_USER`, `NEXTCLOUD_ADMIN_PASSWORD`. Host sign-in (row 36): with the gates | 37-39, 27 |
| 2 | Team folders, share off, reviewers | **PASS** (`proofs.py share`, `see`): internal share CUI->lab02 and ->lab04, public link on CUI/FCI/Archive, FCI internal share, the CUI folder itself: all refused (OCS 404 "Node is not shareable"); Operations internal share and password link allowed. Wazuh 100601 level 12 x7. lab03 (reviewer, not cui-users) sees only Operations/Internal/Public, CUI path 404, may write in Operations (decision 7); lab02 sees no CUI; lab04 reads/downloads CUI, cannot change/add/delete in CUI/FCI/Archive, writes in Operations. Folder map read back: CUI/FCI/Archive = cui-users perms 15 (no share), others chp-users 31, ACL on | 41, 40, 48 |
| 3 | Containment, CUI<->Archive, rename/trash/version, DavGuard | **PASS**: COPY/MOVE CUI -> FCI, Operations, home, Public, Internal: 403, nothing created; FCI -> Operations/CUI 403; CUI -> Archive copy and move (no old versions) allowed and tagged CUI; Archive -> CUI allowed; rename and move into a subfolder inside CUI keep the tag; trash restore keeps file id and tag; DavGuard: MOVE/COPY trash item -> files 403, COPY old version -> files 403; **version restore keeps the tag** (content v1, CUI). Wazuh 100611 level 12 per refusal. **Defect D7**: FolderGuard's refusal of a rename/move is HTTP **500** (data intact), the delete refusal is 403. **Observation O4 (upstream)**: after a trash restore, the next change keeps no earlier version (1 version listed) | 41, 43, 44, 45 |
| 4 | Tagging | **PASS** for files: WebDAV PUT, browser-style chunked upload, NFC and NFD non-ASCII names, CUI folder copy into Archive (every file tagged CUI); the restricted tag cannot be removed by the user (DELETE 404). By design **folders are not tagged** (chp_foldertag README: files are tagged; folders walked) — my first expectation was wrong. ACL-hidden child: lab01 cannot see `hidden.txt`; FolderGuard counts it (rename and delete of the folder that looks empty: refused); a copy of the folder into Archive copies the **visible** child only (tagged), the hidden child is not copied (no leak). **Defect D8**: false `chp.tag.failed` (Wazuh **level 12**, rule 100613) on every user's first sign-in | 41, 43, 46, 47 |
| 5 | MD5/FIPS DEGRADED | **PASS**: `documents status` and the check print "DEGRADED: database MD5 unavailable (folder moves/renames/deletes refused)"; FolderGuard refuses non-empty folder rename/delete and a move of a file with old versions; Wazuh **100616 level 7 once**, then **100615 level 3** (x8): the `ignore` fallback works | 27, 41, 43, 48 |
| 6 | Egress | **PASS** for enforcement: as apache, outbound 93.184.216.34:80 and 1.1.1.1:443 refused (curl rc 7, php fsockopen "Connection refused"), DNS refused (`CHP-NC-EGRESS-DNS`, 16 packets), /etc/hosts names resolve, the server itself reachable (idm:443 -> 200); kernel log `CHP-NC-EGRESS` lines; table removed -> check 79 ALERT and php-fpm + httpd refuse to start; table edited at run time -> 79 ALERT ("differs"); address file widened -> 79 ALERT and the egress unit refuses to start, php-fpm/httpd go down (BindsTo); all restored. **Defect D9 (important): rule 100620 never fires**: the kernel line is decoded by Wazuh's firewall decoder and taken by rule **4100 (level 0)** (`wazuh-logtest`); 0 egress alerts in alerts.json | 49, 51 |
| 7 | Mail | PARTLY: `mail_smtpmode` = null, no MTA installed (enable's check: none). The refusal with an MTA installed: NOT RUN (no MTA package in the offline repo) | 26, 49 |
| 8 | Wazuh rules at their levels | Seen live: 100601 (12, share refused), 100604 (7, NextCloud "Login failed" — taken by 100604, not 2501/100605), 100606 (7, delete in CUI), 100607 (3, download from CUI), 100608 (3, canary refusal anchored to file 159), 100609 (12, canary enabled outside the window), 100611 (12, contain), 100613 (12: D8 false alarms), 100615/100616 (3/7), 100617 (3, apps switched off by enable), **100630 (7) fires 3x per wrong TOTP** (three kanidmd lines match; real line: `Handler::PasswordMfa -> Result::Denied - TOTP Fail`, `Credentials denied | reason: incorrect totp`, `Auth result: Denied: incorrect totp`). `user` for occ = `--` (canary enable lines). Rule-file order: `chp_nextcloud_rules_canary.xml` loads after the main file (100608 fired). NOT SEEN: 100602/100603/100612 (no share made, no control app disabled), 100618 (needs the 03:05-03:45 window), 100620 (D9) | 48, 50, 53, 54 |
| 9 | Nightly check + canary + break on purpose | **PASS**: manual check (outside the window; ISSO = lab): OK, canary refused both ways, check 81 OK, DEGRADED shown not alerted. Broken on purpose (untag a CUI file, delete `contain`, rename team folder 3, config.php changed out of band): **5 alerts** (untagged, name, app:contain, folder:3 renamed, trust) and check 81 ALERT; restored -> OK. SIGKILL of the check unit mid-canary: `ExecStopPost` canary-off ran ("canary account disabled, its app tokens deleted"), canary disabled, 0 tokens; canary left enabled by hand -> next run `canary:leftover` ALERT and cleanup. Inside the 03:05-03:45 window: NOT RUN. **Observation O6**: the first check run writes the canary rules and restarts the manager in the middle of the run; the canary "User enabled" line written during the restart was not seen by Wazuh (100609 missed that once; seen on the next run) | 52-55 |
| 10 | fapolicyd | trust.d format `<path> <size> <sha256>` under a header; enable run 5: config.php sha256 unchanged, **no fapolicyd restart**; `%post fagenrules --load`: no restart (round 1); user-stored `.so` (ELF) uploaded and downloaded unchanged (rule 65, no ftype=); check 80 after back-to-back installs OK (round 1). `--check-status` read after a restart: **0 denials** (restart -> baseline -> all the proofs -> 0 at the end). **Defect D6**: enable's own fapolicyd restart left fapolicyd **dead** ("recvmesg failed", exit 1, 1 s after start) and enable still exited 0 ("Denied accesses: unknown"); check 80 alerted. 5 manual restarts and 5 restarts right after a trust update or a dnf transaction all worked: intermittent (3 of about 18 restarts on this lab, incl. round 1's two under FSMARK=1, so round 1's D2 was probably this, not the setting) | 26-30 |
| 11 | allow_filesystem_mark trial | DROPPED (§13); FSMARK=0 on all hosts | 24 |
| 12 | Backup + restore | **PASS** with one defect: a held lock -> "another backup is running", exit 75; a partial dir (no MANIFEST) deleted at the next run; backup unit OK (`/backup/nextcloud/<stamp>`, 0700 root, MANIFEST 86 lines, pgdump, data, etc-nextcloud, 3.1 MB); a backup leaves config.php unchanged; restore: a file added after the backup is gone, services back, maintenance off, labels `httpd_sys_rw_content_t`, 0 denials, 0 AVC. **Defect D10**: after a restore config.php no longer matches its fapolicyd trust entry (restore's `maintenance:data-fingerprint` rewrites it), so the README's own verify step (`documents check`) alerts "trust" | 56, 57 |
| 13 | Daily review rows | NOT RUN: the NextCloud rows appear in the 2026-11-14 report, built at 00:20 on 11-15 (a report is never rebuilt, so I did not build today early) | |
| 14 | Reboot srv + client | **PASS** (nvram stage): see the table above | 35 |
| 15 | Gates | CUI scan **MET** (no change from the new services); wazuh-on-neg PASS (round 1); adapter, nvram, snapspike, fixtures, golden ALL PASS; **regression 33/33** (11 x 3 GREEN, NextCloud running; model 33/33 valid, 32/33 agreeing, l4 2/3 as in 0.6.0; `lab/iso5/regression-2026-11-14.md`); **row 36 3/3** (label `var_auth_t`) | 32-36, 63-65 |
| 16 | groupfolders `--delete` cascade | **PASS (no cascade)**: a stray chp-users mapping (perms 23 incl. share) + an ACL rule for chp-users on CUI; enable run 5 removed the mapping (CUI back to cui-users 15) and left the **doc-reviewers ACL rules intact**; the stray group's own ACL row stays behind (orphan, harmless) | 58-60 |
| 17 | chp-canary disabled outside the window | **PASS**: disabled after every run (incl. a SIGKILLed run), 0 app tokens left | 52-55 |

### Product defects found in round 3 (for the controller; nothing patched)

- **D6 (important)** — `documents.py` step 17 (fapolicyd restart): after `systemctl restart fapolicyd` it reads
  `--check-status` once, gets nothing ("Denied accesses: unknown") and exits 0 although fapolicyd died ("recvmesg
  failed"): the server ran with **no file-execution control** until check 80 alerted. Fix: after the restart wait (a
  few seconds), require `systemctl is-active fapolicyd` and a parsed counter; on failure retry the restart once, then
  fail the run loudly (as chp-base 0.1.0-11's helper now does). Root cause of the intermittent "recvmesg failed" in
  fapolicyd 1.4.3: open (upstream research).
- **D7 (minor)** — FolderGuardListener on `BeforeNodeRenamedEvent` (rename/move of a non-empty folder, or a file with
  old versions): the client gets **HTTP 500** and nextcloud.log "Uncaught exception" / webdav "Failed to rename"; the
  data is intact and the audit/Wazuh lines are right. The delete refusal is 403. Fix: throw a Sabre `Forbidden` (as
  DavGuard does) or an exception the DAV layer maps to 403 for the rename path.
- **D8 (important: false level-12 pages)** — TagListener: on a user's **first sign-in** NextCloud creates
  `/<user>/files` (NodeCreatedEvent); the walk finds the team-folder mounts below it and writes `chp.tag.failed:
  mounts below the target are not walked (...)` twice per user (rule 100613, level 12 -> ALERT_HOOK). Seen for lab01-04
  and chp-canary. Fix: skip the nested-mount report (or the whole walk) when the target is not inside a ruled team
  folder (`$folder === null` / no rule), i.e. a user's home root.
- **D9 (important)** — rule 100620 (`<program_name>^kernel$</program_name><match>CHP-NC-EGRESS</match>`, no
  `if_sid`): Wazuh's firewall decoder takes the kernel line and rule **4100 (level 0, "Firewall rules grouped")**
  matches first, so 100620 is never evaluated. The design's "outbound block tripped -> level 12" does not happen.
  Fix: `<if_sid>4100</if_sid>` (or `<if_group>firewall</if_group>`) + `<match>CHP-NC-EGRESS</match>`; prove with
  `wazuh-logtest` on a real line (logs/51 has one).
- **D10 (minor)** — `chp-nextcloud-backup restore`: `occ maintenance:data-fingerprint` rewrites config.php, so its
  fapolicyd trust entry is stale afterwards; the nightly check (and the README's verify step) alerts "trust". Fix: the
  restore runs `fapolicyd-cli --file update /etc/nextcloud/config.php --trust-file nextcloud; fapolicyd-cli --update`
  after its last occ call (or the README says to re-run `chp-site documents enable`).
- **D11 (important)** — `chp-documents/nextcloud-cron.service` line 9 `ExecStartPre=/usr/sbin/nft list table inet
  chp_nextcloud_egress` runs as `User=apache` (line 8): "Operation not permitted (you must be root)", so **NextCloud's
  background jobs never run** (`oc_jobs` max last_run = 0; the unit fails every 5 minutes; `systemctl --failed` shows
  it). Check 77 says OK because it checks only the timer. Fix: `ExecStartPre=+/usr/sbin/nft list table …` (the `+`
  runs that line as root), and check 77 should also alert on a failed `nextcloud-cron.service` / a stale `oc_jobs`.
- Minor notes: rule 100630 fires 3 times per wrong TOTP (three kanidmd lines match; anchor it on `Auth result: Denied`);
  enable prints "AIDE: … refresh the baseline now" even on a no-change run; the AIDE baseline hashes
  `/etc/nextcloud/oidc-secret` and `/etc/pki/nextcloud/key.pem` (as the progress carry noted; hashes, not contents);
  NextCloud's audit log (and so Wazuh `full_log`) records the OIDC authorization code in the `url` of the sign-in
  request (single-use, short-lived; redacted in these logs).

**Lab state at the end of round 3:** srv and cli2 at golden (taken after the NextCloud proofs; NextCloud enabled, the
proof files and users in it), lab adapter + fixtures present, size guards active; cli1 untouched since install +
repo r3. nextcloud-cron.service fails every 5 min (D11). The lab Kanidm admin session and SSH tunnel on the Mac are
throw-away.

### Before round 4 (Task 9d, 2026-11-14): D6-D11 and the minors fixed, repo 0.12.0 re-staged (r4)

chp-site **0.14.0-4**, chp-base **0.1.0-12**, chp-documents **0.1.0-6**, nextcloud-chp **35.0.3-5** (details:
`.superpowers/sdd/2026-11-13-iso-0.7.0-plan2-nextcloud-server-role/task-9d-report.md`):
- **D6:** enable proves its fapolicyd restart (active at 3 samples over ~5 s, a parsed `Denied accesses` counter, then
  `fapolicyd-fsmark --verify`); dead -> restarted once more; dead again -> the run fails (check 80, POA&M), the restart
  mark stays. The fsmark helper samples 3 times too and restarts a dead fapolicyd once more when there is no change of
  its own to revert. **The "recvmesg failed" exit is not caused by allow_filesystem_mark: it was seen at
  allow_filesystem_mark = 0 too** (logs/28-30). No upstream bug-report draft exists under lab/ or docs/ yet; whoever
  drafts it (design §13) must say so.
- **D7:** a refused WebDAV rename/move is 403 (DavGuard asks FolderGuard in Sabre's beforeMove). **D8:** no walk (no
  false `chp.tag.failed`) for a target where nothing can be tagged, e.g. `/<user>/files` on first sign-in.
- **D9:** rule 100620 is `<if_sid>4100</if_sid>` + `<match>CHP-NC-EGRESS</match>`; rule 100630 matches only
  `Auth result: Denied: incorrect totp`. wazuh-logtest 4.14.7 on aero (logs/66): new = 100620 level 12 on the round-3
  kernel line and 100630 once per wrong code; old = 4100 level 0 and 100630 three times.
- **D10:** `chp-site documents trust` (new) after restore's `occ maintenance:data-fingerprint`. **D11:** the cron unit's
  nft line is `ExecStartPre=+...` (root); check 77 also alerts on a failed last cron run and a stale/missing
  `core/lastcron`.
- Minors: AIDE note only when the run changed something; OIDC `code` in the audit `url` = SSP/POA&M note in the
  chp-documents README (NextCloud's own log writer).
- PHP: `php -l` via stdin on iso5-docs (PHP 8.3.29): all 10 clean (logs/67). Stage: only those 4 packages changed
  (by sha256 and by NEVRA), modules.yaml unchanged; dry-run on iso5-srv: upgrade = those 4 only; test_sign_repo 52/0
  (`stage-0.12.0-r4-logs/`). Signed r3 repo kept as `repo-superseded-r3`.

**Round 4 should prove:** after `plan2.sh repo`, `enable 6`: the fapolicyd step line ("active over 5 s; Denied
accesses: N"); a rename of a non-empty CUI folder = 403; a new user's first sign-in writes no `chp.tag.failed`; an
egress attempt raises 100620 (level 12) in alerts.json; one wrong TOTP = one 100630; nextcloud-cron.service succeeds,
`oc_jobs` last_run > 0, check 77 OK (and ALERT when the unit is broken on purpose); backup + restore then
`documents check` with no "trust" alert; enable run 7 prints "AIDE: this run changed no watched file".
