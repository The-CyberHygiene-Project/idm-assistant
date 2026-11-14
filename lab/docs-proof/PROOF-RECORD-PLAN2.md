# Proof record: ISO 0.7.0 Plan 2 Task 9 (NextCloud server role) on the iso5 lab, round 1

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
