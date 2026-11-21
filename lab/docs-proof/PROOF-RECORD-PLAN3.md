# Proof record: ISO 0.7.0 Plan 3 Task 11c (controlled-document workflow) on the iso5 lab

**Round 1 final (2026-11-21):** the overnight items ran and passed (below, "Timed items"); B15 not run.

Date: 2026-11-20. Repo: the owner-signed **0.13.0** (`aero:/data/chp-release/0.13.0/repo`, `verify-repo`: REPO OK 72,
repomd signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E). Lab reset from **ISO 0.6.0-rc2** (sha256 `0cb27c14…cac0`
verified). Raw logs: `lab/docs-proof/logs/101-…` onwards. Driver: `plan3.sh` (wraps `plan2.sh`) with the workstation
helpers `doc_browser.py` (scripted Kanidm sign-in for `chp-site doc login`), `doc_api.py` (raw WebDAV/OCS with the
user's own Bearer), `doc_req.py` (raw ledger requests, for the server-side refusals), `docx_edit.py` (the lab stand-in
for editing in ONLYOFFICE), `g3_probe.py`, `introspect_probe.py`. Work list: spec §8 and
`.superpowers/sdd/2026-11-19-iso-0.7.0-plan3-document-workflow/task-11c-checklist.md` (every item's verdict is in that
folder's `task-11c-report.md`). **Product code was not changed.**

## How the lab ran it (method notes)

- **Users on the workstation** (iso5-cli2, after the lab adapter): each lab user runs `chp-site doc` in a real logind
  session made by `systemd-run -p PAMName=login -p User=<u>` (context `unconfined_t`, `/run/user/<uid>` on tmpfs 0700).
  A lasting "anchor" session per user stands in for the desktop session, so the tokens outlive single commands. (`su -`
  from a unit exits 203; `su` inside an ssh session makes no session.)
- **Sign-in:** `chp-site doc login` prints the Kanidm URL; `doc_browser.py` (as root, script on stdin, so fapolicyd never
  sees an untrusted .py open) posts the Kanidm forms with the user's lab password + TOTP and follows the redirect to the
  `http://127.0.0.1:<port>/` loopback listener. The password file goes through a 0600 file in the user's runtime dir and
  is deleted on read.
- **Editing:** the lab VMs have no display (`--graphics none`). ONLYOFFICE's first run (AllFonts.js) and the
  recovery-copy tests ran the real DesktopEditors under a headless `mutter --wayland --virtual-monitor` with Xwayland, in
  the user's session. Document edits are made with `docx_edit.py` (one paragraph added; `--strip-marks` for the
  missing-marks case).
- **Hand-off:** as the guide says (CUI/Drafts upload by WebDAV with the author's Bearer, download by the approver).
- Lab workaround **W1** (P3-D2): `dnf install chp-templates` from the signed repo on cli1/cli2.
- Long server commands ran in the root console shell (detached), as in Plan 2: a transient systemd unit runs rsync
  confined (the first two restore attempts failed with Permission denied and no AVC; logs/169), a lab artifact like
  Plan 2's O1.

## Setup

| Step | Result | Log |
|---|---|---|
| Reset from 0.6.0-rc2, `SECURITY_ADDONS=yes`: prep, server (1863 GiB sparse, 8 GiB, guard 50), firstboot, export, client1 (120), client2 (512, guard 50), wazuh-on | ALL PASS (wazuh-on's first run counted 1 Active agent right after cli2's reboot; re-run ALL PASS) | 101-103 |
| Signed repo 0.13.0, `dnf --refresh --enablerepo=chp upgrade` | srv upgrade 5 (chp-base 0.1.0-13, chp-identity-client 0.2.4-2, chp-identity-server 0.1.2-3, chp-integrity 0.1.7-2, chp-site 0.14.0-7: a fresh server has no nextcloud-chp/chp-documents yet), cli1/cli2 upgrade 4; 0 denials; no restart pending | 104 |
| Site keys: `DOCUMENTS=yes`, `CUI_CONTROLLED_BY`, `CUI_CATEGORY`, `CUI_POC` on the stick, the server and both workstations' site.conf | validate OK | 105 |
| `documents enable` run 1 | **FAILED at maintenance:install (P3-D1)** | 106, 107 |
| enable run 2 (no change) | exit 0, every step; fapolicyd restarted and proven active 5 s | 108, 109 |
| `onlyoffice enable` cli1, cli2 | Install 10 each; AI Tools plugin absent; linger off; egress table; sweep timer; checks 80 and 83 OK; 0 denials | 110, 111 |
| AIDE accept (srv, cli1, cli2) | accepted and pinned; `/etc/aide.conf` changed (chp-integrity 0.1.7-2) as expected | 112 |
| **CUI scan** | **108 pass / 2 fail on every host; no rule changed vs Plan 2 round 4; Gate 3 MET** (the workstations now carry ONLYOFFICE and the egress table) | 113, 114, `scan-results-p3/` |
| adapter, nvram, snapspike; fixtures | ALL PASS; FIXTURES OK | 115, 116 |
| `DOC_APPROVER_ACCOUNTS=nosuchuser` then enable 3 | refused before any change ("not a Kanidm account … nothing was changed") | 117 |
| `DOC_ISSO_ACCOUNT=lab01`, `DOC_APPROVER_ACCOUNTS=lab04`, `ALERT_HOOK=/usr/local/sbin/lab-hook`; enable 4 | exit 0; "document approvers: ISSO lab01; approvers lab04 (checked)"; "fapolicyd: no restart needed"; "AIDE: this run changed no watched file" | 118 |
| Web sign-in lab01, lab04, lab06 (user_oidc callback) | groups mapped; 100629 L12 for each new cui-users member | 122, 126, 129 |
| Reboot srv, cli1, cli2 | all units back; NextCloud egress before php-fpm/httpd; checks 76-83 OK; KillUserProcesses=yes in force; `meta skuid 997` (chrony) loaded at boot; 0 denials | 176 |
| Golden (srv, cli2) | ALL PASS (reset + 0 engine findings) | 177 |

## The workflow (spec §8, brief Step 3)

| Proof | Result | Log |
|---|---|---|
| new → check → mark → approve by a delegate → publish → reader PDF → CR number | `doc new SecPolicy --cui` (marks filled from the site keys), `check` OK, `mark` nothing to add; draft handed over through CUI/Drafts; lab04 approved; lab01 renamed and published **CR-2026-0001** in 3.4 s; docx + PDF in CUI/Compliance, both tagged CUI; reader PDF by ONLYOFFICE 10.0.0.169, `pdftotext`: banner first and last, block on page one | 121, 125-128 |
| Superseded version in Archive | v0.2 published (CR-2026-0002): v0.1 docx + PDF in Archive/Superseded, same file id (71), tag kept | 133, 134, 144 |
| Non-CUI document through Internal/Compliance | `doc new Handbook --non-cui` → CR-2026-0004; reader PDF has no CUI line | 145 |
| xlsx | CR-2026-0008; reader PDF banner + block on page one | 162 |
| md | **refused at x2t (P3-D10)** | 162 |
| Refusal: self-approval | lab01 (the author, also the ISSO): "lab01 created it in this cycle, so lab01 is an author" | 123 |
| Refusal: override while a delegate exists | "not a one-person site: approver account(s) other than the author exist (lab04)" | 123 |
| Refusal: reader-checkout approval | lab04 checked out to read, then approved: refused as an author; its earlier approval no longer counts (publish refused) | 137 |
| Refusal: stale checkout | after the other author's publish: `check` NOT READY, `publish` refused ("canonical copy … changed since your checkout") | 134 |
| Refusal: publish race | two authors publishing at the same second: one CR-2026-0002, the other refused (message misleading: P3-D4) | 133 |
| Refusal: unapproved hash | file edited after the approval: "no valid approval of this exact file" | 135 |
| Refusal: `-DRAFT` | client (exit 2) and server (raw request: "is still -DRAFT") | 123, 136 |
| Refusal: missing marks | client `check` lists the 5 problems; raw approve accepted by the server (it has only the hash), raw publish refused on the server with the plain marking message | 136 |
| Compliance written through the browser path and WebDAV | 14 operations x 2 auth types (the chp-doc Bearer, and a NextCloud app password = the browser's DAV path): PUT, MKCOL, DELETE, MOVE (rename, out), COPY in, on CUI/Compliance, Internal/Compliance(/Superseded), Archive/Superseded and the area folders themselves: **all 403** | 140 |
| ISSO override, one-person site | `DOC_APPROVER_ACCOUNTS` emptied: lab01 override (reason) → published CR-2026-0003; **100643 L12 at the hook 5 s later**; empty reason refused | 138 |
| Approval alert | **100642 L12 at the hook 3 s after each approval** (6 approvals = 6 alerts) | 126, 139 |
| Ledger export + `verify --stick`; tamper on a copy | OK 20 entries, stick anchor OK; a changed entry on a copy (private mount namespace) → "entry 3 does not follow entry 2"; `ledger.head` removed on a copy → verify exit 1 naming it and check 82 ALERT | 147 |
| Appender resilience: start-limit flood | 450 stray files in 59 s and 400 rapid starts in 30 s: never a permanent stop, every stray quarantined (100645 L12); the limit itself was not reached (systemd merges the starts); the OnFailure line → **100646 L12** at the hook, JSON unescaped right | 149, 152 |
| Appender resilience: Kanidm outage | the client is refused with "run chp-site doc login" (exit 2), not pending (P3-D9); the same command works when Kanidm is back | 161 |
| Appender resilience: broken site.conf | deferred as retry 3 times, exactly one 100646, path unit active, client pending (exit 3); the same command succeeds after the fix | 153 |
| Appender in maintenance mode | `files:put` refused by occ → publish undone, answer "retry (maintenance mode)", nothing in the area, client pending (exit 3); same command → CR-2026-0007 | 160 |
| Backup / restore with the ledger | nightly backup holds `chp-docs-ledger/`; restore onto a server without a ledger: the restored ledger is byte-identical, 39 entries, `verify --stick` OK; nightly check OK; services up; 0 denials | 158, 169 |
| G2: killed editor session swept, live session kept | real DesktopEditors, kill -9; copies aged 13 h: lab06 (no process) removed under `chp-doc-sweep` (**100626**), lab01 (live session) kept; no AVC, 0 fapolicyd denials; recents.xml owner kept. `doc close` removes the working copy, the recovery copy and the recents entry (grep finds nothing) | 163-165 |
| G3: egress with an IPv6 default route and the tap capture | DNS v4/v6 to public resolvers, 853, 443 out (v4 and v6) refused and logged with the uid; resolver, Kanidm 443, NextCloud 8443, Wazuh 1514, chrony work; the tap on aero's br-lab saw cli1 talk only to the server (plus ssh replies and MLD) | 150 |
| G4: AI Tools absent | the plugin folder `{9DC93CDB…}` is absent after install on both workstations | 111 |
| Back-to-back installs, then check 80 | chp-onlyoffice then chp-templates on cli1/cli2: fapolicyd up, check 80 OK, 0 denials (also after reboot) | 111, 120, 176 |
| Plan 1/2 carries | I1: uploads in Wazuh (100621, 36 events); I2: a local NextCloud account put in cui-users → nightly check ALERT; **D13**: `chp-documents-check.timer` enabled by the fresh enable; D14, D15: overnight (pending) | 108, 139, 170 |
| Untested Plan 2 rules | **100603 + 100612** (L12) on `occ app:disable chp_ledger`; 100602 (a share actually made) not run | 156 |
| Nightly check | clean after enable (SQL names right: no `check:access`); breaks alert: cui-users RO rule removed (`area-ro`), a group mapped to Internal by hand, `chp_ledger` disabled (`ledger-app`); an untagged `CUI_` file in a home folder found | 156 |
| Check 82 | path unit stopped → ALERT; quarantine → ALERT; a root `publish-started` with no end → PENDING after the 30-min grace, `resolve` clears it | 148, 168 |
| MD5-degraded admin folder move (guide procedure) | folder MOVE refused (403); new folders, files moved one by one, empty folders deleted bottom up: done, tags kept | 157 |

## Product defects (Plan 3 numbering; nothing patched)

- **P3-D1 (important; first enable fails on a fresh server).** `documents.py:656` `_trust_sync` adds config.php's
  fapolicyd trust entry and runs `fapolicyd-cli --update`, and the next line runs `occ status`/`maintenance:install`
  at once. `--update` is asynchronous: fapolicyd logged "Updated" at 10:34:32.06, php was denied
  `/etc/nextcloud/config.php` (obj_trust=0) at 31.21, 31.51 and 31.61, and the install failed ("fopen(/usr/…",
  truncated). A re-run passes (the entry is loaded by then). Plan 2's D3 fix never ran on a fresh server (Plan 2
  round 3 note). Fix: after `--update`, wait until the daemon has reloaded (e.g. poll `fapolicyd-cli --test-filter`/a
  read of config.php as apache, or retry the first occ call on a fapolicyd denial). logs/106, 107.
- **P3-D2 (important; `doc new` cannot work on a workstation).** Nothing installs chp-templates on a workstation:
  `chp-onlyoffice.spec` Requires (lines 26-32) has no chp-templates and `onlyoffice enable` installs only chp-onlyoffice;
  `doc new` refuses "the template … is not installed (it comes with chp-templates 1.4.0)" (doc.py:689-691). Fix:
  `Requires: chp-templates >= 1.4.0` in chp-onlyoffice (or chp-site's workstation docs step installs it). logs/120.
- **P3-D3 (important).** A chp-doc Bearer for a Kanidm person without a NextCloud account **creates the account**
  (no groups, display name = uid), although provider 2 has `bearerProvisioning: false` (documents.py:977). It came
  from `doc login`'s `/ocs/v2.php/cloud/user` call; no "User created" audit line, so 100623 did not fire. Effect:
  until the person signs in once in the browser, every doc command says "the area CUI/Compliance is not visible to
  you". A web sign-in then maps the groups. Fix: find why user_oidc 8.13.0 provisions on the Bearer path (upstream?),
  or document "sign in once in the browser first" and make the doc commands say so. logs/119-122.
- **P3-D4 (minor).** The loser of a publish race is refused with "lab01 is not an author of this change (only nobody
  may publish it …)" (doc_ledger.py:1671): the cycle ended with the other publish. Should say the current version
  changed since the checkout. logs/133.
- **P3-D5 (minor, guide).** The first enable raises 100623 five times (ncadmin created + added to admin,
  chp-publisher created + added to chp-users + cui-users); SITE-STICK.md:387 says twice. logs/139.
- **P3-D6 (minor).** `LimitRequestBody 100663296` on `^/ocs/v[12]\.php/apps/chp_ledger/` (chp-documents
  nextcloud-httpd.conf) does not stop a 97 MiB body: the app answered 400 on both OCS paths (PHP read it). The
  64 MiB + 1 case is refused 413 by the app itself, so the size rule holds; the httpd guard does not. logs/141, 142.
- **P3-D7 (important).** Workstation journal lines written just before or during an egress lock-down
  (`EGRESS RENDER FAILED`, `EGRESS LOCKDOWN`) never reached the manager after the link was back: no 100632/100628
  from cli1, although both rules match in wazuh-logtest and later test lines arrived at once. The guide
  (SITE-STICK.md:365) says the lock-down line "arrives only after the link is back". Likely the agent sent them into a
  dead connection and does not re-send. Fix: do not rely on it (say so in the guide; check 71 is the signal), or have
  the egress unit re-log the state after recovery. logs/154, 155.
- **P3-D8 (minor).** A publish while NextCloud is in maintenance mode (the backup window) stops at the client's own
  PROPFIND: "refused: NextCloud answered HTTP 503 for CUI/Compliance", exit 2 (doc.py:325), not pending (exit 3).
  Nothing is sent and the next run works, but the guide's exit-code table says 2 is a refusal. logs/159.
- **P3-D9 (minor).** During a Kanidm outage NextCloud cannot check the Bearer (user_oidc userinfo) and answers 401;
  the client says "refused: NextCloud did not accept your sign-in; run chp-site doc login", exit 2 (doc.py:323). The
  appender's retry path is never reached. It should be pending, and not send the user to a login that cannot work.
  logs/161.
- **P3-D10 (important; Markdown documents cannot be published).** x2t exits 89 converting the `.txt` copy of a `.md`
  (`doc.py:857-862` `_x2t_params` has no `m_nCsvTxtEncoding`); with `<m_nCsvTxtEncoding>46</m_nCsvTxtEncoding>` (UTF-8)
  the PDF is made and both banners survive `pdftotext`. logs/162.
- **P3-D11 (minor).** A spool file the appender cannot delete (`chattr +i`) is copied into the quarantine again on
  every run (299 copies, 299 L12 quarantine events in 75 s) until the path unit's limit; only one `appender-failed`.
  Fix: remember a file already set aside (by inode/name) and stop re-quarantining it. logs/167.
- **P3-D12 (minor).** `doc login` always says "sign-in ends: Kanidm did not say": Kanidm answers the refresh-token
  introspection with `active: false` (the access token's is `active: true`, exp 15 min) (doc_auth.py:323-337). logs/173.
- **P3-D13 (minor).** `--notes` over 2000 BYTES (MAX_TEXT, LedgerController.php:53) is sent and refused with the
  generic "the request is not valid …"; the client could check and say so. 1990 bytes go through intact (journal and
  Wazuh). logs/171.
- **P3-D14 (minor; decision).** The server's journal is volatile (`/var/log/journal` absent): after the reboot the
  appender's journal lines were gone. Check 82's journal side and the review's journal-based rows lose history at each
  reboot; the durable `unfinished/` records cover unfinished publishes. Task 9's concern 1 / Task 10 "journal
  persistence as an operations note": persistence is not configured. logs/109, 176.

## Observations (not product defects, or lab-caused)

- O1: Wazuh rule 40101 ("System user successfully logged") L12 fired hundreds of times from the lab driver's
  `runuser`/PAM sessions (lab noise).
- O2: `chp-nextcloud-backup restore` under `set -e` stops at the first failing command with that command's message
  only (no "restore FAILED" line), leaving httpd/php-fpm stopped (seen with the lab's confined rsync).
- O3: The server accepts an approval of a file with no marks (it holds only the hash); the marks are checked at
  publish. The client's own approve refuses it.
- O4: The server's marking refusal repeats the file name ("X: X: …").
- O5: The address file stays `etc_t` after a re-render (the Task 9 note expected `net_conf_t`).
- O6: `systemctl stop nftables` with nftables.service inactive leaves the egress table; start-then-stop
  (`flush ruleset`) removes it and check 83 says MISSING; `systemctl restart chp-workstation-egress` restores it.
- O7: With chp-publisher disabled, `occ files:put` says "The specified user is disabled": keeping it enabled
  (as built) is right.

## Later proofs (after the regression)

| Proof | Result | Log |
|---|---|---|
| `SECURITY_ALERT_LEVEL=13`, enable | WARNING line printed, enable exit 0; key removed again (site.conf byte-identical) | 184 |
| Citation of a superseded version | `check` WARNING and the publish result's "marking warnings (not refused)"; CR-2026-0011 | 185 |
| Check 82 under a lock held 70 min | "busy, not checked" each run; ALERT on the 4th run in a row (15:48 MST, at the hook); OK after the release | 186 |
| Early-boot egress failure (cli1) | OnFailure lock-down at 9.47 s, before network-pre (9.55 s); a lab boot timer restored the files | 179 |

## Gates (final)

| Gate | Result | Log |
|---|---|---|
| CUI scan, every host | 108 pass / 2 fail x3, no rule changed vs Plan 2 round 4; deviations MET (the two accepted AIDE rules) | 113, 114 |
| adapter / nvram / snapspike / fixtures | ALL PASS / FIXTURES OK | 115, 116 |
| Regression | **33/33 in one pass** (11 scenarios x 3; model 33/33 valid, 32/33 agreeing; c4 3/3) - `lab/iso5/regression-2026-11-20.md` | 178 |
| Row 36 | **3/3**, label `var_auth_t` | 182 |
| Golden | ALL PASS (177); retaken after removing the lab scripts and test files (188) | 177, 188 |

## Fault injection and restoration

Every deliberate weakening (stopped kanidmd, broken site.conf / address file, lock-downs, immutable files, a logger
bind mount, maintenance mode, app off, rules removed, a local cui-users account, a disabled chp-publisher, a held lock,
an IPv6 route, a tap capture on aero) and the evidence that each was undone is listed in the Task 11c report
(`.superpowers/sdd/2026-11-19-iso-0.7.0-plan3-document-workflow/task-11c-report.md`), logs/180, 181, 183, 184, 186-188.
Kept on purpose: the lab alert hook (`ALERT_HOOK=/usr/local/sbin/lab-hook`) and chp-templates on the workstations (W1).

## Lab state at the end

srv and cli2 at the final golden (188); cli1 restored (180). Overnight items pending: the 00:20 review (override under
Needs attention, D14 counts), 01:40 backup, 03:10 check + canary, 04:04 AIDE (D15), and an 8 h sign-in end (B15).

## Timed items (2026-11-21, round 1 final)

| Item | Result | Log |
|---|---|---|
| Review 2026-11-20 (built 00:20 11-21) | "Needs attention: 1" = the ISSO override (CR-2026-0003, lab01, 12:34) with its reason; 11 publications each "approved by lab04" / "ISSO override by lab01"; refusals row "canary: 16 refused as expected" (D14 fixed) | 189 |
| Review sign-off | signed as `ISSO_NAME` "D. Shannon" (typed name, unchanged in 0.7.0); needs a terminal (`script -q`); recorded; `review verify` OK. The 2026-11-22 build should no longer list the override (follow-up) | 189 |
| Nightly backup 01:40 | OK, 4.2M, 75 files; ledger copy identical to the live ledger; 0.13.0 order: shared lock → ledger copy → maintenance on → lock released → pg_dump | 190 |
| Nightly check + canary 03:10 | OK; 100618 level 3 inside the window; 100608 x2; canary disabled, 0 tokens; check 81 OK | 190 |
| Daily AIDE 04:04 (D15) | no `/etc/pki/nextcloud` path although chain.pem was re-issued at 02:37 after the baseline (D15 fixed); lab residue listed (adapter, lab hook, /root lab logs) | 190 |
| 8 h sign-in end (B15) | NOT RUN: no sign-in was kept alive overnight (sessions ended before the final golden) | — |

# Round 2 (repo 0.14.0, Task 13c, 2026-11-21)

Repo **0.14.0** (owner-signed; `verify-repo` REPO OK 72) applied **in place** (no reset) to iso5-srv, iso5-cli1,
iso5-cli2. Code read from branch `iso-0.7.0-owner-batch`. Logs 191-227. Driver additions: `cycle.sh` (one document
cycle). No product code changed. Full verdicts: `task-13c-report.md`.

## Setup

| Step | Result | Log |
|---|---|---|
| `dnf --refresh upgrade` | srv upgrade 6 (chp-base 0.1.0-14, chp-documents 0.1.0-10, chp-identity-client 0.2.4-4, chp-identity-server 0.1.2-6, chp-site 0.14.0-10, nextcloud-chp 35.0.3-7); cli1/cli2 upgrade 5 (incl. chp-onlyoffice 0.1.0-5, chp-templates 1.4.0-2); pins pulled together; 0 denials | 191 |
| `chp-site time-sync --role server` (first), twice | chrony: `allow 192.168.100.0/24`, `bindaddress 192.168.100.50` + `::1`, `local stratum 10`; firewalld 123/udp from the subnet only; second run "unchanged"; label etc_t, no AVC; **NTP socket on 192.168.100.50:123 only** (no `[::1]:123` socket either: stricter than expected) | 192 |
| `time-sync --role client` cli1, cli2 | only source the server (`^*`), Reference ID = server; egress table: chronyd (uid 997) → server:123 only; check 20 OK "the CHP server"; server serverstats count the packets | 193 |
| Second time source by hand (cli1) | check 20 ALERT "time sources other than the CHP server"; the packets refused and logged (CHP-WS-EGRESS DPT=123); removed → OK | 194 |
| `documents enable` run 6; `onlyoffice enable` cli1/cli2 | exit 0; new Wazuh rules; workstations: exit 0 (run as a transient unit: see note) | 195, 196 |
| AIDE accept x3 | accepted and pinned | 198 |
| CUI scan, round-1 profile | srv 107/3: the only change vs round 1 is `chronyd_client_only` pass→fail (the server now serves time: owner decision 2026-11-20); cli1/cli2 108/2, no change. Lab decision row added citing the owner decision → **Gate 3 MET** | 200, 202 |
| Server tailoring `chp-server-cui-tailoring.xml` (profile `xccdf_org.cyberhygiene_profile_cui_chp_server`, extends the stock CUI profile) | vs the stock CUI profile on the same host: exactly `chronyd_client_only` and `sysctl_user_max_user_namespaces` change fail → notselected; everything else identical (101 pass, 0 fail) | 201 |

Note: on the workstations `KillUserProcesses=yes` (in force since round 1's reboot) ends every process of the admin's
console session at logout, so the driver's detached runs died there; workstation commands now run as transient units.
This is the documented product behaviour (guide: admins' tmux/screen end at logout).

## Proofs

| Proof | Result | Log |
|---|---|---|
| FCI end to end, docx/xlsx/md | `doc new --fci` → check ("FCI banner") → mark → approve → publish: CR-2026-0012/13/14; reader PDFs: "FCI" first line and last line of page 1, no "CUI" line; files + PDFs in CUI/Compliance tagged CUI | 203, 204 |
| CUI `.md` (D10) | CR-2026-0015; banners first/last, block on page one | 204 |
| Wrong banners | CUI marks on an `FCI_` doc and FCI marks on a `CUI_` doc: refused by `doc check` and `doc mark` (client) and by the server's marking check (raw publish) | 205 |
| `doc mark` on an unmarked FCI draft | adds only "FCI" (header + footer); then OK | 206 |
| FCI v0.2, nightly check | v0.1 → Archive/Superseded; `documents check` OK, no `name:` alert | 206 |
| 12b wrapped banners | `**CUI**`, `# CUI`, `> CUI`, `C U I`, `CUI //SP-PROPIN` in an FCI .md: each refused | 216 |
| D4 | loser: "the current version changed since your checkout: lab06 published … as CR-2026-0017 (ledger entry 72) … check out the current version again" | 207 |
| D13 | 2001 bytes: exit 2 plain text, nothing sent; 2000 bytes sent | 208 |
| D9 | `/status` = `true` 200; kanidmd stopped: checkout exit 3 "Kanidm cannot be reached … no new sign-in is needed (nothing was sent)"; back: works, no new login | 209 |
| D8 | maintenance mode: publish exit 3 "pending … maintenance mode … (nothing was sent)", spool and journal unchanged; after: CR-2026-0018 | 210 |
| D6 | `<If "%{REQUEST_URI} …">` LimitRequestBody: a 97 MiB body still reached PHP on both OCS paths (app 400); the `%{THE_REQUEST}` variant tried on the lab conf, same; conf restored byte-identical. **Still failing** (the app's 64 MiB check stays the control, as the README now says) | 211 |
| D11 | one quarantine copy, one spool-unlink-failed, one appender-failed for a run of 40 triggers; the path unit then trips its limit (as designed); reset | 212 |
| D3 | (a) user_oidc 8.13.0 `Backend.php`: the Bearer path calls `getOrCreate` whenever the global `auto_provision` is on; per-provider bearer provisioning only controls attribute provisioning; no setting stops Bearer creation without stopping web first sign-ins. (b) lab02 (never on the web) `doc login`: refused with the browser URL; the group-less account exists. (c) a group-less account's POST: 403 "your NextCloud account has no groups yet …", audit `chp.ledger.nogroups`, **100634 L12** at the hook. (d) nightly check ALERT `has no groups`; after lab02's web sign-in: clean | 197, 213, 214 |
| D2 | chp-onlyoffice requires chp-templates >= 1.4.0-2 and chp-site >= 0.14.0-10; upgraded together (the pull onto a workstation without templates not shown: round 1's W1 had installed it) | 215 |
| D7 | agent state file `/var/ossec/var/run/wazuh-agentd.state`, `status='connected'`, rewritten every ~5 s. Render failure + lock-down on cli1 with a restore timer: after recovery the check-83 run sent **100635 L12** (lock-down start time + cause) and **100636 L7** to the manager. One 100636, for a render failure that ended the same second the lock-down began, was lost (the residual Task 13a noted). **60-min fallback: FAIL (P3-D15)** | 217, 226 |
| D12 | `doc login`: "sign-in ends: about … (an estimate: sign-in time + the 8 h refresh lifetime; Kanidm did not give the end)" | 199 |
| D14 | `/var/log/journal` exists; after a server reboot `--list-boots` keeps the previous boot with 92 appender lines (incl. CR-2026-0018); checks 77-82 OK | 219 |
| D5 | guide row: "raises it five times" with the breakdown | (SITE-STICK.md:469) |
| O5 | `matchpathcon` = `etc_t`: the old net_conf_t expectation was wrong; cosmetic | 217 |
| D1 | NOT RUN: needs a server where NextCloud was never installed (a full reset); the run-6 enable found the trust entry already matching, so the probe did not run | 195 |

## New defect

- **P3-D15 (important).** `onlyoffice.py:199-208` `_agent_connected` returns None ("no Wazuh agent state file
  (nothing to wait for)") when `/var/ossec/var/run/wazuh-agentd.state` is missing, and wazuh-agentd removes that file
  when it stops. With the agent stopped at recovery (cli1, 18:13:41), the recovery lines were logged at once (18:13:42,
  "OK egress: reported: EGRESS RECOVERED …"): no hold, no 60-min fallback, no ALERT, and a line written while the
  agent is down is not sent later. Fix: when the agent is installed (`/var/ossec/bin/wazuh-agentd` or the unit
  exists), treat a missing state file as "not connected". logs/226.

## Fault injection and restoration (round 2)

| Host | What | Why | Undone / evidence | Log |
|---|---|---|---|---|
| srv | kanidmd stopped (~1 min) | D9 | active | 209, 220 |
| srv | maintenance mode on | D8 | off | 210, 220 |
| srv | installed `chp-nextcloud.conf` edited to the THE_REQUEST variant + reload | D6 | copy restored, sha256 equal ("conf restored byte-identical"), `apachectl -t` OK, httpd active | 211 |
| srv | immutable spool file + 40 stray files | D11 | `chattr -i`, path unit reset + active, quarantine purged (0), 0 immutable files | 212, 220 |
| srv | lab01 removed from cui-users/chp-users in NextCloud | D3(c) | groups back by a web sign-in (user_oidc maps them) | 214, 220 |
| srv | reboot | D14 | all units back, checks OK | 219 |
| srv | /root lab outputs | driver | removed | 220 |
| cli1 | a second chrony source by hand | T3 | deleted; check 20 OK | 194 |
| cli1 | render failure, lock-down x2 (address file removed + DOMAIN broken), restore timers `lab-egress-restore-r2`/`-b`, units `lab-d7`/`lab-d7b` | D7 | site.conf + address file `sha256sum -c` OK against the pre-test hashes; 0 lab units; no `*.good`; egress active, policy drop, no lock-down table | 218, 226 |
| cli1 | wazuh-agent stopped (~2 h) | D7 fallback | started, `status='connected'` | 226 |
| cli2 | lab user sessions; 97 MiB bodies and test docs in /tmp | driver, D6 | anchors stopped, /tmp cleaned (220); **lab01's anchor restarted for B15 (kept on purpose)** | 220, 227 |
| Mac (worktree only) | `.venv` symlink to the main checkout's venv (prove.sh/engine need it) | gates | not committed | — |
| lab file | `lab/iso5/decisions.tsv`: the `chronyd_client_only` row citing the owner decision of 2026-11-20 | Gate 3 | committed (controller to confirm) | 202 |

SELinux Enforcing, fapolicyd active (0 denials) and firewalld active on every host after the tests (218, 220, 226).

## Gates (round 2)

| Gate | Result | Log |
|---|---|---|
| CUI scan | srv 107/3 (`chronyd_client_only`, owner decision), cli1/cli2 108/2; no other change; MET | 200, 202 |
| adapter / nvram / snapspike | ALL PASS | 221 |
| fixtures | not re-runnable on users that already hold credentials (fixtures.py stops at lab01's enrolment; lab tool); round-1 users intact (lab01 web sign-in and POSIX probe OK) | 222 |
| Golden | ALL PASS (fresh, after the proofs) | 223 |
| Regression | **NOT RUN**: LM Studio's server was OFF on the Mac (`lms status`: Server OFF), all 32 runs before the stop EXPLAIN-FAILED; aborted, srv/cli2 reset to golden | 224 |
| Row 36 | 3/3 | 225 |

## Pending

- **Regression 33/33:** needs LM Studio's server on the Mac (`lms server start`, the devstral model). Run it AFTER the
  B15 check (it resets cli2).
- **B15:** lab01's sign-in started 2026-11-21 20:03:45Z (13:03 MST) on cli2 in a held session; due ~21:04 MST
  (04:04Z 11-22): `chp-site doc check` / any doc command should say "run chp-site doc login".
