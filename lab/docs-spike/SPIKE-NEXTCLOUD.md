# Spike: NextCloud on a hardened CHP server (ISO 0.7.0 Plan 1, Task 1)

## Plan 2 inputs (Task 9 hand-off, 2026-11-12)

Plan 2 is written from this section. Each item cites the section or log below that holds the evidence. Nothing
here is new testing: it summarises Tasks 1-3.

### What was chosen

- **Packages** (§Packages, `logs/42`). Everything below comes from the Rocky 9.8 DVD and is Rocky-signed:
  PHP `php:8.3` stream 8.3.29 (php-fpm with the modules listed there; no php-sodium in Rocky); PostgreSQL
  `postgresql:16` 16.13, socket only, peer authentication, so there is no database password; httpd 2.4.62 + mod_ssl +
  php-fpm; APCu cache, file locking in the database. NextCloud 35.0.3 plus groupfolders 23.0.1, files_accesscontrol
  6.0.1 and user_oidc 8.13.0 (signatures verified, `MANIFEST.txt`), plus our apps `chp_foldertag` and `chp_ledger`.
  All of it goes in our own RPM, code under `/usr/lib/nextcloud` (not `/usr/share`: fapolicyd's filter, §Under the
  CUI profile fix 1). **PHP 8.3 is the newest PHP in Rocky 9, and NextCloud 35 already calls it deprecated**
  ("Nextcloud 37 may require at least PHP 8.4", finding 4).
- **Sign-in** (§Sign-in). OIDC from NextCloud's user_oidc to Kanidm: ES256 id tokens, PKCE S256, a `chp_groups`
  claim map (`cui-users`, `doc-reviewers`, `chp-users`). The login page goes straight to Kanidm. The break-glass
  admin uses `/login?direct=1` with a bcrypt hash, because FIPS breaks PHP's Argon2id (fix 3). Host sign-in is
  unchanged: row 36 3/3 (`logs/20`).
- **Transport for `chp-site doc`** (§Transport, route 1, `logs/44-49`, `logs/62-63`). A Kanidm **public client**
  `chp-doc` (authorization code + PKCE, a one-shot `127.0.0.1` redirect listener on port 0). The access token goes to
  NextCloud as `Authorization: Bearer`. Tokens are kept in `$XDG_RUNTIME_DIR` (tmpfs) and are gone at logout. Access
  tokens last 15 min; refresh tokens are set to 8 h, but that limit is untested. A Kanidm lock takes effect on the
  next request. NextCloud gets a second user_oidc provider that checks the Bearer with userinfo, and five vhost
  rewrite lines keep the login page straight to Kanidm. Login Flow v2 app passwords are rejected: they never expire
  and keep working after a Kanidm lock (`logs/47`).
- **Freshness** (§Freshness, `logs/50-53`). The marker is the **sha256 of the canonical bytes plus the file id**,
  recorded at checkout and compared at publish. The ETag can stay the same when the content changes and can come
  back after a version restore, so it is used only as a cheap pre-check and as `If-Match` on the final write. That
  **narrows** the race between check and write. It does not close it (review fix 2).
- **Ledger** (§Ledger L1, review fixes 3-5, `logs/57`, `logs/60`, `logs/67-72`). The NextCloud app `chp_ledger`
  takes a request over NextCloud's HTTPS (no new port), stamps it with the authenticated NextCloud user and drops it
  in `/var/lib/chp-docs/spool`. A `.path` unit then starts the **root appender**, which writes the hash-chained
  ledger at `/var/lib/chp-docs/ledger/ledger.jsonl` (root, 0600), with a head witness and an export to the stick.
  The appender **re-validates every Bearer at Kanidm's `chp-doc` userinfo** and records only what Kanidm returns. A
  token that does not validate makes the whole request refused, and approve and override need a verified Bearer.
  **Author rule, per cycle** (fix 4). A cycle runs from the last publish (or the creation) to now. Authors(cycle) =
  the creator + everyone who checked the file out in the cycle + the publisher. An approver must be outside
  Authors(cycle), must approve after the cycle's last checkout, and must approve that exact sha256. The publisher must
  be in Authors(cycle).
- **Server-side publish is a MUST** (review fix 1). The prototype's PUT by the author lets anyone with write access
  skip every rule. In Plan 2 the Compliance areas are read-only to all users (ACL), and `chp_ledger` (or the
  appender) receives the bytes. Under a lock, it compares and writes in one step: the received sha256 must equal the
  approved sha256, and the canonical copy's current sha256 must equal the checkout's.
- **Tag by folder** (§Tag by folder, `logs/24`, `logs/26`). The app `chp_foldertag` tags on NodeCreated, Written,
  Copied and Renamed. Its rule maps a team folder to a restricted system tag (`CUI`, `FCI`). Disabling it raises a
  level-12 alert. The nightly check must run **outside** the app, from chp-base/chp-site with SQL, because the
  app's own command disappears when the app is off. **ContainListener** (§Copy out, `logs/41`): `chp_foldertag`
  0.2.0 refuses copy and move out of CUI, FCI and Archive (403, nothing created).
- **Egress** (§Outbound, `logs/21`, `logs/40`). The settings say there is no internet connection and the outbound
  apps are off. Below the application, the nftables table `inet chp_nextcloud_egress` matches **the apache uid**
  (`meta skuid "apache"`, a positive match): loopback and the server's own address only; anything else is logged
  (`CHP-NC-EGRESS`) and rejected. SELinux: only `httpd_can_network_relay` is on. **BindsTo + `ExecStartPre` pre-check**
  drop-ins mean php-fpm and httpd do not run without the table. **No DNS for apache** (port 53 refused and
  logged). NextCloud's own names (`idm.`, `files.`) come from **`/etc/hosts`, rendered from site config**. The
  spike recommends shipping the no-DNS variant.
- **Editor** (§Editor, `logs/78-89`). **ONLYOFFICE Desktop Editors 10.0.0 works with limits** on the FIPS/CUI
  workstation: open, edit, save and PDF export, with the marks kept on every page; no crypto error; 0 fapolicyd
  denials and 0 AVCs from the app. The limits: (1) the "latest" RPM is unsigned (the yum-repo copy is signed, so we
  re-sign it); (2) the bundled Chromium BoringSSL is not validated and ignores FIPS (POA&M; the editor makes no TLS
  in the data path); (3) headless `x2t` works only after a first GUI run and is undocumented; (4) the start page
  shows vendor and AI features; (5) Chromium runs `--no-sandbox`; (6) the app is 1.2 GB, runs `unconfined_t` and
  keeps autosave copies of CUI under `~/.local/share/onlyoffice` (`logs/88`); (7) fapolicyd failed once during back-to-back installs;
  (8) the GUI was tested under Xvfb only, with a minimal feature set; (9) Chromium has a path straight to a public
  resolver, so `/etc/hosts` alone is not an egress control. It also needs six extra Rocky packages in the stick repo.
  Its three gate items are G1-G3 below. LibreOffice was not tried.
- **Resource use** (§Resource use, `logs/37`; §Transport, `logs/63`; §Editor). At rest the server used 1.7 GiB of
  an 8 GiB VM. The largest services are wazuh-manager 1,281 MB and suricata 539 MB; php-fpm 123 MB, httpd 60 MB and
  postgresql 39 MB. The code is 874 MB and the database 74 MB. **The server needs 8 GiB, not the 4 GiB default.** A
  Bearer PROPFIND takes a median 191 ms, against 92 ms with an app password. On the workstation, ONLYOFFICE is a
  291 MB RPM, 1.2 GB installed, plus 14 MB of user data.
- **Port 8443** (finding 3). Kanidm owns `SERVER_IP:443`, so NextCloud serves `https://files.<DOMAIN>:8443`, LAN only
  (`SUBNET_CIDR`, fix 7).
- **Build host** (§Packages). aero's fapolicyd denies `rpmbuild` reading untrusted PHP, so the spike RPM was built
  on the Mac (rpm 6.1, v4 format; EL9 installs it). An aero rule was refused by the permission system.
- **App version bump** (§Copy out, review fix 3, `logs/67`). Any change to an app's version leaves NextCloud
  answering 503 ("upgrade required") until `occ upgrade` runs, so the RPM's `%post` must run it.

### Every "(builder)" item in the design, answered

| Design | Item | Answer |
|---|---|---|
| §2 | database, web server, PHP stream | PostgreSQL 16 (socket, peer auth), httpd + mod_ssl + php-fpm, `php:8.3` (§Packages) |
| §2 | no-internet mechanism | settings + apps off; nft table by apache uid; no DNS for apache, `/etc/hosts` from site; BindsTo + pre-check; only `httpd_can_network_relay` (§Outbound) |
| §3 | sign-in protocol | OIDC (user_oidc, ES256, PKCE S256, `chp_groups` claim) (§Sign-in) |
| §4 | doc transport and authentication | Kanidm public client `chp-doc` + Bearer, tokens in tmpfs (§Transport route 1) |
| §4 | citation check: how far to automate | **not studied in the spike**; Plan 2 design |
| §4 | site-key names for the ISSO's and approvers' Kanidm accounts | **not named in the spike** (the prototype used constants, `proto/docs_ledger.py` `APPROVERS`/`ISSO`); Plan 2 names them |
| §4 | ledger location; append without a new listener | `/var/lib/chp-docs/ledger/`, `chp_ledger` OCS app → spool → root appender with Kanidm userinfo check (§Ledger L1) |
| §5 | marking site-key names | **not studied**; Plan 2 names them |
| §5 | checker per format | **not built**. Evidence only: python-docx, openpyxl and `pdftotext` read the banners and blocks reliably on ONLYOFFICE output (§Editor); `x2t` can make the PDF after a first GUI run (limit 3); md not looked at |
| §6 | monitor check numbers | **not assigned** (check 76 is the latest in use). The spike needs checks for: httpd, php-fpm and postgresql up; the NextCloud certificate; the egress table present and intact; `chp-docs-ledger.path` active; `fapolicyd.service` not failed (G1) |

### Plan 2 MUST / gate items (deduplicated)

1. **M1 Server-side publish** (review fix 1): Compliance read-only to users; atomic compare-and-write by sha256 under a lock.
2. **M2 Ledger hardening** (fixes 3-5, round 2, deferred minors): Kanidm userinfo re-validation; approve and override
   need a Bearer; per-cycle author rule; quarantine on any failure; finite start limits with `OnFailure` alert on the
   service **and** the path unit; a per-user rate limit in the app; Compliance-only file ids, with the team-folder
   ids rendered from the site; a generic refusal text; the userinfo call pinned to the site CA, host from site
   config, no redirects, timeout + rate budget; retry (not quarantine) on a Kanidm outage; `O_NOFOLLOW`, no TOCTOU on the
   spool; keep `--mapping-uid=preferred_username`/`--unique-uid=0`; set `auto_provision` deliberately. Deferred
   minors (ledger, Task 2): root check on `purge-quarantine`; non-dict JSON in quarantine; the appender's
   team-folder re-check trusts apache-side fields; `O_TRUNC` filename collision; unlink failure in `finally`; a
   requester told "refused" after a successful append.
3. **M3 Transport**: bind port 0 and keep listening until the right `state` arrives; linger off for these users;
   test a refresh near the 8 h limit and read the expiry from Kanidm (fix 6); the login rewrite.
4. **M4 Egress**: ship the no-DNS variant and `/etc/hosts` from the site; BindsTo + pre-check; a monitor check for the
   table (deleting it at run time goes unnoticed until a restart).
5. **M5 Tags**: nightly tag check and canary from chp-base/chp-site (SQL), not from the app; send ContainListener's
   refusals to the audit log and Wazuh. Untested so far: renames and subfolder moves inside CUI, and trash or
   version restore across folders.
6. **M6 Package**: our signed RPM from a decided build host; `occ upgrade` in `%post`; the `config.php` trust entry;
   rule 65; stock listeners off; `SUBNET_CIDR`; `files` in the site zone; certificate renewal timer (ACME opens
   :80 per issue, like Kanidm's); backup timer; Wazuh rules (+ a Kanidm failed-TOTP rule); 8 GiB server default.
7. **M7 fapolicyd** (findings 1-2): trial `allow_filesystem_mark = 1` per role before shipping; decide the gate
   (FANOTIFY count vs `--check-status`, read after a fapolicyd restart, because a rule reload keeps cached
   decisions).
8. **G1 fapolicyd health** (editor gate 1): alarm on `fapolicyd.service` failed; a "two package installs back to
   back" test on the workstation role.
9. **G2 Autosave cleanup** (editor gate 2): a close hook in `chp-site doc` **and** a periodic sweep that removes
   `recover/DE__*` only when there is no live ONLYOFFICE process of that user **and** it is older than N hours;
   logged; the copies are treated as CUI.
10. **G3 Per-application egress on the workstation** (editor gate 3): default-drop except the site server, DNS only
    to the site resolver (IPv4 + IPv6, DoT/DoH ports), hosts block kept; tested with an IPv6 default route present.
11. **G4 ONLYOFFICE packaging**: re-sign the yum-repo RPM (sha256 pinned); remove the AI Tools plugin as a
    post-install step; pre-seed "Don't show AI Tools"; ship the six extra packages.

### Owner decisions needed (not decided here)

1. **fapolicyd `allow_filesystem_mark`** (finding 1). *Problem:* with the RHEL default 0, daemons in their own mount
   namespace (httpd, php-fpm, kanidmd, named, step-ca, suricata, …) have their file opens unchecked; this was seen
   on two hosts and probably affects released ones. Past "0 denials" gates and the **shipped**
   collector `idm-collect` (line 266) share the blind spot (finding 2). *Options:* turn it on for 0.7.0 and released hosts after a per-role
   trial (it broke php-fpm until rule 65); 0.7.0 only; or leave it off and record it. *Spike:* trial per role
   before shipping.
2. **Download then re-upload of CUI** (§Copy out). *Problem:* a `cui-users` member can download a CUI file, upload it
   to Operations and share it; nothing in NextCloud can stop that. *Options:* a content (banner) check on uploads
   outside CUI/FCI; no share right for `cui-users` outside CUI; or accept it, document it, and rely on training and
   audit. *Spike:* no recommendation.
3. **ContainListener also blocks CUI → Archive/FCI moves** (§Copy out; a Task 1 review minor). *Problem:* the
   design's "withdraw to Archive" step and admin moves are refused too. *Options:* allow named pairs (for example
   CUI → Archive); do withdrawals through the server-side publish path; or keep the block and do moves by admin
   `occ`. *Spike:* no recommendation.
4. **Where the NextCloud RPM is built** (§Packages). *Problem:* aero's fapolicyd blocks PHP in `rpmbuild`.
   *Options:* an aero fapolicyd rule limited to the build directory (owner approval); a small build VM; the Mac.
   *Spike:* no recommendation.
5. **Port 8443** (finding 3). *Options:* (a) 8443; (b) a second server address for `files.`; (c) an SNI router in
   front of Kanidm and NextCloud. *Spike:* (a).
6. **PHP 8.3** (finding 4). *Problem:* NextCloud 35 calls PHP 8.3 deprecated and Rocky 9 has nothing newer; 37 may
   need 8.4. *Options:* ship on 8.3 and plan the move before 37 (a later Rocky 9 stream, or Rocky 10; neither
   checked); a third-party PHP (breaks the Rocky-signed rule in design §2); stay on an older NextCloud. *Spike:* needs
   a plan before 37; no choice made.
7. **Reviewers read-only on all six folders** (§Folders). *Problem:* as built, the reviewer ACL removes write,
   create, delete and share for reviewers on Operations, Internal and Public as well. *Options:* confirm; or limit
   the ACL to CUI, FCI and Archive. *Spike:* asks for confirmation.
8. **ONLYOFFICE: accept the limits?** (§Editor; design §4 TBD). *Problem:* it works, but with a bundled
   non-validated BoringSSL (POA&M line), `--no-sandbox`, `unconfined_t`, autosave copies of CUI outside the CUI
   rules (G2), and a vendor RPM we must re-sign. *Options (design §4):* accept with the POA&M line and G1-G4;
   LibreOffice from Rocky (not tested); or ship the store without a desktop editor. *Spike:* no recommendation.

Smaller policy points that Plan 2 should confirm with the owner: repeated checkouts void pending approvals, and
`create` makes the caller an author (round 2).

**Task 3 (editor, 2026-11-12, §Editor): ONLYOFFICE Desktop Editors 10.0.0 on the FIPS/CUI workstation: works with limits.**

**Task 2 (doc commands, 2026-11-13, §Transport and §Ledger):** sign in with a Kanidm public client and send the
token as a Bearer (nothing long-lived on the workstation; a Kanidm lock takes effect on the next request); the
freshness marker is the content hash, because **NextCloud's ETag can stay the same across a content change**;
the approval ledger is appended by a root job, fed by a small NextCloud app over NextCloud's own HTTPS (no new port).

**Result: NextCloud 35.0.3 runs on a FIPS, SELinux-enforcing, fapolicyd, CUI-profile CHP server installed from ISO
0.6.0, signs in through Kanidm (password + TOTP), never reaches the internet, refuses every share of CUI/FCI, tags by
folder, audits to Wazuh, and restores from `/backup`. No product blocker.** Every step below was run on the lab
(2026-11-12); raw output is in `logs/` (numbered in run order). Rebuild: `README.md`.

Five findings matter beyond NextCloud and need decisions in Plan 2 (details in their sections; review fixes of
2026-11-12 in `logs/38-42`):

1. **fapolicyd does not check file opens by processes in their own mount namespace while `allow_filesystem_mark = 0`.**
   Observed on iso5-docs (server) and iso5-dcli (client): `head` of an untrusted `.php` file is denied in the host
   namespace and allowed under `systemd-run -p PrivateTmp=yes` (`logs/31`); php-fpm (`PrivateTmp=yes`) downloaded users'
   `.php`/`.py` files unchecked (`logs/30`). `allow_filesystem_mark = 0` is the RHEL default and CHP never changes it, so
   the other CHP hosts are probably affected too, but they were **not tested**. Only file **opens** on `/data`, `/home`
   were tested; **execute** and other mounts were not. Units that run in their own mount namespace on these two hosts
   (`logs/39`): chronyd, dbus-broker, irqbalance, kanidm-unixd(-tasks), ModemManager, NetworkManager, rsyslog, suricata,
   systemd-logind, systemd-udevd, usbguard on both; plus httpd, php-fpm, kanidmd, named, step-ca on the server (Wazuh
   is not among them). **Turning it on is not simply "stricter": it broke php-fpm's downloads of users' script files at
   once (HTTP 503, `logs/32`) until rule 65 was added.** On released hosts it may start blocking daemons that work
   today only because they are unchecked (suricata, kanidmd, named, step-ca, …). Plan 2 must trial it per host role
   (server and workstation) before shipping it. iso5-docs runs with it on since `logs/31`; iso5-dcli is as installed.
2. **The "0 FANOTIFY records" gates and the collector's fapolicyd signal: not shown blind, but not a full count
   either.** Side-by-side (`logs/38`): a php-fpm denial (daemon, no login uid) added 2 FANOTIFY records and 2 to
   `fapolicyd-cli --check-status`; an admin-session denial added 1 and 1. So **daemon denials do reach the audit log**
   here; my first claim that they do not was wrong. What was observed: early in the work the counter said 8 denials
   while the audit log held 3 FANOTIFY records (`logs/11`), unexplained; the counter resets when fapolicyd restarts while
   the audit log does not; and `fagenrules --load` does not drop fapolicyd's decision cache (a removed rule kept
   allowing until a restart, `logs/38`), so a gate run right after a rule change can pass on stale decisions. The places
   that rely on the FANOTIFY count (not changed now; Plan 2 decides): `lab/iso5/prove.sh` 82, 169, 360;
   `lab/iso4/prove.sh` 52, 187, 301; `lab/iso3/prove.sh` 71, 132; `lab/security/prove-r1.sh` 58, `prove-s1.sh` 60, 121,
   `prove-w1.sh` 50, `prove-y1.sh` 55; `lab/host/iso1-install-test.sh` 42; the **shipped** collector
   `collector/idm-collect` 266 (`ausearch -m FANOTIFY -ts recent`, `resp=2`); and the records that cite those gates:
   `appliance/release/RELEASE-RECORD-0.1.0.md` (53, 60: "0 FANOTIFY events ever"), `0.1.1`, `0.5.6`, `0.7.8`,
   `lab/iso3`, `lab/iso4`, `lab/iso5` PROOF-RECORDs, `lab/security/PROOF-RECORD-{ISO-0.6.0,W1,W2,Y1,R1,S1}.md`,
   `SPIKE-{SURICATA,YARA,REVIEW}.md`, `lab/aide/PROOF-RECORD.md`, `lab/iso-requirements.md`. **The diagnostic
   collector's fapolicyd signal and every past "0 denials" gate share finding 1's blind spot**: a denial that never
   happens (because a namespaced daemon is not checked) is counted by neither method.
3. **Kanidm owns `SERVER_IP:443`**, so NextCloud cannot also use 443 on the server's address. The spike serves
   `https://files.docs.lab.test:8443` (Plan 2 options below).
4. **PHP 8.3 is the newest PHP stream on the Rocky 9.8 DVD** (`dnf module list`: 8.1, 8.2, 8.3; `logs/42`) **and
   NextCloud 35 already calls it deprecated** ("Nextcloud 37 may require at least PHP 8.4"). NextCloud 35 runs on it
   (shown); that 36 will too is an **inference** from that message, not shown. The product needs a plan before 37.
5. **Copy-out-of-CUI bypass** (`logs/41`): a `cui-users` member also has write + share in Operations and their own home,
   so a CUI file copied or moved there could be shared internally and by public link, and lab02 read it; a copy carries
   no tag. A prototype control (refuse copy/move out of CUI/FCI/Archive) stops the WebDAV/browser copy and move;
   **download then re-upload still works**, which nothing in NextCloud stops: an owner decision (§Copy out).

## Lab

| Host | Role | Disk | Notes |
|---|---|---|---|
| iso5-docs | server, 192.168.100.53, `52:54:00:c4:05:53` | 1863 GiB sparse, size guard 50 GB (never tripped; image 14 GB at the end) | raised to 8 GiB RAM / 4 vCPU after the scan (`install.sh mem`) |
| iso5-dcli | client, 192.168.100.54, `52:54:00:c4:05:54` | 120 GiB | for row 36 |

**Hosts table: not one row added to `lab/iso5/hosts` but a separate lab site** (`hosts`, `site.conf.in`,
`docs.lab.test`, `SECURITY_ADDONS=yes`), because `chp_site/hosts.py` allows exactly one server per site and NextCloud
belongs on the server that runs Kanidm. The iso5 lab was not touched (its helpers in `aero:/tmp/iso2` are reused, never
deleted). Install chain: `install.sh prep/server/firstboot/export/client` all PASS (`logs/01-06`), from the released
ISO 0.6.0-rc2 (sha256 `0cb27c14…7cac0`, checked on aero).

**CUI scan before anything: 108 pass / 2 fail on both hosts** (the two accepted AIDE rules,
`aide_periodic_cron_checking`, `aide_scan_notification`; `scan-results/*.xml.xz` (xz, as earlier proof records), `logs/07`). **After all the NextCloud work:
108 / 2 on iso5-docs, the same two rules** (`scan-results/after-nextcloud/iso5-docs.xml.xz`): NextCloud, httpd, PHP, PostgreSQL, the
egress table and the fapolicyd changes moved no rule.

## Packages (Step 2)

All from the **Rocky 9.8 DVD** (`aero:/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso`, sha256 = the published CHECKSUM),
attached read-only to the server as a virtio disk and used with `--repofrompath` and `gpgcheck=1` (`spike.sh dvd-on`;
SATA cannot hot-plug and USBGuard correctly blocks a USB disk). Every installed httpd, mod_ssl, apr, php and postgresql
package carries `RSA/SHA256 … Key ID 702d426d350d275d` (Rocky Release key 2022, in the rpm database), and `rpm -K` of
the DVD's php-fpm and postgresql-server packages says `digests signatures OK` (`logs/42`).

| Choice | Version | Why |
|---|---|---|
| PHP | `php:8.3` stream, 8.3.29 (php-fpm, -cli, -gd, -mbstring, -intl, -xml, -pgsql, -process, -bcmath, -gmp, -opcache, -pecl-zip, -pecl-apcu) | NextCloud 35 needs PHP >= 8.3 (`lib/versioncheck.php`: 8.3 to < 8.6); 8.3 is the newest stream on the DVD (`dnf module list`, `logs/42`). **No php-sodium in Rocky** (libsodium is EPEL-only): NextCloud lists it as recommended, not required. |
| Database | `postgresql:16`, 16.13 | NextCloud 35 supports 14 to 18. Unix socket only (`listen_addresses = ''`), **peer authentication**: the OS user `apache` is the database role, so there is **no database password anywhere**; `password_encryption` is scram-sha-256 (FIPS-safe) for any later password. 15 and 18 are also on the DVD (`logs/42`); 16 chosen as the middle of NextCloud's window. |
| Web server | httpd 2.4.62 + mod_ssl + php-fpm (proxy_fcgi) | the stock SELinux `httpd_t` policy covers it; NextCloud's shipped `.htaccess` works. Only one listener (`*:8443`): `Listen 80` commented out, `ssl.conf`/`welcome.conf`/`userdir.conf`/`autoindex.conf` disabled. |
| Cache | APCu (`memcache.local`), file locking in the database | no extra daemon; Redis not needed at this size |

**NextCloud** 35.0.3 (current stable, built 2026-11-12): sha256 = the published `.sha256` and a good GPG signature by
Nextcloud Security `2880 6A87 8AE4 23A2 8372 792E D758 99B9 A724 937A`. **App-store apps** (`fetch-inputs.sh`): each
release's RSA-SHA512 signature verified with the app's certificate, and that certificate verified against the
NextCloud code-signing root shipped in the (verified) server tarball, CN = app id: groupfolders 23.0.1 (Team folders),
files_accesscontrol 6.0.1, user_oidc 8.13.0 (`MANIFEST.txt`). Shipped in the server tarball already: systemtags,
admin_audit, password_policy, bruteforcesettings, files_downloadlimit, workflowengine. Plus the spike's own
`chp_foldertag` (Step 7).

**The spike RPM** `nextcloud-chp-35.0.3-0.spike4.el9.noarch` (`nextcloud.spec`, 33,895 files, 250 MB,
sha256 `84ed0ee0…a7b6986`): **unsigned. Trust decision recorded: installed with `dnf --nogpgcheck` on the server
(`localpkg_gpgcheck = 1` refuses it otherwise); fapolicyd then trusts its files through the rpm database like any
installed package.** Plan 2 signs it into the repo.

- **Build host: the Mac (Homebrew rpm 6.1, `_rpmformat 4`), not aero.** aero runs fapolicyd, which denies any process
  reading untrusted PHP/JS (`70-trusted-lang.rules`), so `rpmbuild`'s `%install` copy failed there. I tried to add a
  temporary aero fapolicyd rule for the build directory; **the permission system refused it** (it would weaken the
  hypervisor's control) and I did not work around it. **Plan 2 needs a decision:** a fapolicyd rule on aero
  limited to the build directory (owner approval), a small build VM, or the Mac. EL9's rpm 4.16 installs the
  Mac-built v4 package without complaint.
- **Code under `/usr/lib/nextcloud`, not `/usr/share`.** fapolicyd's `fapolicyd-filter.conf` drops `/usr/share/` from the
  trust database except `*.php`, `*.js`…, so `occ` (no extension) and every `*.mjs` would be untrusted: `occ` failed
  with "Operation not permitted" (spike2, `logs/11`). Under `/usr/lib` every file is in the trust database except types
  the filter drops everywhere (json, html, png, md: 5,348 files, none a language type).
- Config in `/etc/nextcloud` (`apache`, `httpd_sys_rw_content_t`), symlinked from the code tree; data on
  `/data/nextcloud/data` (the 0.6.0 `/data` LV, `rw,nosuid,nodev`); logs in `/var/log/nextcloud`.

## Under the CUI profile (Step 3): every denial and its fix

| # | What failed | Cause | Minimal fix |
|---|---|---|---|
| 1 | `occ` "Could not open input file" | fapolicyd trust filter drops `/usr/share` | code tree moved to `/usr/lib/nextcloud` (package) |
| 2 | install: "Can't write into config directory" (EPERM on `config.php`) | `config.php` is PHP that NextCloud writes itself: untrusted | **trust entry** `fapolicyd-cli --file add /etc/nextcloud/config.php --trust-file nextcloud` (path trust; CHP uses `integrity = none`, so later rewrites stay trusted) |
| 3 | `password_hash` "Password hashing failed" | **FIPS: PHP's Argon2id does not work** | `hashing_default_password = true` (bcrypt) for the one local account (break-glass admin); people have no NextCloud password |
| 4 | httpd would not start | mod_ssl's `Listen 443` collides with Kanidm on `SERVER_IP:443` | httpd listens on 8443 only |
| 5 | NextCloud could not reach Kanidm (curl error 7; `strace`: `connect() = -EACCES`, **no AVC even with dontaudit off**) | SELinux: `httpd_t` may not connect to `http_port_t` | **boolean `httpd_can_network_relay = on`** (http ports only; not `httpd_can_network_connect`); the egress rule limits where to |
| 6 | downloads of users' `.py`/`.php` files: HTTP 503 (once filesystem marks were on) | fapolicyd: a stored script is "untrusted language" even when only read | **rule** `rules.d/65-chp-nextcloud.rules`: `allow perm=open exe=/usr/sbin/php-fpm : dir=/data/nextcloud/data/ ftype=%languages` (+ `/usr/bin/php`, and `rsync`/`sha256sum` for the backup); open only, never execute; other programs stay denied (`logs/32`) |
| 7 | `firewall-cmd` rule let in only `192.168.100.0` | my mistake: `chp-site get SUBNET` is the network address; the CIDR is `chp-site get SUBNET_CIDR` (`192.168.100.0/24`, `logs/40`) | the spike reads `SUBNET` from `site.conf` (Plan 2: use `SUBNET_CIDR`; a `SUBNET_CIDR` key or fix `get`) |
| 8 | the audit log stayed empty | admin_audit writes at level 1; `loglevel = 2` drops it | `log.condition = {apps: [admin_audit]}` |

**At the end: 0 left.** After the final reboot, a full run (four OIDC sign-ins with the Files page and its 57 scripts
and styles, uploads, tags, shares, visibility, a backup, the tag check) gave **"Denied accesses: 0" of 63,621, and 0 AVC
records since boot** (`logs/35`), with filesystem marks on. The only denials seen during the work were the cases in
the table and the deliberate negatives.

**HTTPS:** `files.docs.lab.test` added to the site zone (`files IN A SERVER_IP`, serial bumped, `rndc reload`); the
certificate comes from the site's step-ca over ACME exactly as Kanidm's does (`step-cli ca certificate … --provisioner
acme --kty EC --crv P-384`, port 80 opened only for the challenge): `CN=files.docs.lab.test`, issuer
`docs.lab.test CA Intermediate CA`, 24 h. Renewal: not yet automated in the spike. ACME (http-01) needs port 80
opened for each issue, as `cert-renew-kanidm` does (`step ca renew` while still valid needs no port); Plan 2 needs a
timer like Kanidm's, with `systemctl reload httpd`. **firewalld:** `rule family=ipv4 source address=192.168.100.0/24 port port=8443
protocol=tcp accept` (LAN only); reached from aero (192.168.100.1): 200 (`logs/12`).

**Port choice for Plan 2 (Kanidm has `SERVER_IP:443`):** (a) keep NextCloud on 8443 (no change to anything existing;
users type `:8443`; the spike's choice); (b) a second server address for `files.` (hosts table gains an optional
field); (c) an SNI router in front of both (changes the identity server's front door). Recommendation: (a).

## No internet (Step 4) — §Outbound

**Settings:** `has_internet_connection = false`, `appstoreenabled = false`, `updatechecker = false`,
`upgrade.disable-web = true`, `lookup_server = ''`, `gs.enabled = false`, `reference_opengraph = false`,
`knowledgebaseenabled = false`, `check_for_working_wellknown_setup = false`, `enable_previews = false`; apps off:
`text office firstrunwizard recommendations survey_client nextcloud_announcements updatenotification federation
sharebymail weather_status support app_api webhook_listeners files_external contactsinteraction dashboard circles
photos related_resources user_status files_reminders privacy suspicious_login`; outgoing/incoming federation and
lookup-server sharing off (`files_sharing` app config). `federatedfilesharing`, `lookup_server_connector` and
`cloud_federation_api` cannot be disabled (core); their settings are off.

**Below the application:** an nftables table of its own, `inet chp_nextcloud_egress` (`pkg/nextcloud-egress.nft`,
loaded by `chp-nextcloud-egress.service` before php-fpm/httpd; survives `firewall-cmd --reload`): packets whose socket
belongs to `apache` (php-fpm workers, cron, occ) may go only to loopback and the server's own address; anything else is
**logged (`CHP-NC-EGRESS`, with UID) and rejected**. SELinux: `httpd_can_network_connect` stays **off**; only
`httpd_can_network_relay` is on (fix 5). In the lab only (not product properties): the bridge has no route out (aero
`ip_forward = 0`) and the site DNS has no forwarders (`recursion no`; `apps.nextcloud.com`: no answer).

**Proof (`logs/21`):** a probe OIDC provider whose discovery URL is an internet address (93.184.215.14) made NextCloud's
own HTTP client in **php-fpm (`httpd_t`)** connect when the login route was requested: NextCloud logged "cURL error 7:
Failed to connect to 93.184.215.14 port 443: Connection refused" and the kernel logged
`CHP-NC-EGRESS … DST=93.184.215.14 … DPT=443 … UID=48 GID=48`; the rule's counter rose. The same from the apache user
outside the web server (curl to 1.1.1.1:443, a TCP connect to 8.8.8.8:53): refused and logged. The probe provider was
deleted. **A bug found and fixed:** the first rule (`meta skuid != apache accept`) does not match packets that have no
socket, so the kernel's own IGMP/MLD reports were refused after the reboot; the rule now jumps on a positive
`meta skuid "apache"` match.

**Limits of the egress rule, and Plan 2 prototypes (`logs/40`):**

- **Any service on the server's own address is allowed.** The local resolver is the main one: at a site with
  `DNS_FORWARDERS` set, named recurses (`recursion yes; forward only`, `render.py` 78-80), so DNS queries from NextCloud
  could tunnel data out; any local relay or proxy on the server would do the same. **Prototype:** the apache user gets
  no DNS at all (`pkg/nextcloud-egress-nodns.nft`: port 53 logged as `CHP-NC-EGRESS-DNS` and refused) and NextCloud's own
  names (`idm.`, `files.`) come from `/etc/hosts`. Result: `dig @SERVER_IP example.com` as apache times out and is
  logged, and the Kanidm sign-in still works. That is the variant loaded on iso5-docs now. Proposal for Plan 2: ship
  that (hosts entries rendered from the site), or accept the resolver as a channel and document it.
- **If the table fails to load, NextCloud ran unblocked**: the unit was only `Before=` php-fpm/httpd. **Prototype**
  (`pkg/nextcloud-bindsto.conf`, a drop-in for php-fpm and httpd: `BindsTo=` + `After=` the egress unit, and
  `ExecStartPre=nft list table inet chp_nextcloud_egress`): with the table file missing, the egress unit fails and php-fpm
  and httpd stop and will not start ("A dependency job … failed"); with the table deleted at run time, the next php-fpm
  start fails on the pre-check. **Gap left:** deleting the table while php-fpm runs is not noticed until a restart; Plan 2
  needs a monitor check (table present, its rules intact).

**Admin overview (`occ setupchecks`, `logs/36`), every warning explained:** "Errors in the log: 9" = the deliberate
outbound probe and the two attempts before fix 5, plus background jobs of apps switched off; "Mimetype migrations" (a
maintenance command); "App directories owner" (by design: the code tree is root-owned and read-only); "PHP 8.3 is
deprecated" (finding 4); "imagick", "2FA not enforced" (sign-in is Kanidm's TOTP), "server ID", "remote address" (the
command line has none), "memcache for locking". **No outbound-attempt error is left unexplained.**

## Sign-in through Kanidm (Step 5)

Protocol: **OIDC** (user_oidc 8.13.0; Kanidm signs id tokens with **ES256**, user_oidc verifies it; **PKCE S256** on).
The exact Kanidm commands (as `idm_admin`; `logs/14`, `logs/15`, `kanidm.sh`):

```
kanidm group create cui-users ; kanidm group create doc-reviewers
kanidm person create lab01 "Docs Lab 01" ; kanidm group add-members chp_users lab01 ; kanidm group add-members cui-users lab01
kanidm person posix set lab01                      # lab01 only: host sign-in for row 36
kanidm person credential create-reset-token lab01  # then: kanidm person credential use-reset-token <t>
                                                   #   password -> totp (label, code) -> [unix-password] -> commit
kanidm system oauth2 create nextcloud "NextCloud" https://files.docs.lab.test:8443
kanidm system oauth2 add-redirect-url nextcloud https://files.docs.lab.test:8443/index.php/apps/user_oidc/code
kanidm system oauth2 update-scope-map nextcloud chp_users openid profile email groups
kanidm system oauth2 prefer-short-username nextcloud
kanidm system oauth2 update-claim-map nextcloud chp_groups cui-users cui-users
kanidm system oauth2 update-claim-map nextcloud chp_groups doc-reviewers doc-reviewers
kanidm system oauth2 update-claim-map nextcloud chp_groups chp_users chp-users
kanidm system oauth2 update-claim-map-join nextcloud chp_groups array
kanidm system oauth2 show-basic-secret nextcloud   # -> /etc/nextcloud/oidc-secret (0640 root:apache), never printed
```

NextCloud side (`setup.sh oidc`): `occ user_oidc:provider kanidm --clientid=nextcloud --clientsecret-file=…
--discoveryuri=https://idm.docs.lab.test/oauth2/openid/nextcloud/.well-known/openid-configuration --mapping-uid=preferred_username
--unique-uid=0 --mapping-groups=chp_groups --group-provisioning=1 --group-whitelist-regex='^(cui-users|doc-reviewers|chp-users)$'`;
`allow_multiple_user_backends = 0` (the login page goes straight to Kanidm; the break-glass admin uses `/login?direct=1`);
`occ security:certificates:import` of the site root (NextCloud has its own CA bundle); `allow_local_remote_servers =
true` (Kanidm is a LAN address; the egress rule is what limits destinations).

**Claims** (lab04, an id token from an identical throwaway client `claimprobe`, deleted afterwards; `logs/18`):
`iss https://idm.docs.lab.test/oauth2/openid/<client>`, `sub` (UUID), `preferred_username lab04`, `name "Docs Lab 04"`,
`chp_groups ["cui-users", "doc-reviewers"]`, `groups` (every group as UUID and `name@idm.docs.lab.test`, including
Kanidm's built-ins: hence the separate `chp_groups` claim), `scopes`, `auth_time`, `exp` (15 min), alg ES256. No email
claim (the lab people have none).

**Sign-in (`oidc_login.py`, a scripted browser through SSH tunnels: the same redirects and HTML forms):** NextCloud
-> Kanidm `/ui/oauth2` -> `/ui/login/begin` (user name) -> `/ui/login/totp` (code) -> `/ui/login/pw` (password) ->
consent -> NextCloud. `SIGNED IN: id=lab01 … groups=['cui-users'] backend=user_oidc` (`logs/17`); lab02/03/04 the same
with their groups (`logs/19`, `logs/23`). A wrong TOTP was refused ("Login Failed Reason: incorrect totp"; it happened
by accident: the lab clocks differ by about 8 s, so the script now takes the time from Kanidm's `Date` header).

**Host sign-in unchanged: row 36 3/3 on iso5-dcli** (`chp-site pam-test gdm-password lab01`, POSIX password + the host's
GA code; `PAM_OK` x3; token label `var_auth_t`; `logs/20`). Honest account: my first three runs sent no code (a script
bug), pam_faillock locked lab01 (`deny = 3`, `unlock_time = 0`, the CUI setting, correct), the lock made the next runs
fail even when GA and Kanidm accepted, an admin `faillock --reset` cleared it, then 3/3. The Kanidm web credential
(password + TOTP) and the host credential (POSIX password + host GA token) are separate, as the owner decided.

## Folders and sharing (Step 6)

All by `occ` (`folders.sh`; no web UI, no app password needed for any setting):

| Setting | Route |
|---|---|
| team folders | `occ groupfolders:create CUI` (… FCI, Archive, Operations, Internal, Public; ids 1-6, each its own storage) |
| access | `occ groupfolders:group <id> cui-users read write delete` (**no `share`**) for CUI/FCI/Archive; `… chp-users read write delete share` for the other three |
| advanced permissions | `occ groupfolders:permissions <id> --enable` |
| reviewer layer | `occ groupfolders:permissions <id> --group doc-reviewers -- / +read -write -create -delete -share` (all six) |
| sharing policy | `occ config:app:set core shareapi_allow_resharing no`, `shareapi_enforce_links_password yes`, `shareapi_enforce_expire_date yes` (7 d), `shareapi_allow_public_upload no` |
| group sync | Kanidm claim map (above) + user_oidc `--group-provisioning=1`; `occ group:add chp-users` first so folders can name it |

**Proofs (`proofs.py share|see`, `logs/25`, re-run after the restore and after the reboot):**

- internal share of a CUI file to lab02 (not `cui-users`): **refused** (HTTP 403 "You are not allowed to share …");
  even to lab04 (in `cui-users`): refused; the CUI folder itself: refused
- public link on a CUI file: **refused**; on an FCI file: refused
- control: an Operations file shared to lab02: allowed
- lab03 (`doc-reviewers`, not `cui-users`): sees Internal, Operations, Public only; GET of the CUI file by path: 404;
  reads Operations; cannot write there
- lab04 (`doc-reviewers` + `cui-users`): sees CUI, **reads** the CUI file, **cannot** change it, add to CUI or delete
  (403 each); the file is unchanged afterwards

These folder proofs authenticate with each user's **app password (HTTP Basic)**, not an OIDC browser session; the
server-side permission, ACL and share checks are the same for both (the sign-in itself is proved separately).

Note for Plan 2: an ACL rule overrides the group's folder permissions for a user in both groups (lab04), which is
exactly the owner's reviewer rule. **As built, reviewers lose write, create, delete and share on ALL six folders**,
including Operations, Internal and Public; the owner should confirm that is meant (the design says "a read-only layer"). Download limits (`files_downloadlimit`) are on but only apply to share links, and
CUI/FCI have none.

## Tag by folder (Step 7)

**Mechanism: the spike app `chp_foldertag`** (`chp_foldertag/`, ~100 lines, in the RPM): it listens to NodeCreated /
NodeWritten / NodeCopied / NodeRenamed, and a file whose mount is a team folder named in its rules
(`occ config:app:set chp_foldertag rules --value='{"1":"1","2":"2"}'`, team folder id -> system tag id) gets that
tag through `ISystemTagObjectMapper`. Tags `CUI` and `FCI` are **restricted** (`occ tag:add CUI restricted`): visible,
only admins can assign or remove. Why not a flow rule: workflowengine has no folder/path check (checks are file
name, MIME type, size, tags, request, group), and flow rules cannot be scripted with an app password (the diwai lesson).

**Proofs (`logs/24`, `logs/26`, `logs/35`):** WebDAV PUT into CUI -> `['CUI']`; **browser-style chunked upload** (the web
UI's chunking v2: MKCOL `uploads/…`, chunk PUTs, MOVE `.file`; 40 KB and 7 MB files) into CUI -> `['CUI']`, into FCI
-> `['FCI']`; Operations -> no tag; lab01 cannot remove the tag (DELETE `systemtags-relations` -> 403). The browser
path was scripted, not clicked: the same requests the Files app sends.

**Cannot be switched off silently:** `occ app:disable chp_foldertag` is in the audit log (`App "chp_foldertag"
disabled`) and raises a **level 12** Wazuh alert (rule 100603). **The nightly check** `occ chp:foldertag:check` lists
every file in a ruled folder without its tag (exit 1): it caught a file put straight onto the disk + `groupfolders:scan`
(no upload event) and a file uploaded while the app was off. **Finding: the check must not live in the app it checks**
— with the app disabled its command disappears too ("no commands defined"; it still exits 1, so a timer would notice,
but Plan 2 should run the check from chp-base/chp-site with SQL: team folder storages are `oc_group_folders.storage_id`,
files under `files/`).

## Copy out of CUI (review item, `logs/41`)

**The bypass, before any control:** lab01 (`cui-users`) did a WebDAV COPY of a CUI file into Operations and into their
home, and a MOVE into Operations: all three worked (201). The copies carry **no tag**; the moved file kept its CUI tag
but nothing acts on the tag. From Operations and the home folder an internal share to lab02 **and** a public link were
both accepted (OCS 200), and lab02 read the file (200). The cleanup deleted those files.

**Prototype control: `chp_foldertag` 0.2.0 `ContainListener`** (in RPM spike5): on `BeforeNodeCopiedEvent` /
`BeforeNodeRenamedEvent`, a source in a contained team folder (`occ config:app:set chp_foldertag contain
--value='[1,2,3]'`: CUI, FCI, Archive) and a target anywhere else is aborted with `AbortedEventException` (NextCloud 35
supports this in `HookConnector`). Result after `occ upgrade` (the first run was void: the app version bump left
NextCloud in "upgrade required" and every request got 503): COPY to Operations, MOVE to Operations, COPY to home, MOVE
CUI -> FCI: **refused (403), nothing created**; COPY inside CUI and MOVE from Operations into CUI still work and are
tagged CUI. NextCloud logs `chp_foldertag: REFUSED move out of contained team folder 1: …` (nextcloud.log, level 2;
Plan 2 should send it to the audit trail and Wazuh).

**What it does not stop:** a member **downloads** the CUI file and **uploads** the bytes to Operations, then shares it
(proved: 200, 201, link OCS 200). Copy-and-paste of content, a sync client (not shipped) and screenshots are the same
class. Nothing in NextCloud can tell where uploaded bytes came from; only a content check (the CUI banner/marking
check from §5 of the design, run on uploads outside CUI/FCI) or not giving `cui-users` share rights elsewhere would
narrow it. **That is an owner decision.** A files_accesscontrol rule by tag was not built: a copy has no tag, so it
would only cover moves, which the listener already refuses.

## Audit to Wazuh (Step 8)

`/var/log/nextcloud/audit.log` (admin_audit, JSON) read by the server's Wazuh (the manager reads its own files;
`wazuh/localfile.xml`); Wazuh's built-in JSON decoder; rules `wazuh/chp_nextcloud_rules.xml` (ids 100600-100605):
100601 **level 12** share refused, 100603 level 12 a control app disabled, 100605 level 7 failed sign-in, 100604 level 7
deletion. **NextCloud 35 audits refused shares itself**: `Interaction OCP\Interaction\Actions\ShareAction from user lab01
on 70 to lab02 is restricted: Node is not shareable.` Arrived at the manager (`alerts.json`, `logs/27`): five
share refusals at level 12, the app-disabled line at level 12, the failed sign-in at level 7. Two Wazuh details: the
regexes need `type="pcre2"` (OS_Regex has no grouped alternation; a bad rule stops the manager: it was down for 20 s),
and a `Login failed` line is taken first by Wazuh's generic rule 2501, so 100605 hangs off 2501. Sample lines (no
secrets): `wazuh/sample-audit-lines.json`. Failed **Kanidm** sign-ins (wrong TOTP) are in kanidmd's journal, which Wazuh
already reads; a rule for them is Plan 2.

## Browser editors off (Step 9)

`text` and `office` disabled; `richdocuments`/ONLYOFFICE not installed; no editor capability advertised; `viewer` and
`files_pdfviewer` on. docx, xlsx, md, PDF uploaded and downloaded byte-for-byte (Operations by lab02, CUI by lab04)
(`logs/29`). With `text` off a Markdown file has no in-browser viewer: download only. Users' script files (.py, .php,
.js, .sh) download after fix 6 (`logs/30`, `logs/32`).

## Backup and restore (Step 10)

`pkg/chp-nextcloud-backup` (+ `.service`, `.timer` nightly 01:40): maintenance mode on, `pg_dump -Fc` (peer auth),
`rsync -aHAX` of the data and `/etc/nextcloud` into `/backup/nextcloud/<UTC stamp>/` (0700), maintenance off, a sha256
MANIFEST, 14 copies kept. 0 fapolicyd denials during it (fix 6 covers rsync), 0 AVCs. **Restore onto a reset server:**
the NextCloud state was destroyed (services stopped, database dropped, `/data/nextcloud`, `config.php` and the OIDC
secret deleted: `status.php` said `installed:false`), then `chp-nextcloud-backup restore <dir>` (MANIFEST checked first)
-> installed, 6 team folders, tag check consistent, `tags` and `see` proofs ALL PASS, lab04 signs in through Kanidm
(`logs/34`). One bug fixed on the way: `pg_restore` as postgres could not read the root-only dump; it now reads stdin.
"Reset" here = the NextCloud state wiped on the same server, not a reinstall from the ISO. The backup holds
`config.php` (instance secret, password salt) and the OIDC client secret: `/backup` must stay encrypted when it leaves
the server (the 0.6.0 backup-drive runbook does that).

**Reboot (`logs/35`):** TPM unlock, every unit active (httpd, php-fpm, postgresql, the egress table, the cron and backup
timers, wazuh-manager, kanidmd, fapolicyd), 0 failed units, 0 denials, 0 AVCs.

## Resource use (`logs/37`)

At rest after the proofs, 8 GiB VM: used 1.7 GiB. Service memory: wazuh-manager 1,281 MB, suricata 539, php-fpm 123,
kanidmd 76, httpd 60, postgresql 39. Disk: code 874 MB (`/usr/lib/nextcloud`), database 74 MB, data 7 MB, backups 15 MB
for three copies. **4 GiB (the install default) is too small for the server with SECURITY_ADDONS and NextCloud; Plan 2
should say 8 GiB.**

## Transport (Task 2): how `chp-site doc` signs in and finds a stale copy

Task 2 of Plan 1, run on 2026-11-13 (UTC) on the same two VMs; raw output in `logs/43-65`, prototypes in `proto/`
(stdlib-only Python 3.9 on the workstation, like chp-site). The workstation scripts travel to iso5-dcli as a `-c`
argument (`proto/on-dcli.sh`) because fapolicyd there refuses `python3` opening an untrusted `.py` in a home
directory. The product ships chp-site as a trusted RPM file, so this only affects the spike. The browser step is
scripted (`--scripted-browser`, the same forms as `oidc_login.py`). **A real Firefox click-through on the
workstation was not done.**

### Sign-in: three routes

| Route | What the workstation keeps | How long it is valid | After a Kanidm lock | Logs |
|---|---|---|---|---|
| **1. Kanidm public client `chp-doc`**: authorization code + PKCE S256, redirect to a one-shot listener on `127.0.0.1`; the access token is sent to NextCloud as `Authorization: Bearer` | access token (JWT `at+jwt`, ES256, 722 chars) + refresh token in `$XDG_RUNTIME_DIR/chp-doc/session.json` (tmpfs, 0600). Nothing in the home (a grep of `/home` found none) | access token 900 s; refresh token: the client is set to 8 h (`set-refresh-token-expiry chp-doc 28800`), but **that limit is untested** (computed client-side, fix 6); it is replaced on every refresh (`logs/68`). The file goes when the user's last session ends: logind removed `/run/user/1000` and the token with it | **next call 401; refresh `invalid_grant`** | 44, 45, 47, 48 |
| **2. NextCloud Login Flow v2** (`POST /index.php/login/v2`, browser signs in through Kanidm and grants, CLI polls) | a 72-char **app password**: 0600 file in `~/.config/chp-doc/` (on the LUKS home) or tmpfs | **no expiry at the server** (`user:auth-tokens:list`: type 1 = permanent, `expires: None`; nothing in config expires it) until it is revoked | **still 200**: NextCloud checks an app password itself and never asks Kanidm | 46, 47, 48 |
| 3. OIDC device flow (RFC 8628) | – | **not offered by Kanidm 1.11.2**: no `device_authorization_endpoint` in discovery, `POST /oauth2/device` 404 | – | 43 |

Both working routes sign out cleanly. Route 1 revokes at Kanidm (`/oauth2/token/revoke`, 200), route 2 calls
`DELETE /ocs/v2.php/core/apppassword` (200), and the old credential then gets 401 (`logs/48`, `logs/64`). An app
password that is never signed out stays valid. A first Flow v2 run left one behind (id 30), and only an admin
`occ user:auth-tokens:delete` removed it (`logs/48`).

**Recommendation: route 1 (Kanidm public client + Bearer).** Nothing long-lived sits on the workstation: 15 min, and a refresh token set to 8 h (untested, fix 6), in RAM, and
gone at logout. A lock or removal in Kanidm takes effect on the next request, because
NextCloud asks Kanidm about the token on every call. The identity is the same Kanidm person NextCloud already uses,
and the ledger can record that person's Kanidm `sub`, `session_id` and `auth_time` (§Ledger). Route 2 is rejected:
its app password is a permanent bearer secret, and it keeps working for a person locked out in Kanidm (`logs/47`).
That is an offboarding gap. Keeping the app password in tmpfs and adding an expiry job would narrow the gap but not
close it.

**What route 1 costs (all shown):**

- **Kanidm:** one public client `chp-doc` (`create-public`, `enable-localhost-redirects`, the same scope map and
  `chp_groups` claim maps as `nextcloud`, refresh expiry), rendered by chp-site on the server (`proto/auth-setup.sh
  kanidm`, `logs/44`).
- **NextCloud:** a second user_oidc provider `kanidm-cli` (`--check-bearer=1 --bearer-provisioning=0`) and
  `user_oidc.userinfo_bearer_validation = true`, `selfencoded_bearer_validation = false`. Why: Kanidm's access token
  carries `sub` (a UUID) but **no `preferred_username`**, so NextCloud's self-encoded check found no user ("Could
  not find unique token validation", `logs/45`). With the userinfo check, every API call costs a call to Kanidm:
  **PROPFIND median 191 ms with the Bearer vs 92 ms with an app password** (`logs/63`). A doc command makes a handful
  of calls, so the cost is small. Kanidm ties userinfo to the client that issued the token: a `chp-doc` token is
  refused at the `nextcloud` client's userinfo (400 `invalid_request`, `logs/65`), so one client's token cannot be
  used as the other's. WebDAV accepts the Bearer too (`logs/53`).
- **The second provider breaks the straight-to-Kanidm login page.** user_oidc redirects `/index.php/login` only
  when exactly one provider exists (`Application.php` `registerRedirect`). With two, the page shows two buttons
  (`logs/62`). Fix, prototyped: five `RewriteRule` lines in the NextCloud vhost (`proto/nextcloud-login-rewrite.conf`)
  send `/index.php/login` to provider 1 and keep `redirect_url` (Login Flow v2's grant page needs it) and
  `?direct=1` (break-glass). Shown working for the plain page, for `redirect_url`, and for the whole Flow v2 hop chain
  up to Kanidm (`logs/62`). The `?direct=1` page still lists the useless "kanidm-cli" button (cosmetic).
- **A loopback listener during sign-in.** This is not a network port: it binds `127.0.0.1` only, answers one
  request and closes (`ss` shows nothing afterwards). The workstation listens only on 22 and 631 (`logs/45`,
  `logs/61`). Kanidm accepts **any** loopback port for this client even with strict redirects on (`logs/49`), so
  Plan 2 can bind port 0. A local process that took the port first would get only a code it cannot redeem without
  the PKCE verifier.
- **A browser on the workstation** (Firefox 140 is installed) and a Kanidm password + TOTP sign-in at most once
  per 8 h, or once per GNOME login. **Untested:** whether an existing Kanidm browser session skips the prompts (the
  scripted browser starts with no cookies; consent was remembered on the second sign-in, `logs/45`). Also untested:
  `chp-site doc` run from a session with no runtime dir (cron, `su`).
- Notes for Plan 2, not tested here. user_oidc's Bearer path sets `last-password-confirm` 4 years ahead, so
  password re-confirmation never applies. With the default `auto_provision`, a Bearer for a Kanidm person who never
  used the web UI creates their NextCloud account; they would have no groups, so no CUI access.

### Freshness marker: the ETag alone is not enough

`proto/freshness.py` (`logs/50`) recorded the WebDAV marker (`getetag`, `oc:fileid`, size, versions) of one
controlled file in `CUI/Compliance/` after each event:

| ETag unchanged (correct) | ETag changed |
|---|---|
| GET by the author or a reviewer; PROPFIND; a refused reviewer PUT (403); favourite; comment; rename away and back; admin `groupfolders:scan`; background jobs; a share (Operations file) | every author PUT, **even of the same bytes**; PUT with the current `If-Match`; a version restore; mtime changed on the disk + rescan. **Also, wrongly: WebDAV LOCK and UNLOCK** (files_lock app), with the content unchanged |

`fileid` never changed (rename, restore and overwrite all kept it). **Three defects make the ETag unsafe as the
proof:**

1. **Different content, same ETag.** NextCloud's local-storage ETag is `md5(mtime_seconds . inode . dev . size)`
   (`lib/private/Files/Storage/Local.php` `calculateEtag`, quoted in `logs/51`), and the inode stays the same from
   one write to the next (`logs/51`). Two writes in the same second kept the ETag **4 times in 10** with the same
   size (`logs/52`, case E). Once in `logs/50` a new-content PUT left it unchanged. In `logs/51` case C it stayed
   the same **twice with a different size**. That is observed and **not explained**, since size is part of the hash.
   **10 in 10** when the second PUT sent `X-OC-Mtime` equal to the first one's mtime, even 2 s later (`logs/51`,
   `logs/52` case D). Any NextCloud client may send that header.
2. **An old ETag comes back.** Restoring a version brought back an ETag the file had had before (`6af6604cc5ba8`,
   `logs/50`). A checkout made at that ETag would look fresh again after intermediate publications.
3. **A change on the disk behind NextCloud** that keeps size and mtime is invisible even after a rescan
   (`logs/50`). That is expected, and only a content hash catches it.

`If-Match` works: a stale value gets **412** and the current one 204 (`logs/50`).

**Prototype (`proto/doc_fresh.py`, `logs/53`, on iso5-dcli over route 1):** `checkout` writes the working copy to
`~/chp-docs-work/` and records `{fileid, etag, sha256, user, time}` beside it. `publish` downloads the canonical
copy and refuses unless fileid, ETag **and** sha256 all still match, then PUTs with `If-Match: <checkout etag>`.
Shown: a fresh copy publishes. A colleague's same-size update with `X-OC-Mtime` kept the ETag; an ETag-only check
**would have published over it**, and the hash check refused. An ordinary update by someone else is refused. The
real publish moved the ETag, so the old checkout record is then refused too.

**Recommendation: the freshness marker is the sha256 of the canonical bytes (with the fileid), recorded at checkout
and compared at publish.** The ETag is used only as a cheap first look and as the `If-Match` on the final write. If-Match compares the same
unreliable ETag, so it only **narrows** the gap between check and write (fix 2). The real close is a **server-side**
compare-and-write by content hash (fix 1). With the central ledger (§Ledger), Plan 2 should also refuse when
the ledger holds a publication of that fileid after the checkout entry. Ledger sequence numbers only grow, so this
closes defect 2 without trusting NextCloud. **Cost:** one extra GET of the canonical copy at publish (controlled
documents are small), a checkout record beside the working copy, and a hash. A LOCK by anyone makes the copy look
stale (a false refusal, the safe direction): `doc check` should say so plainly.

## Ledger (Task 2): where the approval ledger lives

Two places were prototyped. Both use the same root-owned appender `proto/docs_ledger.py`: stdlib Python 3.9 on the
server, modelled on `chp_site/review_ledger.py`. It writes one JSON line per entry, each with the SHA-256 of the
previous line, under `flock`, with a `ledger.head` witness, `export` of the ledger + `heads.txt` to the stick, and
`verify-heads` against the stick. It applies design §4's rules: the approver is a listed approver and never the
author (the user of the latest checkout); the ISSO override needs a reason and a one-person site; publish needs an
approval of that exact sha256 since the checkout, by someone else. The ledger is
`/var/lib/chp-docs/ledger/ledger.jsonl` (root, 0600, directory 0700). Install: `proto/ledger-setup.sh` (`logs/54`).

- **L1, through NextCloud's own HTTPS:** a small NextCloud app `chp_ledger` (`proto/chp_ledger/`, one OCS
  controller). `POST /ocs/v2.php/apps/chp_ledger/api/v1/request` stamps the request with the user NextCloud
  authenticated (`IUserSession`, never a name in the request), the kind of authentication (bearer / app password /
  session) and, for a Bearer, the token's Kanidm `sub`, `session_id`, `auth_time`. **0.1.0 took those claims unverified; that was forgeable
  (`logs/66`), and fix 3 replaces it with a check at Kanidm.** It checks that this user can see
  the file id, then drops the request in `/var/lib/chp-docs/spool` (`root:apache 1730`, `httpd_sys_rw_content_t`).
  `chp-docs-ledger.path` starts the root appender, which writes a result to `out/` (`httpd_sys_content_t`, read-only
  to the web server), and the CLI polls `GET …/result/<id>`.
- **L2, a restricted NextCloud folder:** a team folder `Approvals` (read + create; no write, delete or share,
  through an ACL, because team folders have no "create" permission, `logs/54`). The CLI uploads a request file there.
  A root job takes the uploader from NextCloud's `admin_audit` log (`File with id "N" created:
  "/<user>/files/Approvals/<name>"`), never from the file, appends, and deletes the request.

| Proof | L1 (OCS app) | L2 (drop folder) |
|---|---|---|
| author approves own document | refused: "is the author" (`logs/57` 2) | refused (`logs/59` 6) |
| author claims to be the approver (`user=lab04` in the request / in the file) | ignored; recorded and refused as lab01 (`logs/57` 3) | ignored; refused as lab01 (`logs/59` 2, 6) |
| a different signed-in approver | appended, with Kanidm sub (`logs/57` 7) | appended; identity from the audit log, no Kanidm session (`logs/59` 6) |
| ISSO override with other approvers present; non-ISSO override | both refused (`logs/57` 8, 4) | (same rules) |
| publish without approval / of a different hash / of the approved hash | refused / refused / appended (`logs/57` 5, 9, 10) | (same rules) |
| people outside `cui-users` (lab02, reviewer lab03) | 404: they cannot reference the CUI file (`logs/57` 6) | not shown |
| no credentials | 401 (`logs/57` 11) | (no upload without sign-in) |
| a request written on the server's disk, not uploaded | (cannot reach the spool: apache-only) | refused: no audit record (`logs/59` 5-6) |
| another user changes or deletes a waiting request | spool not listable by apache, not reachable by users | 403 / 403 (`logs/59` 3) |
| users see others' waiting requests | no | **yes** (2 visible, `logs/59` 4) |
| answer to the user | synchronous, 0.1-0.3 s (`logs/57`) | **none**: a refused request vanishes unseen (`logs/58` note) |
| app password instead of Bearer | accepted, and the entry records `auth=app-password` (`logs/57` 12). **Since fix 3, approve and override are refused without a verified Bearer** (`logs/72` G) | can't tell (the audit line doesn't say) |
| new network port | none (8443, `logs/61`) | none |

**Common to both:**

- The web server's user cannot read or append to the ledger, list the spool or write a result (`logs/60`).
- A cut-off entry is caught by the head witness. A cut plus a rewritten witness (root on the server) is caught only
  by the heads on the stick. An approver's name changed in place breaks the chain. All of this was shown on a copy;
  the real ledger still verifies, and so do its heads on the stick (`logs/60`).
- **Residual risk (both routes):** whoever controls the NextCloud PHP process can submit requests as anyone,
  because NextCloud is the authenticator in both. The ledger detects later tampering. It cannot prevent forged
  entries from a NextCloud that is already compromised.

**Recommendation: L1.** It records the identity NextCloud authenticated for that very request, and with route 1
that is a live Kanidm session (sub, session id, auth time). It answers at once, needs no new port, and its spool and
ledger are out of every user's reach. The same app is where Plan 2 can move `publish` itself: a server-side
compare-and-write of the Compliance area that a modified client cannot skip. L2 works, but each defect it showed
counts against it: identity rests on matching log lines (fragile: the prototype's first match missed escaped quotes,
`logs/58`) and on `admin_audit` staying on; requests are visible to every user; there is no answer channel; and it
cannot see the Kanidm session.

**What L1 costs:**

- A second custom NextCloud app (about 100 lines of PHP, kept current with NextCloud like `chp_foldertag`). It goes
  in the RPM, because fapolicyd needs it trusted (the spike used `fapolicyd-cli --file add … --trust-file
  chp-spike`, `logs/54`).
- `/var/lib/chp-docs` with two SELinux file contexts, a `.path` + `.service` pair, and `docs_ledger.py` in chp-site.
- The stick export joins the existing export.
- Two defects to carry into Plan 2:
  - **Six requests in ten seconds tripped systemd's start limit** and stopped the appender for good
    (`unit-start-limit-hit`, `logs/56`): any user could have switched approvals off for the site. Fixed with
    `StartLimitIntervalSec=0` and `TriggerLimitIntervalSec=0` (`logs/57`), **superseded by fix 5** (finite limits +
    quarantine + alert): unlimited restarts let a bad request loop forever as root. Plan 2 should add a per-user rate limit in
    the app and a monitor check that the path unit is active.
  - **FIPS refuses `hashlib.md5`** (`logs/58`): use SHA-256 for every id.
- One rule to settle (**settled by fix 4**): "author = the user of the latest checkout" let a reviewer's own checkout (lab04, `logs/57`
  entry 8) make them the author. Plan 2 must define the author per change cycle (for example the publisher and the
  checkout user of that cycle).

### Review fixes (2026-11-13; `logs/66-73`)

**1. The prototype's gate does not control the write (residual, IMPORTANT).** In the prototype, `publish` is a
WebDAV PUT by the author, and the ledger's publish entry trusts the sha256 the client sends. Anyone with write
access to the Compliance area (curl, or a modified client) can overwrite a controlled document and skip the
approval, author and freshness rules entirely; the ledger then simply lacks a publish entry. **For Plan 2 this is a
MUST: publish is server-side.**
- The Compliance areas are read-only to every user through the ACL (no write, create or delete).
- `chp_ledger` (or the root appender acting for it) receives the bytes.
- Under a lock on the target, it does an atomic compare-and-write. It checks that sha256(the bytes received) equals
  the approved entry's sha256, and that the canonical copy's current sha256 equals the checkout's. Only then does it
  write and append the publish entry, in one step.

The client-side checks in `proto/doc_fresh.py` stay as the user-facing early answer, not the control.

**2. If-Match only narrows the window.** It compares the ETag, which §Freshness shows is unreliable, so it does not
close the gap between check and write. It only makes the gap smaller. The real close is fix 1's server-side
compare-and-write by content hash.

**3. Kanidm evidence was forgeable (IMPORTANT; `logs/66`).** `chp_ledger` 0.1.0 base64-decoded the Bearer payload
without checking the signature, and set `auth` from the Authorization header's prefix. Test: lab01 signed in with a
browser (cookie session) and sent the same POST twice, once plain and once with a forged
`Authorization: Bearer <hdr>.<claims>.bad-signature` (sub `00000000-forged-sub`, session `forged-session`,
`auth_time 1`, `preferred_username lab04`).
- NextCloud authenticated **lab01 by the cookie** both times. user_oidc's Bearer check failed silently and the
  session won, so the uid was not forgeable.
- The entry recorded **`auth=bearer` with the forged sub, session and auth time** (entry 13).

Fix (`chp_ledger` 0.2.0 + `docs_ledger.py`, `logs/67`, `logs/69`):
- The app no longer reads claims. It records `bearer-claimed` and forwards the raw token in the spool request.
- The root appender asks **Kanidm's `chp-doc` userinfo** with it (stdlib `urllib`; only `chp-doc` tokens pass there,
  `logs/65`). It checks `preferred_username == the NextCloud uid` and `aud`/`azp == chp-doc`, records only what
  Kanidm returned (`sub`, `auth_time`, `verified: kanidm userinfo`), and never writes the token anywhere. (That became true only in round 2: until then, quarantine kept the original spool file and its token, `logs/75`.)
- A Bearer that does not validate makes the whole request refused.
- **approve and override require a verified Bearer.** An app password or browser session is refused (`logs/72` G).
  Route L2 approvals are refused for the same reason.

This partly mitigates the "compromised NextCloud submits as anyone" residual: a forged approval now also needs a
live Kanidm token of that person for `chp-doc`. Two costs:
- The spool briefly holds a 15-minute token. The spool is apache-written and only root reads it; apache had the
  token anyway.
- The app's version bump put NextCloud into "require upgrade" until `occ upgrade` ran (`logs/67`). Plan 2's RPM
  `%post` must run it.

**4. The author rule, per cycle (IMPORTANT; `logs/72`).** The first rule ("author = the user of the latest
checkout") let an approver who authored a change approve it after anyone else checked it out, and let any
`cui-users` member block approvals with a checkout. Adopted for Plan 2, and now in `decide()`:
- A **cycle** of a fileid runs from its last successful publish (or its creation) to now.
- **Authors(cycle)** = the creator (new action `create`) + every user who checked it out in the cycle + the
  publisher.
- An approval is refused if the approver ∈ Authors(cycle). It counts only if made **after the cycle's last
  checkout**, of that exact sha256.
- The publisher must ∈ Authors(cycle).
- Reviewers read through a plain fetch (GET), which records nothing as authorship.

Re-run on two new controlled documents in `Internal/Compliance`, as listed in `logs/72`:
- The self-approval sequence (approver lab04 checks out, lab02 checks out after, lab04 approves) is refused.
- A non-author publish is refused.
- An approval followed by another checkout no longer counts.
- The clean path (create → approve by a non-author → publish) is appended.

**5. Failure loop and ledger growth (IMPORTANT; `logs/70`).**
- With `StartLimitIntervalSec=0`, a spool file that raised would have re-triggered the path unit forever as root.
  Now every exception moves the request to `quarantine/` (0700) and, where it has an id and user, writes a refusal
  result.
- The limits are finite again: 300 per 60 s on the service and on the path trigger, with
  `OnFailure=chp-docs-ledger-alert.service` (logs at `auth.crit`, standing in for ALERT_HOOK).
- The app and the appender accept only file ids under a Compliance area, so a user cannot grow the forever-ledger
  with files from their own home.
- Shown: three bad requests quarantined, the spool emptied, the path unit active, the ledger unchanged. A
  home-folder file id gets 403 at the app.
- **Plan 2 adds a per-user rate limit in the app** (and the monitor check that the path unit is active).

**6. Refresh lifetime and rotation (IMPORTANT; `logs/68`).**
- "Refresh at most 8 h" was **computed client-side** from the client setting. It is **untested**, and `stored` now
  says so.
- The "rotated: True" check compared after overwriting. It now compares old vs new, and **`logs/68` shows the
  result**.
- Plan 2 tests a refresh near the limit and reads the session expiry from Kanidm (introspection), not from a
  constant.
- Linger: the tokens die with the user's last session (`logs/45`). That is intended for a desktop user. With
  `loginctl enable-linger` the runtime dir would outlive logout. Plan 2 must keep linger off for these users, or
  stop relying on the runtime dir.

**Minor fixes.**
- **Loopback listener.** The prototype binds the fixed port 8400 and accepts the first request from any local user.
  PKCE makes a stolen code useless, but another local user can still make a sign-in fail. Plan 2 binds port 0 (any
  port is accepted, `logs/49`) and keeps answering until a request arrives with the right `state`.
- **tmpfs can swap.** The workstation's swap is the `chp-swap` LV inside the LUKS2 (aes-xts-plain64, 512-bit)
  volume group, so swapped token pages stay encrypted (`logs/71`).
- **Open redirect through the rewrite:** checked and refused. user_oidc strips scheme and host from `redirectUrl`
  and accepts only `/` + an alphanumeric (`LoginController::getRedirectResponse`). Live, after a real sign-in
  (`logs/73`): `redirect_url=https://evil.example/pwn` ended at `https://files.docs.lab.test:8443/pwn` (the host
  was dropped). `//evil.example/pwn` ended at NextCloud's base URL and was logged as "Rejected invalid redirect
  url". Neither left the site.
- **`auto_provision` vs `--bearer-provisioning=0`:** this is not a contradiction. In `Backend.php`,
  `auto_provision` (default true) creates the NextCloud account (`getOrCreate`). `bearer-provisioning` only decides
  whether attributes and groups are then updated from the token. So with `bearer-provisioning=0` a Bearer can still
  create an account, with no groups. Not tested. Plan 2: set `auto_provision` deliberately.
- **Results** in `out/` are now `0640 root:apache` (directory `0750 root:apache`, `logs/67`, `logs/70`).
- **`logs/62`'s "before"** (two buttons on the login page) rests on the continued part of that log (the `?direct=1`
  page still lists both). The first "before" line probed `/login`, which is a 404 here.

**Review round 2 (`logs/75-77`).**
- **Quarantine kept the raw Bearer.** `os.replace` moved the original spool file, and `pop()` removed the token only
  from memory, so the claim "never stores the token" was false. Fixed:
  - `quarantine()` now writes a record without `bearer_token` (an unparsable file is recorded only as its size and
    sha256), then always deletes the spool file.
  - `purge-quarantine` cleaned the one existing file (`71c55686…`, the forged request of `logs/69`).
  - The forged case was re-run: refused, and no quarantine file holds `bearer_token` or the forged signature
    (`logs/75`, `logs/76`).
- **Compliance was decided by a path regex over the user's own view**, so a home folder named `Compliance` would have
  matched. Fixed in chp_ledger 0.3.1: the app requires a `GroupMountPoint` with team-folder id 1 (CUI) or 5
  (Internal), and an internal path starting `Compliance/`. The appender re-checks both fields.
  - 0.3.0 wrongly expected `files/Compliance/`: the team folder's jail reports `Compliance/<name>`, found with a
    debug reply (`logs/75`).
  - Shown: home `Compliance/fake-controlled.txt` and `MyStuff/CUI/Compliance/fake2.txt` get 403; the real CUI and
    Internal Compliance files are accepted (`logs/76`).
  - The team-folder ids are spike constants; Plan 2 renders them from the site.
- **The result write could leave the file in the spool:** quarantine now happens first, and the result write is
  guarded. Shown with `out/` made immutable: the request was quarantined (its fake token not kept), "no result
  written" was logged, the spool emptied, and the path unit stayed active (`logs/77`).

**State left on iso5-docs** (for Plan 2; removal in `README.md`, as of `logs/77`):
- Kanidm client `chp-doc`.
- user_oidc provider `kanidm-cli` and the two `user_oidc` settings.
- The vhost rewrite (the original is `/root/spike/nextcloud.conf.before-task2`).
- App `chp_ledger` **0.3.1**.
- `/var/lib/chp-docs`: the ledger holds **25 entries**, verify OK. They include test artefacts:
  - 1-4 are `logs/56` leftovers (`logs/57` note);
  - **12-13 are the logs/66 forged-Bearer test on file 119; entry 13 carries the FORGED Kanidm evidence**, made
    before fix 3;
  - 22 and 25 are the session checkouts of logs/69 and logs/76;
  - 23-24 are logs/76's app-password checkouts.
  - Quarantine holds 5 records, none with a token.
- Units `chp-docs-ledger.{path,service}` and `chp-docs-ledger-alert.service`.
- Team folder `Approvals` (id 7).
- Test documents: file ids 281/282 in `Internal/Compliance`; lab01's home files `notes-fix5.txt`,
  `Compliance/fake-controlled.txt`, `MyStuff/CUI/Compliance/fake2.txt`.
- fapolicyd trust file `chp-spike`.
- The stick stand-in `/root/spike/stick` (its heads show 11 entries).

All route-1 sessions were revoked (`logs/64`, `logs/65`). No new SELinux or fapolicyd denials were recorded during
Task 2 (`logs/61`). fapolicyd's counter says 1 denial since its start while the audit log holds none: the same
mismatch as finding 2, not explained.

## Editor (Task 3): ONLYOFFICE Desktop Editors on a FIPS, CUI-profile workstation

**VERDICT: works with limits.** ONLYOFFICE Desktop Editors 10.0.0 (build 169) installs, runs, opens, edits, saves and
exports PDF on **iso5-dcli** (Rocky 9.8, FIPS mode on, SELinux Enforcing, fapolicyd, CUI profile, site docs.lab.test)
with **no crash, no FIPS or crypto error, 0 fapolicyd denials from the app and 0 AVCs from the app** (the tuned-ppd AVCs in the window are unrelated) (2026-11-12; logs
`78`-`86`, test documents and outputs in `editor/`). The limits are below; none stopped the editing, saving or
PDF-export path. The owner decides (spec §4); the limits that matter most are 1, 2, 4, 5, 7 and 9, and the **Plan 2 gate items** at the end of this section.

### What was tested, and how
| Check | Result | How |
|---|---|---|
| Install from the vendor RPM | pass | `rpm -K` against the vendor key, then `dnf install` (deps from the Rocky 9.8 DVD) (`logs/78`) |
| Open docx (8 pages, odd/even header + footer "CUI", designation block, page-number field) | pass | **GUI** (`desktopeditors`) |
| Edit + save in place (Ctrl+S) | pass: saved file keeps odd/even header and footer | **GUI**; reread with python-docx |
| Export PDF (File > Save as > "Portable Document (*.pdf)") | pass: PDF page 1 starts `CUI (odd)`, page 8 `CUI (even)`, designation block on page 1, `Page 1` footer field; 8 pages; Producer `ONLYOFFICE/10.0.0.169` | **GUI** + `pdftotext` |
| Same for xlsx (odd/even header + footer "CUI", designation block in rows 1-4, 200 rows, repeating title row) | pass: saved xlsx keeps `differentOddEven` and all four header/footer parts; PDF (5 pages) has `CUI` as first and last line of every page checked (1, 2, 5) | **GUI** + openpyxl + `pdftotext` |
| Headless conversion (`x2t`, no GUI) | pass **after the GUI has run once** (see limit 3): docx and xlsx to PDF give the same pages and banners as the GUI; docx and xlsx round-trips work | **CLI** (`logs/81`) |

GUI driving: ONLYOFFICE ran under Xvfb (display :77) on the workstation, with keystrokes and clicks sent through
XTest and screenshots read from the Xvfb framebuffer (`editor/xinput.py`, `xin.sh`, `shot.sh`, `xwd2png.py`).
**GDM's real desktop session was not used.** What was not exercised in the GUI: Print > PDF, comments and tracked
changes, templates inside the editor (the CUI template library is Plan 2 work), macros.

### Package and signature
- The "latest" direct link `download.onlyoffice.com/install/desktop/editors/linux/onlyoffice-desktopeditors.x86_64.rpm`
  is **not signed** (`rpm -Kv`: header and payload digests only, no OpenPGP signature; sha256 `2572599736765cef...c6bf`).
  The **same version in the vendor's yum repository is signed**: `https://download.onlyoffice.com/repo/centos/main/noarch/onlyoffice-desktopeditors-10.0.0.x86_64.rpm`
  (the path says noarch; the file is x86_64), sha256 `2e63445620f8df8449e5c485754861bdfc662482b711024e2d38f2ec545c2df9`
  (equals the checksum in the repo's `primary.xml`, whose own checksum is in `repomd.xml`, which carries a good detached
  signature `repomd.xml.asc` by the key below). That signed file is the one installed.
- **Signing key:** Ascensio System Limited (ONLYOFFICE) <support@onlyoffice.com>, RSA 4096, created 2016-12-15,
  **fingerprint `E09C A29F 6E17 8040 EF22 B409 8320 CA65 CB2D E8E5`** (key id `8320CA65CB2DE8E5`; rpm shows `cb2de8e5`).
  The key was fetched from `download.onlyoffice.com/GPG-KEY-ONLYOFFICE` and the same fingerprint was served by
  keyserver.ubuntu.com (that is a second source, not a web-of-trust check: first use is trust-on-first-use).
- **Plan 2 should re-sign:** the spec says "ships in our repo as a signed package". Our repo would carry the vendor RPM
  under our key (or the vendor key as a second trusted key in the stick), with the sha256 above pinned in the build.
  Pull the vendor's RPM from the repo path, **not** the "latest" link, and verify before re-signing.
- Package facts: 291 MB RPM, 1.2 GB installed under `/opt/onlyoffice/desktopeditors`, requires
  `boost-filesystem`, `libXScrnSaver`, five `xcb-util-*` and `liberation-narrow-fonts` beyond the CUI image (all from
  Rocky BaseOS/AppStream; they came in with the install: `boost-system` too). No `%post` scriptlet (only `%postun`).
  `rpm -V` is clean. Launcher `/usr/bin/onlyoffice-desktopeditors` sets `LD_LIBRARY_PATH` to the app directory.
  Running `/opt/.../DesktopEditors` directly (without the launcher) aborts: Qt cannot find its platform plugins.
  Dependencies cannot be resolved without a repo: Plan 2 must ship the six extra packages in the stick repo.

### Under the CUI profile (SELinux, fapolicyd)
- **SELinux:** files are `usr_t`, processes run `unconfined_t` (the user is unconfined): **zero AVC denials** from the
  application. SELinux therefore constrains it by nothing; this is a property of the user, not of the package.
- **fapolicyd:** the RPM's files are trusted through the rpmdb backend (fapolicyd's trust DB had 2235 ONLYOFFICE
  entries after the sync); the application, the CEF helpers and `x2t` ran with **0 denials from the app** (after the daemon
  restart noted below: `fapolicyd-cli --check-status` `Denied accesses: 0`, `Permissive: false`; `ausearch -m FANOTIFY`
  shows only my own `ldd` runs (ld.so exec is refused: `logs/79`) and one Xvfb exec, below). Both counters were read,
  as Task 1 requires.
- **All ONLYOFFICE processes share the host mount namespace** (`mnt:[4026531841]` for the main process and the
  helpers), so Task 1 finding 1 (own mount namespace is not checked while `allow_filesystem_mark = 0`) does not apply
  to it: its file opens were genuinely checked, and passed. It does not bypass the policy; it also does not rely on it.
  (I could not read `/etc/fapolicyd/fapolicyd.conf` as chpadmin; the setting is the RHEL default per Task 1.)
- **fapolicyd daemon failure during package install (not ONLYOFFICE-specific, but seen while installing it; PLAN 2 GATE item 1):** the
  second `rpm` transaction (installing Xvfb for GUI testing, 1 minute after the ONLYOFFICE install) triggered fapolicyd's
  rpm-plugin trust sync, which logged `Cannot delete database (1)` / `Cannot update trust database!` and the daemon
  **exited (failed)** at 18:51:47; the freshly installed `/usr/bin/Xvfb` was denied (`obj_trust=no`) in that window;
  `systemctl start fapolicyd` rebuilt the DB and fixed it. The first sync (the ONLYOFFICE install) was fine. **Retried (`logs/87`): three trials of two back-to-back `dnf install`s of small packages (no concurrent `--dump-db`) did not reproduce it: fapolicyd stayed active, two of the three trials show a sync (trial 2's packages were probably already installed, so it was most likely a no-op) and no error line was seen. Spacing was ~1-2 s between the two installs and ~20 s between trials, against ~90 s in the original failure: not reproduced, not ruled out.** Cause not isolated (two syncs 90 s apart, with my `fapolicyd-cli --dump-db` run concurrently is the
  only unusual thing). **A failed fapolicyd leaves the host unprotected until someone notices** (the monitoring should
  alarm on `fapolicyd.service` failed); Plan 2 should test "install two packages back to back" on the workstation role.
- **User data (all under `~/.local/share/onlyoffice` and `~/.config/onlyoffice`, 14 MB):** font cache, Chromium profile,
  recents list and an **auto-recovery copy of every open document** under `data/recover/` (`Editor.bin` + a copy of the
  file). These copies are CUI. **Lifecycle measured (`logs/88`):** a clean tab close (discarding changes) empties `recover/`; **`kill -9` keeps the copy and the unsaved edit** (and the next launch offers "Recover"); **a session scope killed with SIGKILL after a `loginctl terminate-session` (a forced simulation of logout, not a real GDM logout) keeps it**; no timeout was seen over the ~5 minutes observed (inside the 19:10-19:15 test window in the log's header; the start and end of that observation itself were not recorded). `recents.xml` (paths of every opened file) and the Chromium profile also persist. **These copies sit outside the CUI folder's labelling and cleanup rules** (no `CUI_` name, no tag, not under `~/chp-docs-work`), and a logged-off, locked-out or revoked user would presumably leave them behind (only a forced session kill was measured; lock-out and revocation were not) in a home directory that survives (home is 0700, on LUKS2, but readable by root/backup and by the next admin). **PLAN 2 GATE item 2:** cleanup is a requirement (see below).

### FIPS (what can and cannot be determined)
`fips-mode-setup --check`: "FIPS mode is enabled."; `/proc/sys/crypto/fips_enabled` = 1; crypto policy `FIPS`
(`logs/83`). No crypto, TLS or FIPS error anywhere: not in the application's stderr (only a harmless `libva` GPU-driver
line), not in the journal, no core dumps. **Findings:**
1. The package bundles **no separate OpenSSL, NSS, GnuTLS or curl library.** It bundles **Chromium (CEF `libcef.so`,
   313 MB) with BoringSSL statically linked** (strings: `third_party/boringssl`, `fipsmodule`). BoringSSL does **not**
   read the system's FIPS mode, crypto policy or OpenSSL FIPS provider; it is not the system's validated module.
   `libooxmlsignature.so` (document digital signatures) has `fips_mode` strings; document signing was **not tested**.
2. The processes also map the **system's** `libcrypto.so.3.5.5`, `libgnutls`, `libnss3`, `libgcrypt`, `libnettle`
   (through GTK/glib and similar). I could not establish which of the two stacks a given TLS connection would use;
   Chromium's network service (`NetworkService` helper present) uses BoringSSL for TLS.
3. In this workflow **nothing in the application makes a TLS connection**: the workstation opens and saves local files in
   the working folder, and `chp-site doc` (the Task 2 prototype, Python and the system's OpenSSL) does the NextCloud
   transport. So the editor's own TLS is out of the data path, and the FIPS posture of the working path is the system's.
   If ONLYOFFICE's network features were ever used (Clouds, Templates, update), they would use BoringSSL: **not
   FIPS-validated crypto outside the system policy.** This is a POA&M line (like the bundled OpenSSL 3.5.1 one):
   "ONLYOFFICE bundles a non-validated TLS stack (Chromium BoringSSL); network features are blocked".
4. `x2t` crashed once with a V8 trap (`invalid opcode in libdoctrenderer.so`, journal `18:51:20`): not crypto: see limit 3.

### Vendor calls (observed) and how they were blocked (`logs/82`, `logs/86`)
Captured on aero (`tcpdump` on the workstation's tap) during the edit sessions, plus `strace -e connect`:
- **Observed vendor traffic (default config, no block):** a DNS lookup of **`download.onlyoffice.com`** (the update
  check, `appcast.json`) at the first launch and again when the second file was opened; **`templates-embed.onlyoffice.com`**
  when the Templates page is opened (user action). The binary also contains `templates.onlyoffice.com`,
  `onlyoffice.com/registration`, `docspace.onlyoffice.com` and `download.onlyoffice.com/.../help/` (Help). All of these
  are plain names resolved over the site's DNS. On the lab nothing can leave anyway (no route and the site DNS
  answers REFUSED for outside names): **0 packets** left 192.168.100.0/24 in run 1 (excluding mDNS multicast); 5,954
  packets from the workstation, all to the lab's server (Wazuh, Kanidm, DNS) or mDNS.
- **Product-level block (what Plan 2 ships):** (a) `/etc/hosts` mapping the eight vendor names to `0.0.0.0` (a
  firewall/DNS block on the site gives the same: the site DNS must refuse them; the workstation's resolver is the
  site server). With that, a full edit session (open, edit, save, PDF) produced **0 DNS queries and 0 packets out of
  the lab net**; a launch under `strace` shows the app's connection attempt go to `0.0.0.0:443` (never leaves the host)
  and one Chromium UDP probe to Google DNS over IPv6 that fails with `ENETUNREACH` (a route probe; **no packet is
  sent**). (b) `~/.config/onlyoffice/DesktopEditors.conf` keys `autoUpdateMode=disabled`, `pluginsDisabled=true`,
  `lockPortals=true` (names found in the binary; values guessed, not vendor-documented): with the file in place, the
  launch showed no update-check DNS. **`pluginsDisabled` and `lockPortals` had no visible effect** (the Plugins
  and AI Tools tabs stayed; run 3 reverted the file and a clean launch also showed no update lookup within 40 s,
  so I cannot separate `autoUpdateMode`'s effect from the "once per interval" behaviour: the hosts block is the
  control that is **proven**, the conf keys are not).
- **AI features:** the editor ships an **"AI Tools" plugin** (`editors/sdkjs-plugins/{9DC93CDB-B576-4F0C-B55E-FCC9C48DD007}`)
  whose agent tools include `run_script` and `file_opener` (it can run commands for a model). It needs a model
  provider configured (none is; without a network it cannot reach one). **Removing that plugin directory removed the
  "AI Tools" tab from every editor** (screenshot-verified, plugin directory restored afterwards; the removal is a
  change to an RPM-owned directory, so `rpm -V` would flag it: ship it as a post-install step or a package patch).
  The start page still offers "AI Chat" and "AI Tools" entries that open an "Accept & Install" offer (a vendor
  download, blocked); **"Don't show me ONLYOFFICE AI Tools" removes both entries** but is a per-user setting
  stored in the Chromium profile (Local Storage), not in `DesktopEditors.conf`: the first-run needs it pre-seeded, or
  the entries stay (harmless without the network, but visible). `--lock-portals` exists on the command line.

### Direct-resolver path and what the run-1 flows were (`logs/89`)
The `strace` of a launch shows `connect()` to **2001:4860:4860::8888 port 53** (Google public DNS, IPv6) failing `ENETUNREACH`.
It is most likely Chromium's network probe (a failed `connect()` emits nothing); **no packet to any public address appeared in the captures logged** (runs 1 and 2: 0 non-multicast packets addressed outside 192.168.100.0/24, IPv4 or IPv6, at the workstation's tap; runs 3-5 captured port 53 only), and the app **did** honour `/etc/hosts` (the vendor names went to `0.0.0.0`). But it is a
**direct-to-public-resolver code path that does not go through `/etc/hosts` or the site resolver**; it failed only because
the lab has no IPv6 route. The same applies to the first run's and the Templates page's lookups: they went through the site
resolver (REFUSED), not directly. So **"0 DNS queries / 0 packets out of the lab net" holds for this lab's routing, and only for runs 1-2** (the full captures; runs 3-5 captured port 53 only); it
is not a proof for a site with a default IPv6 route or open DNS egress. The 5,905 packets to 192.168.100.53 port 1514
were the **Wazuh agent** (`wazuh-agentd`, `ss -tnp`), the 12 to port 443 were, by inference from `/etc/kanidm/config` and timing (not a socket owner at capture), **kanidm-unixd** to `https://idm.docs.lab.test`
(login/identity, the same second as the kanidm AVC), and the 20 DNS/12 mDNS/3 NetBIOS packets were the system resolver and
the GTK file dialog: none were ONLYOFFICE's.

### Limits (the list behind "works with limits")
1. **Vendor RPM from the "latest" link is unsigned;** only the yum-repo copy is signed (above). Re-signing under our key
   is needed (spec already says signed).
2. **Bundled non-validated crypto (BoringSSL in Chromium)** outside the system FIPS policy; harmless on the data path
   (no TLS used) but a POA&M item, and the vendor-call block must be shipped, not optional.
3. **First GUI run is needed before headless conversion works:** `x2t` PDF export failed with `DoctRenderer
   <error code="open"/>` / a V8 `ToLocalChecked` abort (a `ud2` trap in the journal) because `editors/sdkjs/common/AllFonts.js`
   does not exist in the package; the GUI generates it into `~/.local/share/onlyoffice/desktopeditors/data/fonts/`
   on first launch. With `<m_sAllFontsPath>` pointing there, `x2t` converted correctly. So `chp-site doc publish`'s
   PDF step can use `x2t`, but only after a first launch (or after running ONLYOFFICE's font generator; not shipped).
   `x2t` is also an unsupported interface (no documented CLI). `desktopeditors` has no `--convert-to`.
4. **Start page shows vendor features (AI Chat, AI Tools, Templates, Clouds, registration, update);** they fail
   quietly when blocked (Templates is an empty page). They need the pre-seeded setting above, and the Help menu would
   try `download.onlyoffice.com`.
5. **Chromium's sandbox is off** (`--no-sandbox` in the helper command lines; `chrome-sandbox` is not setuid). The
   embedded browser shows only local app content here, so the exposure is small, but it is an unsandboxed
   Chromium on a CUI workstation: owner-level risk statement.
6. **Heavy and not constrained by SELinux:** 1.2 GB, runs `unconfined_t`; it uses `~/.local/share/onlyoffice` for
   an autosave copy of every open CUI document (lifecycle in `logs/88`).
7. **The fapolicyd daemon failed once during back-to-back package installs** (not ONLYOFFICE's fault; not reproduced in
   three retries; Plan 2 gate item 1).
8. **GUI tested under Xvfb, not under GDM,** and on the minimum feature set (open/edit/save/PDF; header/footer;
   odd/even; designation block; page-number field).
9. **A direct-to-public-resolver path exists** (Chromium's probe to 2001:4860:4860::8888): `/etc/hosts` alone is not an
   egress control; and the autosave copies outlive crashes and logout (limit 6, `logs/88`).

### Plan 2 gate items (requirements that come out of this spike)
1. **fapolicyd health:** monitoring must alarm on `fapolicyd.service` failed (a failed daemon leaves the host unprotected and
   denied newly installed binaries meanwhile), and the workstation role needs a "two package installs back to back" test
   in the build gates. (Not reproduced in three retries; the failure was seen once.)
2. **Autosave cleanup:** `recover/` (and `recents.xml`) must be cleaned: both a **close hook** (`chp-site doc` closes/publishes
   and removes the document's `DE__*` dir and its recents entry) **and a periodic sweep** (a systemd timer that deletes
   `recover/DE__*` older than N hours when no ONLYOFFICE process of that user runs, and at logout/revocation), because
   the measurements show the close path alone does not cover `kill -9`, a crash or a killed session, and nothing else
   removes the copy. The copies must also be treated as CUI by the working-folder rules (marking, audit, backup exclusion
   or protection); the sweep must log what it removes (ledger/Wazuh). **Trade-off:** `recover/` is also the editor's crash recovery, so a blanket sweep deletes unsaved CUI edits that "Recover" could restore; the sweep must remove only copies of closed or abandoned sessions (no live ONLYOFFICE process of that user **and** older than N hours), never a live session's.
3. **Per-application egress control, not hosts alone:** an nftables/firewalld rule that drops all workstation egress except
   the site server (the CHP workstation role already has the site zone) and blocks DNS to anything but the site resolver
   (UDP/TCP 53 and DoT/DoH ports, IPv4 and IPv6), ideally per-uid or per-cgroup for the editor; keep the `/etc/hosts` block
   and the site resolver REFUSE as defence in depth. Test it with the same tap capture, with an IPv6 default route present.

### Not done
- LibreOffice comparison: **not run**, because the verdict is not "does not work".
- ONLYOFFICE digital signatures, macros, comment/track-changes round trip, PDF/A, printing, the `.docxf`/`.oform` form
  formats, and any use of the vendor's cloud features.
- Reboot persistence of the `/etc/hosts` block (the lab host's `/etc/hosts` was restored after the test).

### Cleanup / lab state
iso5-dcli keeps ONLYOFFICE 10.0.0-169 and `xorg-x11-server-Xvfb` installed (plus its Rocky dependencies); the vendor key
is in the rpm database; test files are in `~/oo-test`; `/etc/hosts`, the AI plugin directory and the DVD were restored
or detached; the Xvfb and ONLYOFFICE processes were stopped; `DesktopEditors.conf` is back to `titlebar=system` only (the test
version is `~/conf.keep`); the "Don't show AI Tools" click remains in the profile. Vendor package and key are cached on the Mac in `~/idm-lab-inputs/onlyoffice/`
(`repo-copy.rpm` = the signed one; `onlyoffice-desktopeditors.x86_64.rpm` = the unsigned "latest" link).

## For Plan 2 (decisions and work the spike surfaced)

1. fapolicyd: the namespace gap (finding 1) and the gates and collector that count FANOTIFY (finding 2): changes to
   existing products; owner decision after a per-role trial (item 11).
2. Port: 8443 (recommended) or a second address (finding 3).
3. PHP 8.4 path before NextCloud 37 (finding 4).
4. Build host for a PHP package (aero's fapolicyd blocks it): owner decision.
5. The NextCloud package ships: `/usr/lib/nextcloud`, `rules.d/65-chp-nextcloud.rules`, the `config.php` trust entry in
   `%post`, the egress table + unit (packaged since spike4 as a template), httpd/php-fpm configs that disable the
   stock listeners, the boolean, the cert renewal timer, the backup timer, the Wazuh rules.
6. Use `chp-site get SUBNET_CIDR` for the firewall rule; the site zone needs `files`.
7. The nightly tag check outside the app; the canary (public link on a CUI test file expects 403) fits the same timer.
8. Doc commands (Task 2, §Transport, §Ledger, review fixes):
   - Sign in by the Kanidm public client + Bearer (route 1); bind port 0, loop until the right state; linger off.
   - Freshness = sha256 + fileid at checkout; the ETag only as a pre-check and If-Match.
   - **MUST: publish is server-side.** The Compliance areas are read-only to users through the ACL. chp_ledger (or
     the root appender) does an atomic compare-and-write under a lock: the bytes' sha256 must equal the approved
     entry's, and the canonical copy's current sha256 must equal the checkout's (fix 1).
   - Ledger L1 (chp_ledger OCS app -> spool -> root appender).
   - Kanidm evidence is taken only from Kanidm's userinfo; approve and override need a verified Bearer (fix 3).
   - The per-cycle author rule with `create` (fix 4).
   - Quarantine on any failure, finite start limits + alert, Compliance-only file ids, a **per-user rate limit**, a
     monitor check of the path unit (fix 5).
   - Test a refresh near the limit; read the session expiry from Kanidm (fix 6).
   - The login-page rewrite.
   - `occ upgrade` in `%post` when an app's version changes.
   - From review round 2 (doc only):
     - Wire the alert to the **path unit** too (`OnFailure=` on the `.path` / its trigger limit), and test it.
     - Requesters get a fixed, generic refusal text; the detail is logged, not returned.
     - Harden the outbound userinfo call: pin the site CA; take the Kanidm host from site config, not a constant;
       disable redirects so `Authorization` is never re-sent; give it a timeout and rate budget so bad tokens cannot
       stall the appender.
     - On a Kanidm outage, retry instead of quarantining.
     - Repeated checkouts can void pending approvals, and `create` makes the caller an author: a policy decision plus
       the rate limit.
     - `preferred_username == uid` depends on user_oidc's uid mapping (`--mapping-uid=preferred_username`,
       `--unique-uid=0`), which must stay as shipped.
     - Spool hardening: open with `O_NOFOLLOW`; no check-then-use (TOCTOU) between the read and the move.
     - Compliance team-folder ids come from the site, not constants.
9. Egress: BindsTo + pre-check drop-in, a monitor check for the table, and the DNS decision (above).
10. Copy-out containment (`ContainListener`) and its logging into the audit trail; the owner decides on the
    download/re-upload residual (§Copy out).
11. fapolicyd: trial `allow_filesystem_mark = 1` per role; decide the gate (FANOTIFY count vs `--check-status`, run
    after a fapolicyd restart, since a rule reload keeps cached decisions).
