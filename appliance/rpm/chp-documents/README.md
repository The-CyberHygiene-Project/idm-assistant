# chp-documents

The documents role of the CyberHygiene appliance: web and PHP configuration for NextCloud (shipped by `nextcloud-chp`),
the egress table that keeps NextCloud off the internet, units and timers, backup, certificate renewal, a fapolicyd
rule and monitor checks 77-79, 81 and 82. The package is **site-independent**; `chp-site documents enable` renders the
site-specific pieces. Installing the package starts and enables nothing, and everything fails closed until rendered.

## What `chp-site documents enable` must write

| Path | Content | Until it exists |
|---|---|---|
| `/etc/httpd/conf.d/chp-nextcloud-lan.inc` | `Require ip <SUBNET_CIDR>` | shipped `Require all denied`: httpd serves nothing |
| `/etc/chp/nextcloud-egress-addr.nft` | exactly one line `define CHP_NC_SERVER_IP = <SERVER_IP>` (see the `.example`) | `chp-nextcloud-egress.service` refuses to start, so php-fpm, httpd and the cron job (BindsTo) do not start |
| `/etc/hosts` | NextCloud's own names (the apache user has no DNS at all) | |
| `/etc/chp/documents.conf` | `ENABLED=yes`, `FQDN=files.<DOMAIN>`, `SERVER_IP=<IPv4>` (must equal the address file), optional `DOCUMENTS_BACKUP_DAYS=` (default 14) | checks 77-79 print `OK documents not enabled`; cert-renew and backup units are skipped |
| `/etc/pki/nextcloud/chain.pem`, `key.pem` | the certificate (0600, root): run `/usr/libexec/chp/cert-renew-nextcloud --issue` | httpd cannot start; check 78 alerts |

Then enable: `chp-nextcloud-egress.service`, `php-fpm`, `httpd`, `nextcloud-cron.timer`, `chp-nextcloud-backup.timer`,
`chp-nextcloud-cert-renew.timer`, `chp-documents-check.timer` (the nightly check: Plan 2 round 4, D13, it was missing),
and restart `fapolicyd` (rule `65-chp-nextcloud.rules`; read
`fapolicyd-cli --check-status` after the restart). enable proves that restart: fapolicyd must be active at three samples
over about 5 s and answer a `Denied accesses` counter, then `fapolicyd-fsmark --verify` must pass; a fapolicyd found
dead is restarted once more, and dead again fails the run (fapolicyd 1.4.3-3 can exit about one second after a
restart, "recvmesg failed": lab round 3, D6). A fapolicyd found dead when no restart is needed gets the same proven
restart. A stray group on CUI, FCI or Archive is removed together with its ACL rule on `/` (round 4, O8).

## Behaviour

* **Egress.** Table `inet chp_nextcloud_egress` matches the socket owner `apache`: loopback and the server address
  only, port 53 refused (`CHP-NC-EGRESS-DNS`), everything else logged `CHP-NC-EGRESS` and rejected. The unit saves a
  address file is `include`d by nft, so `nextcloud-egress-validate` insists it is one valid IPv4 line equal to
  `SERVER_IP` (the unit refuses to load otherwise). Check 79 rebuilds the expected table from the shipped files in a
  throwaway network namespace on every run and alerts when the live table is missing or differs, or the address file
  is invalid. php-fpm, httpd and `nextcloud-cron.service` `BindsTo=` the unit and run
  `nft list table ...` before starting (in the cron unit as `ExecStartPre=+...`: that line runs as root, the job as
  apache; lab round 3, D11).
* **Background jobs (check 77).** Besides the units and the timer, check 77 alerts when the last
  `nextcloud-cron.service` run failed, and when NextCloud's own record of its last finished cron run (`core/lastcron`,
  written by `cron.php`) is older than 30 minutes (or absent 30 minutes after enable): the robust signal that the
  jobs really ran. Its psql runs with `-X` under `timeout 30`, and not while postgresql itself is down (one alert).
* **Backup age (check 77).** The last backup status (OK or FAILED) older than 26 h alerts, so a backup timer that is
  off or never fires is seen; no status at all alerts once documents.conf is 26 h old (final review M2).
* **Wazuh (owner decision 2, design §3).** Every upload, new file or folder and overwrite (admin_audit "created" /
  "written to") is stored at level 3 (100621), like downloads from CUI/FCI/Archive (100607). A break-glass sign-in as
  `ncadmin` pages at 12 (100622), and so does an account made or a group membership changed inside NextCloud (100623);
  the same lines from the Kanidm sign-in (user_oidc's callback) are stored at 3 (100624), and so are the nightly
  check's own canary set-up lines (occ, 03:05-03:45, 100625). Expected: the FIRST enable pages twice (100623: occ
  makes `ncadmin` and adds it to `admin`); tell the ISSO before enabling.
* **httpd** listens on 8443 only. `/usr/libexec/chp/nextcloud-httpd-stock-off` (run before every httpd start) comments
  out the stock `Listen` lines and the sample sites (`ssl.conf`, `welcome.conf`, `userdir.conf`, `autoindex.conf`),
  because Kanidm owns `:443` and a mod_ssl update would bring them back.
* **Certificate.** `chp-nextcloud-cert-renew.timer` (15 min) renews with `step ca renew`; a missing or expired
  certificate is re-issued over ACME with `:80` opened only for the challenge (as Kanidm's renewal does). Check 78 judges
  the certificate against its own lifetime (alert below 25 % left, or 7 days for certificates of 90 days or more).
* **Checks.** 77: httpd, php-fpm, postgresql, `nextcloud-cron.timer` active. 78: certificate. 79: egress table.
  81: the result of the nightly `chp-site documents check` (`chp-documents-check.timer`, 03:10), read from
  `/var/lib/chp/documents/check.json` (0600): every file in CUI, FCI and Archive carries its tag (Archive: CUI), every
  `CUI_`/`FCI_` file anywhere carries its tag, no CUI/FCI-tagged file outside those folders, no share on anything in
  them, `chp_foldertag` enabled with `rules`/`contain`/`contain_allow` equal to the site policy, no team folder outside
  the site's six, CUI/FCI tags restricted, `/etc/nextcloud/config.php` equal to its fapolicyd trust entry; **access
  granted inside NextCloud** (final review I2): every `cui-users` member is a Kanidm (`user_oidc`) account or
  `chp-canary`, the `admin` group is exactly `ncadmin`, and on CUI, FCI and Archive advanced permissions are on and the
  only ACL rule is doc-reviewers read-only on `/` (any other rule is flagged); and the
  share canary (a public link and an internal share on `CUI/CUI_chp-canary.txt` as the local account `chp-canary`,
  disabled between runs, signed in by a per-run app token that is deleted afterwards) refused. A missing result or
  one older than 26 h alerts, except "pending first run" (OK) while there is no result yet and documents.conf is
  younger than 26 h (final review M1); DEGRADED (database MD5, design §12) is shown, not alerted; a psql failure is
  "UNKNOWN" and alerts (M3). The check reads the database
  with SQL as apache over the socket, so it runs while `chp_foldertag` is off. On a site whose enable set up the
  document workflow (Plan 3), it also checks that every group reaching a Compliance or Superseded area (Internal
  included, and any group mapped to a team folder by hand) has the read-only rule there, that Internal has advanced
  permissions on and no other rule on its areas, and that `chp_ledger` is enabled with exactly the area ids of
  documents.conf.
  82 (Plan 3 Task 9): the document ledger: `chp-docs-ledger.path` active; `chp-site doc-ledger verify` exits 0; the
  quarantine is empty (look, then `chp-site doc-ledger purge-quarantine`); and no unfinished publish
  (`chp-site doc-ledger pending`: the durable records `/var/lib/chp-docs/unfinished/<request id>`, root 0600 in
  0700, written before a publish's first write, removed at its clean end and kept, with the failed steps, when its
  undo failed; plus root's journal lines only, `_UID=0`), until the ISSO has checked the area and run
  `chp-site doc-ledger resolve <request id> --reason "..."` (a chained ledger entry, Wazuh 100651). The journal lines
  of the appender are Wazuh rules 100640-100654 (decoder `chp-docs-ledger`): approvals and overrides level 12 (at
  once), publications 7, checkout and new 3, quarantine and appender failures 12. Every reader (verify, pending,
  export, the daily review, the nightly backup) takes the ledger's shared lock, so it never sees a half-written
  line; one that waits too long reports BUSY (check 82: not checked this run, no all-clear).
  `ExecStopPost=chp-site documents canary-off` switches the canary account off after any end of the run (failure,
  timeout, kill). The timer has no `Persistent=`: Wazuh rule 100609 pages (12) when `chp-canary` is enabled other
  than by occ inside 03:05-03:45 (100618, level 3), and 100619 pages when its password is set or changed. The
  canary's expected refusal is lowered to level 3 only for the canary file's id (rule 100608 in
  `/var/ossec/etc/rules/chp_nextcloud_rules_canary.xml`, written by the check). Alert text can carry CUI file names
  (they stay on the appliance: monitor, Wazuh, daily review). Trash and old versions are not checked for names.
  **Two consequences, by design:** (1) running `chp-site documents check` by hand outside 03:05-03:45 enables
  `chp-canary` outside the window, which pages at **level 12** (rule 100609) exactly like an intrusion; tell the ISSO
  first, or run it inside the window. (2) A missed night (server off at 03:10) is not caught up: there is **no tag
  check and no canary for up to about 48 h**, and check 81 alerts that the result is stale once it is older than
  26 h. `canary-off` fails (unit failed, in the journal) when occ cannot tell whether the account exists; it never
  takes an occ error as "no account".
  Check 77 also alerts when the last backup failed. Each alerts once per change and again after 24 h (state in
  `/var/lib/chp/documents/`); while an alert is held back the check prints `OK ... still failing (alerted <time>)`.

## Backup and restore

`chp-nextcloud-backup.timer` (01:40 nightly) runs `chp-nextcloud-backup backup`: maintenance mode on, `pg_dump -Fc` of
the `nextcloud` database, `rsync` of `/data/nextcloud/data` and `/etc/nextcloud` into `/backup/nextcloud/<UTC stamp>/`
(mode 0700, with a sha256 `MANIFEST`), maintenance mode off. Each night is an `rsync --link-dest` incremental of the previous copy (hardlinks) plus a new
dump. Copies older than `DOCUMENTS_BACKUP_DAYS` (default 14) days are removed, never going below 2 copies. Before
copying, if `/backup` has less free space than the last copy, the oldest copies are pruned (down to 2); if it still
does not fit, the backup fails with a log line and exit 75, `/var/lib/chp/documents/backup.status` says FAILED, and check 77
alerts. The size of the last copy comes from `du -sk`, which counts the files it shares with older copies through
hardlinks in full, so it overestimates what an incremental needs: conservative, the backup can only fail loudly too
early, never fill `/backup` unannounced.

Only a directory with a `MANIFEST` counts as a copy (the `MANIFEST` is written last, by rename). A directory a killed
run left without one (SIGKILL skips the cleanup) is never the `--link-dest` base, does not count toward the 2 kept
copies, and is deleted at the start of the next run. One backup runs at a time (a lock on `/var/lib/chp/documents/backup.lock`).

Restore, on a server with `nextcloud-chp` and `chp-documents` installed and rendered:

1. `chp-nextcloud-backup restore /backup/nextcloud/<stamp>` (checks the MANIFEST first and refuses on a mismatch; stops
   httpd/php-fpm/cron, recreates the database, restores the dump and the files, restores SELinux labels, restarts, turns
   maintenance mode off).
2. `occ maintenance:data-fingerprint` is run for you; clients resync. It rewrites `/etc/nextcloud/config.php`, so the
   restore then runs `chp-site documents trust`: config.php's fapolicyd trust entry is refreshed (`fapolicyd-cli
   --file update`, `--update`; no fapolicyd restart) and read back equal to the file; if not, the restore fails
   (exit 1). Verify with `chp-site documents check`.

## CUI boundary

The NextCloud audit file (`/var/log/nextcloud/audit.log`) and the Wazuh index record file names, folder paths and user
names of controlled material. Treat both as **CUI-boundary records**: keep them for the retention period the site's
policy sets (Wazuh retention is `RETENTION_DAYS`), keep them on the appliance, and do **not** forward them off it
(no external syslog, no cloud log service). Backups under `/backup/nextcloud` hold the documents themselves and are
equally inside the boundary.

## Known limitations (SSP / POA&M notes)

* **OIDC authorization code in the audit log.** NextCloud's audit log (`/var/log/nextcloud/audit.log`, written by
  admin_audit and by NextCloud's log writer, not by CHP code) records the request URL of each line; for the sign-in
  callback that URL carries the OIDC `code` and `state` query values, so they reach the Wazuh `full_log` too. The code
  is single-use, bound to the client secret and to PKCE (S256), and expires within minutes, so it cannot be replayed
  from the log; the log itself is a CUI-boundary record (above). CHP does not control that writer, so it is not
  redacted: record it in the SSP (AU-9 / AU-3) and as a POA&M item until NextCloud can omit query strings from the
  log (lab Plan 2 round 3).
* **Events during a Wazuh manager restart can be missed** (proof record O6, final review M4). enable restarts the
  manager when the NextCloud rules change, and the nightly check restarts it when the canary file's id changes (the
  first run, or a re-created canary file): lines NextCloud writes while the manager restarts may not be analysed (O6
  saw one 100609 missed). The audit log file itself keeps every line. SSP note (AU-6).
* **Up to 24 h to see a changed app policy** (final review M8). Emptying chp_foldertag's `contain` or `rules` turns
  containment or tagging off; the nightly check (81) reports it, up to 24 h later. No Wazuh rule: admin_audit logs
  only the occ form (`Console command executed: config:app:set ...`, root on the server, which enable itself runs on
  every run); the web form needs an admin sign-in, and the break-glass sign-in (100622) or a new admin (100623) pages
  at once. SSP note (CM-3 / SI-4).
* **fapolicyd 1.4.3-3 can exit about 1 s after a restart** ("recvmesg failed", with `allow_filesystem_mark = 0` too):
  every CHP restart is verified and retried once (above, and chp-base's `fapolicyd-fsmark`); check 80 alerts while it
  is down. POA&M item until Rocky ships a fixed fapolicyd.

## Notes for Tasks 5 and 9

* NextCloud mail must stay off and `postfix` absent: a unix-socket relay to a local MTA is a path the egress uid match
  cannot see.
* Run an AIDE baseline refresh after `documents enable` (new files under `/etc`, `/usr/lib/nextcloud`, units).
* Rule 65 has no `ftype=`: prove with a user-stored `.so` and a binary read by NextCloud (no 42-trusted-elf denial).
* `cert-renew-nextcloud` and `cert-renew-kanidm` share `/run/chp-acme.lock` around the `:80` window (chp-identity-server
  needs its next release to carry the Kanidm side).
