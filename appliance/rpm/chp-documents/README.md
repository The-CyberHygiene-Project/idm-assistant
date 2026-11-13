# chp-documents

The documents role of the CyberHygiene appliance: web and PHP configuration for NextCloud (shipped by `nextcloud-chp`),
the egress table that keeps NextCloud off the internet, units and timers, backup, certificate renewal, a fapolicyd
rule and monitor checks 77-79. The package is **site-independent**; `chp-site documents enable` renders the
site-specific pieces. Installing the package starts and enables nothing, and everything fails closed until rendered.

## What `chp-site documents enable` must write

| Path | Content | Until it exists |
|---|---|---|
| `/etc/httpd/conf.d/chp-nextcloud-lan.inc` | `Require ip <SUBNET_CIDR>` | shipped `Require all denied`: httpd serves nothing |
| `/etc/chp/nextcloud-egress-addr.nft` | `define CHP_NC_SERVER_IP = <SERVER_IP>` (see the `.example`) | `chp-nextcloud-egress.service` refuses to start, so php-fpm, httpd and the cron job (BindsTo) do not start |
| `/etc/hosts` | NextCloud's own names (the apache user has no DNS at all) | |
| `/etc/chp/documents.conf` | `ENABLED=yes`, `FQDN=files.<DOMAIN>`, optional `DOCUMENTS_BACKUP_DAYS=` (default 14) | checks 77-79 print `OK documents not enabled`; cert-renew and backup units are skipped |
| `/etc/pki/nextcloud/chain.pem`, `key.pem` | the certificate (0600, root): run `/usr/libexec/chp/cert-renew-nextcloud --issue` | httpd cannot start; check 78 alerts |

Then enable: `chp-nextcloud-egress.service`, `php-fpm`, `httpd`, `nextcloud-cron.timer`, `chp-nextcloud-backup.timer`,
`chp-nextcloud-cert-renew.timer`, and restart `fapolicyd` (rule `65-chp-nextcloud.rules`; read
`fapolicyd-cli --check-status` after the restart).

## Behaviour

* **Egress.** Table `inet chp_nextcloud_egress` matches the socket owner `apache`: loopback and the server address
  only, port 53 refused (`CHP-NC-EGRESS-DNS`), everything else logged `CHP-NC-EGRESS` and rejected. The unit saves a
  normalised listing in `/var/lib/chp/nextcloud-egress.golden` right after loading; check 79 alerts when the table is
  missing or differs from it. php-fpm, httpd and `nextcloud-cron.service` `BindsTo=` the unit and run
  `nft list table ...` before starting.
* **httpd** listens on 8443 only. `/usr/libexec/chp/nextcloud-httpd-stock-off` (run before every httpd start) comments
  out the stock `Listen` lines and the sample sites (`ssl.conf`, `welcome.conf`, `userdir.conf`, `autoindex.conf`),
  because Kanidm owns `:443` and a mod_ssl update would bring them back.
* **Certificate.** `chp-nextcloud-cert-renew.timer` (15 min) renews with `step ca renew`; a missing or expired
  certificate is re-issued over ACME with `:80` opened only for the challenge (as Kanidm's renewal does). Check 78 judges
  the certificate against its own lifetime (alert below 25 % left, or 7 days for certificates of 90 days or more).
* **Checks.** 77: httpd, php-fpm, postgresql, `nextcloud-cron.timer` active. 78: certificate. 79: egress table.
  Each alerts once per change and again after 24 h (state in `/var/lib/chp/monitor/`).

## Backup and restore

`chp-nextcloud-backup.timer` (01:40 nightly) runs `chp-nextcloud-backup backup`: maintenance mode on, `pg_dump -Fc` of
the `nextcloud` database, `rsync` of `/data/nextcloud/data` and `/etc/nextcloud` into `/backup/nextcloud/<UTC stamp>/`
(mode 0700, with a sha256 `MANIFEST`), maintenance mode off. Copies older than `DOCUMENTS_BACKUP_DAYS` (default 14)
days are removed.

Restore, on a server with `nextcloud-chp` and `chp-documents` installed and rendered:

1. `chp-nextcloud-backup restore /backup/nextcloud/<stamp>` (checks the MANIFEST first and refuses on a mismatch; stops
   httpd/php-fpm/cron, recreates the database, restores the dump and the files, restores SELinux labels, restarts, turns
   maintenance mode off).
2. `occ maintenance:data-fingerprint` is run for you; clients resync. Verify with `chp-site documents check`.

## CUI boundary

The NextCloud audit file (`/var/log/nextcloud/audit.log`) and the Wazuh index record file names, folder paths and user
names of controlled material. Treat both as **CUI-boundary records**: keep them for the retention period the site's
policy sets (Wazuh retention is `RETENTION_DAYS`), keep them on the appliance, and do **not** forward them off it
(no external syslog, no cloud log service). Backups under `/backup/nextcloud` hold the documents themselves and are
equally inside the boundary.
