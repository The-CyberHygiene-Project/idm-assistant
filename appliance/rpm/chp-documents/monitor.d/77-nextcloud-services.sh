#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 77-nextcloud-services (Plan 2): httpd, php-fpm, postgresql and the NextCloud cron timer are active. Silent OK when
# documents are not enabled (/etc/chp/documents.conf absent). The nightly backup status is part of it. Alerts once per change, again after 24 h (held-back alerts print "OK ... still failing").
# Background jobs (Task 9d, D11: an active timer said OK while every run failed): once enable has finished
# (ENABLED=yes), also
#   - the LAST nextcloud-cron.service run must have succeeded (systemctl show -p Result), and
#   - NextCloud's own record of its last finished cron run (core/lastcron in oc_appconfig, written by cron.php at the
#     end of each run) must be younger than CHP_NC_CRON_STALE seconds (1800 = 6 missed 5-minute runs). No record
#     yet is an alert only once documents.conf is that old too (a fresh enable gets its first run first).
#   lastcron is the robust signal: it is NextCloud saying the jobs ran, whatever made the unit fail or not start.
#   psql runs with -X (no psqlrc) under `timeout` (a wedged PostgreSQL must not hang the monitor run), and not at all
#   while postgresql itself is down (that one alert names the cause). "never ran", "stale" and "cannot read" are
#   separate keys, so a change from one to another alerts at once (Plan 3 Task 1, 9d review minors 4-5).
# The nightly backup's age (final review M2): its last status (OK or FAILED) older than CHP_NC_BACKUP_STALE seconds
# (26 h, as the daily review) alerts, so a backup timer that is off or never fires is seen; no status at all alerts
# once documents.conf is that old too (a fresh enable waits for the first 01:40 run).
C=${CHP_DOCUMENTS_CONF:-/etc/chp/documents.conf}
[ -f "$C" ] || { echo "OK documents not enabled on this host"; exit 0; }
. "${CHP_DOCS_LIB:-/usr/lib/chp/chp-documents-lib.sh}"
docs_begin 77-services
pgdown=0
for u in httpd php-fpm postgresql nextcloud-cron.timer; do
  if ! systemctl is-active --quiet "$u" 2>/dev/null; then
    docs_flag "$u" "NextCloud: $u is not active"
    [ "$u" = postgresql ] && pgdown=1
  fi
done
# the nightly backup (chp-nextcloud-backup) records FAILED here, e.g. when /backup is out of space
bs=$docs_sd/backup.status
if [ "$(awk 'NR==1{print $1}' "$bs" 2>/dev/null)" = FAILED ]; then
  docs_flag backup "NextCloud backup failed: $(awk 'NR==1{ $1 = ""; $2 = ""; sub(/^ +/, ""); print }' "$bs")"
fi
ct=$(stat -c %Y "$C" 2>/dev/null || stat -f %m "$C" 2>/dev/null)
case $ct in ''|*[!0-9]*) ct=0 ;; esac
jobs=""
if [ "$(sed -n 's/^ENABLED=//p' "$C" 2>/dev/null | tail -n 1)" = yes ]; then
  bstale=${CHP_NC_BACKUP_STALE:-93600}
  if [ -f "$bs" ]; then
    bt=$(awk 'NR==1{print $2}' "$bs" 2>/dev/null)
    case $bt in
      ''|*[!0-9]*) docs_flag backup-stale "NextCloud backup: cannot read when the last backup ran ($bs)" ;;
      *) [ $((docs_now - bt)) -ge "$bstale" ] && docs_flag backup-stale "NextCloud backup: the last backup ran $(docs_when "$bt") (more than $((bstale / 3600)) h ago): is chp-nextcloud-backup.timer enabled and running?" ;;
    esac
  elif [ $((docs_now - ct)) -ge "$bstale" ]; then
    docs_flag backup-stale "NextCloud backup: no backup has run (no $bs; chp-nextcloud-backup.timer enabled?)"
  fi
fi
if [ "$pgdown" = 0 ] && [ "$(sed -n 's/^ENABLED=//p' "$C" 2>/dev/null | tail -n 1)" = yes ]; then
  stale=${CHP_NC_CRON_STALE:-1800}
  r=$(systemctl show nextcloud-cron.service -p Result --value 2>/dev/null)
  case $r in
    success|'') ;;
    *) docs_flag cron-run "NextCloud: the last nextcloud-cron.service run failed ($r): background jobs did not run (journalctl -u nextcloud-cron.service)" ;;
  esac
  if lc=$(timeout 30 runuser -u apache -- psql -d nextcloud -qtAXc "SELECT configvalue FROM oc_appconfig WHERE appid='core' AND configkey='lastcron'" 2>/dev/null); then
    lc=$(printf '%s' "$lc" | tr -d '[:space:]')
    case $lc in
      ''|0)
        if [ $((docs_now - ct)) -ge "$stale" ]; then
          docs_flag cron-never "NextCloud: background jobs have never run (no core/lastcron record from cron.php; nextcloud-cron.service: ${r:-unknown})"
        fi ;;
      *[!0-9]*) docs_flag cron-unread "NextCloud: cannot read when background jobs last ran (core/lastcron is not a number)" ;;
      *)
        if [ $((docs_now - lc)) -ge "$stale" ]; then
          docs_flag cron-stale "NextCloud: background jobs last ran $(docs_when "$lc") (cron.php, more than $((stale / 60)) min ago; nextcloud-cron.service: ${r:-unknown})"
        else
          jobs="; background jobs ran $(docs_when "$lc")"
        fi ;;
    esac
  else
    docs_flag cron-unread "NextCloud: cannot read when background jobs last ran (psql on oc_appconfig core/lastcron failed or timed out)"
  fi
fi
docs_end "NextCloud services (httpd, php-fpm, postgresql, cron timer) active$jobs"
exit 0
