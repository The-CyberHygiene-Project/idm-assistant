# backup.sh (RUNS ON iso5-srv AS ROOT): ISO 0.7.0 Plan 2 item 12: backup, lock, partial dir, restore.
B=/usr/libexec/chp/chp-nextcloud-backup; [ -x $B ] || B=$(command -v chp-nextcloud-backup)
echo "tool: $B"
mkdir -p /backup/nextcloud/20260101T000000Z; echo "partial dir made (no MANIFEST)"
( flock -n /var/lib/chp/documents/backup.lock sleep 20 ) & sleep 1
$B backup; echo "backup while the lock is held: rc=$? (75 expected)"; wait
systemctl start chp-nextcloud-backup.service; echo "backup unit rc=$? result=$(systemctl show chp-nextcloud-backup.service -p Result --value)"
cat /var/lib/chp/documents/backup.status 2>&1 | head -3
ls -l /backup/nextcloud/; ls -d /backup/nextcloud/20260101T000000Z 2>&1 | sed 's/^/partial: /'
s=$(ls /backup/nextcloud | grep -E '^[0-9]{8}T[0-9]{6}Z$' | tail -1); echo "stamp $s"; ls /backup/nextcloud/$s; wc -l < /backup/nextcloud/$s/MANIFEST
du -sh /backup/nextcloud/$s; stat -c '%a %U' /backup/nextcloud/$s
echo "== after the backup: a new file, a deleted file"
echo after > /tmp/after.txt; runuser -u apache -- true
n0=$(runuser -u apache -- psql -d nextcloud -qtAc "select count(*) from oc_filecache where path like 'files/%'")
echo "filecache rows (files/) before restore: $n0"
occ files:scan --all >/dev/null 2>&1
mkdir -p /data/nextcloud/data/__groupfolders/4 && echo x > /data/nextcloud/data/__groupfolders/4/after-backup.txt && chown apache: /data/nextcloud/data/__groupfolders/4/after-backup.txt && restorecon /data/nextcloud/data/__groupfolders/4/after-backup.txt
occ groupfolders:scan 4 >/dev/null 2>&1; echo "after-backup.txt in filecache: $(runuser -u apache -- psql -d nextcloud -qtAc "select count(*) from oc_filecache where name='after-backup.txt'")"
echo "== restore"; $B restore /backup/nextcloud/$s; echo "restore rc=$?"
echo "after-backup.txt in filecache: $(runuser -u apache -- psql -d nextcloud -qtAc "select count(*) from oc_filecache where name='after-backup.txt'"); on disk: $(ls /data/nextcloud/data/__groupfolders/4/after-backup.txt 2>&1 | tail -1)"
echo "filecache rows (files/) after: $(runuser -u apache -- psql -d nextcloud -qtAc "select count(*) from oc_filecache where path like 'files/%'")"
systemctl is-active httpd php-fpm postgresql nextcloud-cron.timer | tr '\n' ' '; echo; occ status --output=json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("maintenance", d["maintenance"])'
ls -Z /data/nextcloud/data | head -3
chp-site documents check >/dev/null; echo "check after restore rc=$?"; python3 -c 'import json; d=json.load(open("/var/lib/chp/documents/check.json")); print("ok:", d["ok"], d["alerts"])' | cut -c1-300
fapolicyd-cli --check-status | grep ^Denied; ausearch -m AVC -ts recent 2>/dev/null | grep -c denied
