# break-check.sh (RUNS ON iso5-srv AS ROOT): ISO 0.7.0 Plan 2 item 9, break the nightly check's subjects on purpose.
PSQL() { runuser -u apache -- psql -d nextcloud -qtAc "$1"; }
show() { python3 -c 'import json; d=json.load(open("/var/lib/chp/documents/check.json")); print("ok:", d["ok"]); [print("  ALERT", a) for a in d["alerts"]]' 2>&1 | cut -c1-260; }
fid=$(PSQL "select fileid from oc_filecache where path='files/CUI_webdav-r1_v1.0.txt' limit 1"); echo "untag file id $fid"
PSQL "delete from oc_systemtag_object_mapping where objecttype='files' and objectid='$fid'"
cv=$(occ config:app:get chp_foldertag contain); occ config:app:delete chp_foldertag contain
occ groupfolders:rename 3 Archive-renamed
occ config:system:set chp_lab_marker --value=out-of-band >/dev/null
echo "== check with everything broken"; chp-site documents check >/dev/null; echo "check rc=$?"; show; /usr/lib/chp/monitor.d/81-documents-tags.sh | cut -c1-200
echo "== restore"; occ config:app:set chp_foldertag contain --value="$cv" >/dev/null; occ groupfolders:rename 3 Archive; occ config:system:delete chp_lab_marker
fapolicyd-cli --file update /etc/nextcloud/config.php --trust-file nextcloud >/dev/null && fapolicyd-cli --update >/dev/null
PSQL "insert into oc_systemtag_object_mapping (objectid, objecttype, systemtagid) values ('$fid','files',1)"
chp-site documents check >/dev/null; echo "check rc=$? after restore"; show
echo "== kill the check run mid-canary"
systemctl start --no-block chp-documents-check.service
for i in $(seq 120); do occ user:info chp-canary --output=json 2>/dev/null | grep -q '"enabled":true' && break; sleep 0.5; done
echo "canary enabled during the run: $(occ user:info chp-canary --output=json | python3 -c 'import json,sys; print(json.load(sys.stdin)["enabled"])')"
systemctl kill -s KILL chp-documents-check.service; sleep 8
echo "unit: $(systemctl is-active chp-documents-check.service) / result $(systemctl show chp-documents-check.service -p Result --value)"
journalctl -u chp-documents-check.service -n 6 --no-pager -o cat | cut -c1-200
echo "canary enabled after the kill: $(occ user:info chp-canary --output=json | python3 -c 'import json,sys; print(json.load(sys.stdin)["enabled"])'); tokens: $(occ user:auth-tokens:list chp-canary --output=json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
echo "== next run"; chp-site documents check >/dev/null; echo "check rc=$?"; show
echo "== SIGKILL with ExecStopPost bypassed: the canary left on by hand, next run must see it"
occ user:enable chp-canary >/dev/null; chp-site documents check >/dev/null; echo "check rc=$?"; show
echo "canary after: $(occ user:info chp-canary --output=json | python3 -c 'import json,sys; print(json.load(sys.stdin)["enabled"])')"
chp-site documents check >/dev/null; echo "clean run rc=$?"; show
