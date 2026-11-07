#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# prove-r1.sh STAGE (RUNS ON THE MAC): security bundle Plan R1 (the ISSO's daily review) proofs on the iso5 lab (0.5.0).
#   repo        unpack signed repo 0.10.0 on srv and cli2; dnf upgrade; record the agent-key hash
#   enable H    attach the site stick, run `chp-site security enable` on H, detach (srv first)
#   on          sysstat and the record timer on both hosts, no new listener, 0 denials, both hosts' records on the
#               manager, the server's build timer and review rules
#   build       seeded: the Suricata catch (prove-s1.sh catch) and a YARA test file; then today's report built as the
#               timer would build it tomorrow (nightly() with today = tomorrow), and its sections checked
#   sign        the ISSO signs that report; review verify is clean
#   tamper      an edited earlier entry, then an edited kept report: review verify fails and monitor 75 alerts
#   export      review export to the site stick; a rewritten ledger then fails `review verify --stick`
#   soon        a test CA certificate with 5 days left: monitor 75 alerts at once; removed again
#   reboot      cold reboot of cli2 then srv: the review timers are active again, records arrive
#   res         sysstat and record cost on both hosts
# cli1 has no lab-adapter sudo: it stays on 0.5.0 (mixed versions) and shows STALE in the review.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; F="$top/lab/iso5/ssh_config"
REPO_V=${REPO_V:-0.10.0}; STICK=/data/libvirt/images/iso5-stick.img; fails=0; ISSO="D. Shannon"
PYZ=/usr/share/chp-site/chp-site.pyz; RD=/var/lib/chp/review
vm() { case $1 in srv) echo iso5-srv ;; cli2) echo iso5-cli2 ;; esac; }
X() {
  case $1 in
    srv) ssh -F "$F" -n -o ConnectTimeout=15 srv1 "$2" ;;
    cli2) ssh -F "$F" -n -o ConnectTimeout=15 client2 "$2" ;;
  esac 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true
}
A() { ssh -F "$F" -n aero "$1" 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true; }
check() { if [[ $2 == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1: got '$2', want '$3'"; fails=$((fails+1)); fi; }
done_() { [[ $fails -eq 0 ]] && echo "stage $1: ALL PASS" || { echo "stage $1: $fails FAIL"; exit 1; }; }
T0='$(sudo cat /root/r1-t0 | awk "{split(\$1,d,\"-\"); print d[2]\"/\"d[3]\"/\"d[1], \$2}")'
# nightly() for a given "today" (the lab cannot wait a day): the same function the timer runs
NIGHTLY='sudo python3 -c "import sys; sys.path.insert(0, \"'$PYZ'\"); import time; from datetime import date, timedelta; from chp_site import cli, review_store as st, wazuh_alerts as wa; s, h = cli._load(\"/etc/chp\"); n = time.time(); print(st.nightly(today=date.today() + timedelta(days=1), site=s, hosts=h, alerts=wa.load_alerts(\"/var/ossec/logs/alerts\", n - 3 * 86400), now=n))"'
case ${1:-} in
  repo)
    for h in srv cli2; do
      ssh -F "$F" -n aero "tar -C /data/chp-release/$REPO_V -czf - repo" 2>/dev/null | \
        ssh -F "$F" "$([[ $h == srv ]] && echo srv1 || echo client2)" \
          'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' 2>/dev/null
      X $h 'sudo sha256sum /var/ossec/etc/client.keys 2>/dev/null | cut -c1-16 | sudo tee /root/r1-keys-before >/dev/null; sudo ss -ltnup | sed -E "s/pid=[0-9]+,//g; s/fd=[0-9]+//g" | sort | sudo tee /root/r1-ss-before >/dev/null; sudo dnf -q -y --refresh --enablerepo=chp upgrade >/dev/null 2>&1; rpm -q chp-site chp-security | tr "\n" " "; echo'
    done ;;
  enable)
    h=${2:?enable srv|cli2}; v=$(vm "$h")
    A "sudo virsh attach-disk $v $STICK sdz --targetbus usb --type disk --live >/dev/null && echo stick-attached-$v"; sleep 6
    X "$h" 'sudo date "+%F %T" | sudo tee /root/r1-t0 >/dev/null; sudo chp-site security enable; echo "RC=$?"'
    A "sudo virsh detach-disk $v sdz --live >/dev/null && echo stick-detached-$v" ;;
  on)
    for h in srv cli2; do
      check "$h: chp-site 0.12.0, chp-security 0.4.0, sysstat" "$(X $h 'rpm -q --qf "%{NAME}-%{VERSION} " chp-site chp-security sysstat')" "chp-site-0.12.0 chp-security-0.4.0 sysstat-12.5.4 "
      check "$h: sysstat and record timers active" "$(X $h 'systemctl is-active sysstat-collect.timer sysstat-summary.timer chp-review-record.timer | tr "\n" " "')" "active active active "
      check "$h: record log present 0640" "$(X $h 'sudo stat -c %a /var/log/chp-review.json')" "640"
      check "$h: no new listener" "$(X $h 'sudo ss -ltnup | sed -E "s/pid=[0-9]+,//g; s/fd=[0-9]+//g" | sort | sudo diff /root/r1-ss-before - >/dev/null && echo same || echo changed')" "same"
      check "$h: 0 AVCs since enable" "$(X $h "sudo ausearch -m AVC -ts \"$T0\" 2>/dev/null | grep -c denied")" "0"
      check "$h: 0 fapolicyd denials since enable" "$(X $h "sudo ausearch -m FANOTIFY -ts \"$T0\" 2>/dev/null | grep -c 'type=FANOTIFY'")" "0"
      check "$h: agent keys unchanged" "$(X $h '[ "$(sudo sha256sum /var/ossec/etc/client.keys | cut -c1-16)" = "$(sudo cat /root/r1-keys-before)" ] && echo same || echo changed')" "same"
    done
    check "srv: build timer enabled" "$(X srv 'systemctl is-enabled chp-review-build.timer')" "enabled"
    check "srv: review rules present" "$(X srv 'sudo test -f /var/ossec/etc/rules/chp_review_rules.xml && echo yes')" "yes"
    X srv 'sudo systemctl start chp-review-record.service'; X cli2 'sudo systemctl start chp-review-record.service'
    n=0; for _ in $(seq 30); do n=$(X srv 'sudo grep "\"id\":\"100520\"" /var/ossec/logs/alerts/alerts.json | grep -o "\"host\":\"iso5-[a-z0-9]*" | sort -u | wc -l'); [[ $n -ge 2 ]] && break; sleep 10; done
    check "srv: records from both hosts on the manager" "$n" "2"
    check "srv: monitor 75 runs" "$(X srv 'sudo bash /usr/lib/chp/monitor.d/75-review.sh | grep -c "failed"')" "0"
    done_ on ;;
  build)
    bash "$here/prove-s1.sh" catch | tail -1
    X cli2 "printf '%s\\n' 'X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > /tmp/r1-eicar.txt"
    n=0; for _ in $(seq 72); do n=$(X srv 'sudo grep -c "r1-eicar" /var/ossec/logs/alerts/alerts.json'); [[ ${n:-0} -ge 1 ]] && break; sleep 5; done
    X cli2 'rm -f /tmp/r1-eicar.txt'
    check "srv: YARA match for the test file reached the manager" "$([[ ${n:-0} -ge 1 ]] && echo yes)" "yes"
    X srv "$NIGHTLY"
    d=$(X srv "sudo ls $RD | grep -E '^[0-9]{4}-' | tail -1"); echo "report day: $d"
    check "srv: today's report built (0600 files)" "$(X srv "sudo stat -c %a $RD/$d/report.md $RD/$d/report.html $RD/$d/data.json | sort -u")" "600"
    J="sudo python3 -c \"import json; d=json.load(open('$RD/$d/data.json'))"
    check "report: Suricata catch from the server, inside" "$(X srv "$J; print(any(i['kind']=='suricata' and i['source']=='192.168.100.50' and i['inside'] and i['source_host']=='iso5-srv' for i in d['intrusions']))\"")" "True"
    check "report: YARA test file under iso5-cli2" "$(X srv "$J; print(any(i['kind']=='yara' and i['source']=='iso5-cli2' for i in d['intrusions']))\"")" "True"
    check "report: cli1 (no records, still 0.5.0) is STALE" "$(X srv "$J; print([s['state'] for s in d['status'] if s['host']=='iso5-cli1'])\"")" "['STALE']"
    check "report: srv and cli2 certs, keys, scans and repo OK" "$(X srv "$J; print(sorted({s['state'] for s in d['status'] if s['host']!='iso5-cli1' and s['item']!='record'}))\"")" "['OK']"
    check "report: resources for srv and cli2 (disk at least; CPU needs 2 sysstat samples)" "$(X srv "$J; print(all(d['resources'][h] and 'disk' in d['resources'][h] for h in ('iso5-srv','iso5-cli2')))\"")" "True"
    done_ build ;;
  sign)
    d=$(X srv "sudo ls $RD | grep -E '^[0-9]{4}-' | tail -1")
    check "srv: ISSO signs $d" "$(X srv "echo yes | sudo chp-site review sign --approver '$ISSO' --notes 'R1 lab proof' --date $d | grep -o 'signed 1 review(s); recorded in the ledger and the audit log'")" "signed 1 review(s); recorded in the ledger and the audit log"
    check "srv: an unlisted name is refused" "$(X srv "echo yes | sudo chp-site review sign --approver 'Mallory' --notes x --date $d 2>&1 | grep -c refusing")" "1"
    check "srv: review verify clean" "$(X srv 'sudo chp-site review verify --quiet; echo rc=$?')" "rc=0"
    check "srv: sign-off in the audit log" "$(X srv 'sudo grep -c "chp-site review-sign" /var/log/audit/audit.log | awk "{print (\$1>0)?\"yes\":\"no\"}"')" "yes"
    done_ sign ;;
  tamper)                  # a chain protects every entry but the newest (that one: the stick anchor), so sign a 2nd day
    X srv "${NIGHTLY/timedelta(days=1)/timedelta(days=2)}" >/dev/null
    d2=$(X srv "sudo ls $RD | grep -E '^[0-9]{4}-' | tail -1")
    X srv "echo yes | sudo chp-site review sign --approver '$ISSO' --notes 'R1 second day' --date $d2 >/dev/null"
    check "srv: two entries" "$(X srv "sudo cat $RD/ledger.jsonl | wc -l")" "2"
    X srv "sudo cp $RD/ledger.jsonl /root/r1-ledger.bak; sudo sed -i 's/R1 lab proof/R1 lab proof EDITED/' $RD/ledger.jsonl"
    check "srv: edited entry: verify fails" "$(X srv 'sudo chp-site review verify --quiet >/dev/null; echo rc=$?')" "rc=1"
    check "srv: edited entry: monitor 75 alerts" "$(X srv 'sudo bash /usr/lib/chp/monitor.d/75-review.sh | grep -c "ledger check failed"')" "1"
    X srv "sudo cp /root/r1-ledger.bak $RD/ledger.jsonl"
    d=$(X srv "sudo ls $RD | grep -E '^[0-9]{4}-' | tail -1")
    X srv "sudo cp $RD/$d/report.md /root/r1-report.bak; echo edited | sudo tee -a $RD/$d/report.md >/dev/null"
    check "srv: edited report: verify fails" "$(X srv 'sudo chp-site review verify --quiet | grep -c "no longer matches"')" "1"
    X srv "sudo cp /root/r1-report.bak $RD/$d/report.md"
    check "srv: restored: verify clean" "$(X srv 'sudo chp-site review verify --quiet; echo rc=$?')" "rc=0"
    done_ tamper ;;
  export)
    A "sudo virsh attach-disk iso5-srv $STICK sdz --targetbus usb --type disk --live >/dev/null && echo stick-attached"; sleep 6
    check "srv: export to the stick" "$(X srv 'sudo chp-site review export | grep -c "written to the stick"')" "1"
    check "srv: verify --stick OK" "$(X srv 'sudo chp-site review verify --stick | grep -c "stick anchor OK"')" "1"
    X srv "sudo cp $RD/ledger.jsonl /root/r1-ledger.bak; sudo truncate -s 0 $RD/ledger.jsonl"
    check "srv: emptied ledger fails against the stick" "$(X srv 'sudo chp-site review verify --stick | grep -c "entries removed"')" "1"
    X srv "sudo cp /root/r1-ledger.bak $RD/ledger.jsonl"
    A "sudo virsh detach-disk iso5-srv sdz --live >/dev/null && echo stick-detached"
    done_ export ;;
  soon)
    X srv 'd=$(mktemp -d); sudo openssl req -x509 -newkey rsa:3072 -nodes -keyout $d/k -out /etc/pki/ca-trust/source/anchors/chp-r1test.crt -not_before 20200101000000Z -not_after $(date -u -d "+5 days" +%Y%m%d%H%M%SZ) -subj /CN=chp-r1-test >/dev/null 2>&1; sudo rm -rf $d; sudo systemctl start chp-review-record.service'
    sleep 15                 # a LONG-lived certificate (2020 to 5 days from now): the 7-day 'at once' rule
    X srv 'sudo openssl x509 -in /etc/pki/ca-trust/source/anchors/chp-r1test.crt -noout -startdate -enddate | tr "\n" " "'
    check "srv: monitor 75 alerts at once (5 days left)" "$(X srv 'sudo bash /usr/lib/chp/monitor.d/75-review.sh | grep -c "chp-r1test.crt.*within 7 days"')" "1"
    X srv 'sudo rm -f /etc/pki/ca-trust/source/anchors/chp-r1test.crt; sudo systemctl start chp-review-record.service'
    sleep 15
    check "srv: removed: no alert" "$(X srv 'sudo bash /usr/lib/chp/monitor.d/75-review.sh | grep -c chp-r1test')" "0"
    done_ soon ;;
  reboot)
    for h in cli2 srv; do
      X $h 'sudo systemctl reboot' >/dev/null; sleep 30
      for _ in $(seq 60); do [[ $(X $h 'echo up') == up ]] && break; sleep 10; done
      sleep 150                                   # the record timer's OnBootSec=2min
      check "$h: review timers active after boot" "$(X $h 'systemctl is-active sysstat-collect.timer chp-review-record.timer | tr "\n" " "')" "active active "
      check "$h: a record since boot" "$(X $h 'b=$(( $(date +%s) - $(cut -d. -f1 /proc/uptime) )); sudo tail -1 /var/log/chp-review.json | python3 -c "import sys,json; print(json.loads(json.loads(sys.stdin.read())[\"chp_review\"][\"body\"])[\"time\"] > $b)"')" "True"
    done
    check "srv: build timer enabled after boot" "$(X srv 'systemctl is-enabled chp-review-build.timer')" "enabled"
    done_ reboot ;;
  res)
    for h in srv cli2; do
      echo "$h: record $(X $h 'sudo tail -1 /var/log/chp-review.json | wc -c') bytes; $(X $h 'systemctl show -p CPUUsageNSec --value chp-review-record.service') ns CPU (last run); /var/log/sa $(X $h 'sudo du -sk /var/log/sa | cut -f1') KB"
    done
    echo "srv: review folder $(X srv "sudo du -sk $RD | cut -f1") KB"
    done_ res ;;
  *) sed -n '5,17p' "$0"; exit 2 ;;
esac
