#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# prove-y1.sh STAGE (RUNS ON THE MAC): security bundle Plan Y1 (YARA) proofs on the iso5 golden lab (ISO 0.3.0, Wazuh on).
#   repo        unpack signed repo 0.8.0 on all three hosts; dnf upgrade
#   enable H    attach the site stick to H's VM, run `chp-site security enable` there, detach it (srv first)
#   yara-on     every host: YARA pieces installed and wired; no Wazuh config errors; no denials; keys unchanged
#   catch       EICAR in the admin's home (/home) and /tmp on cli2 -> match lines, rule-100501 alerts, hook lines; files unmoved
#   full        a weekly scan on cli2 now (EICAR in /var/tmp) -> summary, last-full, monitor 73 OK
# Hosts: srv = iso5-srv, cli2 = iso5-cli2, cli1 = iso5-cli1 (reached with the client2 lab key and its IP).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; F="$top/lab/iso5/ssh_config"
REPO_V=${REPO_V:-0.8.0}; STICK=/data/libvirt/images/iso5-stick.img; fails=0
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
vm() { case $1 in srv) echo iso5-srv ;; cli1) echo iso5-cli1 ;; cli2) echo iso5-cli2 ;; esac; }
X() {   # X HOST CMD: run CMD on a lab host (chpadmin, NOPASSWD sudo via the lab adapter)
  case $1 in
    srv) ssh -F "$F" -n -o ConnectTimeout=15 srv1 "$2" ;;
    cli2) ssh -F "$F" -n -o ConnectTimeout=15 client2 "$2" ;;
    cli1) ssh -F "$F" -n -o ConnectTimeout=15 -o HostName=192.168.100.51 client2 "$2" ;;
  esac 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true
}
A() { ssh -F "$F" -n aero "$1" 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true; }
check() { if [[ $2 == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1: got '$2', want '$3'"; fails=$((fails+1)); fi; }
done_() { [[ $fails -eq 0 ]] && echo "stage $1: ALL PASS" || { echo "stage $1: $fails FAIL"; exit 1; }; }
case ${1:-} in
  repo)
    for h in srv cli2 cli1; do
      ssh -F "$F" -n aero "tar -C /data/chp-release/$REPO_V -czf - repo" 2>/dev/null | \
        case $h in
          srv) ssh -F "$F" srv1 'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' ;;
          cli2) ssh -F "$F" client2 'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' ;;
          cli1) ssh -F "$F" -o HostName=192.168.100.51 client2 'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' ;;
        esac 2>/dev/null
      X $h 'sudo sha256sum /var/ossec/etc/client.keys 2>/dev/null | cut -c1-16 | sudo tee /root/y1-keys-before >/dev/null; sudo dnf -q -y --refresh --enablerepo=chp upgrade >/dev/null 2>&1; rpm -q chp-site chp-security chp-identity-server | tr "\n" " "; echo'
    done ;;
  enable)
    h=${2:?enable srv|cli2|cli1}; v=$(vm "$h")
    A "sudo virsh attach-disk $v $STICK sdz --targetbus usb --type disk --live >/dev/null && echo stick-attached-$v"; sleep 6
    X "$h" 'sudo date "+%F %T" | sudo tee /root/y1-t0 >/dev/null; sudo chp-site security enable; echo "RC=$?"'
    A "sudo virsh detach-disk $v sdz --live >/dev/null && echo stick-detached-$v" ;;
  yara-on)                 # cli1 has no lab-adapter sudo: it stays on 0.3.0 (mixed versions) and must stay Active
    for h in srv cli2; do
      check "$h: yara, rules, chp-security 0.2.0" "$(X $h 'rpm -q --qf "%{NAME}-%{VERSION} " yara chp-yara-rules chp-security')" \
        "yara-4.5.2 chp-yara-rules-2026.10.29 chp-security-0.2.0 "
      check "$h: weekly scan timer enabled" "$(X $h 'systemctl is-enabled chp-yara-fullscan.timer')" "enabled"
      check "$h: recent-files timer enabled (spec §10)" "$(X $h 'systemctl is-enabled chp-yara-recent.timer')" "enabled"
      check "$h: Wazuh FIM off (spec §10.1)" "$(X $h 'sudo grep -A1 "<syscheck>" /var/ossec/etc/ossec.conf | grep -c "<disabled>yes</disabled>"')" "1"
      check "$h: YARA log present before any scan" "$(X $h 'sudo test -f /var/log/chp-yara.json && echo yes')" "yes"
      check "$h: 0 'No such tag' since enable" "$(X $h 'sudo awk -v t="$(sudo cat /root/y1-t0 | tr - /)" "\$0 >= t" /var/ossec/logs/ossec.log | grep -c "No such tag"')" "0"
      check "$h: 0 YARA/Wazuh AVCs since enable" "$(X $h 'sudo ausearch -m AVC -ts "$(sudo cat /root/y1-t0 | awk "{split(\$1,d,\"-\"); print d[2]\"/\"d[3]\"/\"d[1], \$2}")" 2>/dev/null | grep denied | grep -c -E "yara|ossec|wazuh"')" "0"
      check "$h: 0 fapolicyd denials since enable" "$(X $h 'sudo ausearch -m FANOTIFY -ts "$(sudo cat /root/y1-t0 | awk "{split(\$1,d,\"-\"); print d[2]\"/\"d[3]\"/\"d[1], \$2}")" 2>/dev/null | grep -c "type=FANOTIFY"')" "0"
      check "$h: agent keys unchanged" "$(X $h '[ "$(sudo sha256sum /var/ossec/etc/client.keys | cut -c1-16)" = "$(sudo cat /root/y1-keys-before)" ] && echo same || echo changed')" "same"
    done
    check "srv: YARA alert rules present" "$(X srv 'sudo test -f /var/ossec/etc/rules/chp_yara_rules.xml && echo yes')" "yes"
    check "srv: both agents Active" "$(X srv 'sudo /var/ossec/bin/agent_control -l | grep -c ", Active$"')" "2"
    check "srv: no active response" "$(X srv 'sudo grep -c "<active-response>" /var/ossec/etc/ossec.conf')" "0"
    done_ yara-on ;;
  catch)
    ts=$(date +%s)
    X cli2 "printf '%s\n' '$EICAR' > \$HOME/eicar-$ts.txt; printf '%s\n' '$EICAR' > /tmp/eicar-$ts.txt; sha256sum \$HOME/eicar-$ts.txt /tmp/eicar-$ts.txt | sudo tee /root/y1-eicar-sums >/dev/null"
    X srv "printf '%s\n' '$EICAR' > /tmp/eicar-srv-$ts.txt"
    n=0; for _ in $(seq 84); do n=$(X cli2 "sudo grep -c 'eicar-$ts' /var/log/chp-yara.json 2>/dev/null"); [[ $n -ge 2 ]] && break; sleep 5; done   # spec §10: ≤ 5 min + scan
    check "cli2: two match lines for the EICAR files" "$(X cli2 "sudo grep 'eicar-$ts' /var/log/chp-yara.json | grep -c '\"event\": \"match\"'")" "2"
    n=0; for _ in $(seq 84); do n=$(X srv "sudo grep -c 'eicar-srv-$ts' /var/log/chp-yara.json 2>/dev/null"); [[ $n -ge 1 ]] && break; sleep 5; done
    check "srv: its own test file caught (5-minute scan)" "$n" "1"
    X srv "rm -f /tmp/eicar-srv-$ts.txt"
    sleep 20
    check "srv: two rule-100501 alerts for cli2" "$(X srv "sudo grep 'eicar-$ts' /var/ossec/logs/alerts/alerts.json | grep -c '\"id\":\"100501\"'")" "2"
    check "srv: hook got the YARA alerts" "$(X srv "sudo grep -c 'eicar-$ts' /var/log/lab-hook.log | awk '{print (\$1>0)?\"yes\":\"no\"}'")" "yes"
    check "cli2: both files still there, unchanged" "$(X cli2 'sudo sha256sum -c /root/y1-eicar-sums >/dev/null 2>&1 && echo unchanged')" "unchanged"
    X cli2 "rm -f \$HOME/eicar-$ts.txt /tmp/eicar-$ts.txt"
    done_ catch ;;
  full)
    ts=$(date +%s)
    X cli2 "printf '%s\n' '$EICAR' > /var/tmp/eicar-full-$ts.txt; sudo systemctl start chp-yara-fullscan.service"
    s=$(X cli2 'sudo grep "\"event\": \"summary\"" /var/log/chp-yara.json | tail -1')
    echo "summary: $s"
    check "cli2: full scan found the test file" "$(X cli2 "sudo grep 'eicar-full-$ts' /var/log/chp-yara.json | grep -c '\"event\": \"match\"'")" "1"
    check "cli2: summary over 1000 files, 0 errors" "$(python3 -c "import json,sys; d=json.loads(sys.argv[1])['chp_yara']; print(d['files']>1000 and d['errors']==0)" "$s" 2>/dev/null)" "True"
    check "cli2: last-full written" "$(X cli2 'sudo test -s /var/lib/chp/yara/last-full && echo yes')" "yes"
    check "cli2: monitor 73 OK" "$(X cli2 'sudo bash /usr/lib/chp/monitor.d/73-yara-scan.sh | cut -c1-2')" "OK"
    X cli2 "sudo rm -f /var/tmp/eicar-full-$ts.txt"
    done_ full ;;
  *) sed -n '5,10p' "$0"; exit 2 ;;
esac
