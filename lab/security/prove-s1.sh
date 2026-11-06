#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# prove-s1.sh STAGE (RUNS ON THE MAC): security bundle Plan S1 (Suricata) proofs on the iso5 golden lab (ISO 0.4.0).
#   repo        unpack signed repo 0.9.0 on srv and cli2; dnf upgrade; record the agent-key hash
#   enable H    attach the site stick to H's VM, run `chp-site security enable` there, detach it (srv first)
#   on          srv + cli2: Suricata installed, running on the right interface, config passes -T, no denials, keys same
#   hook        a lab ALERT_HOOK on srv (writes /var/log/lab-hook.log), as prove-y1.sh
#   catch       srv serves the S1 test body (SID 2017025, severity 1) on a high port; cli2 fetches it ->
#               eve alert on both hosts, rule-100510 alerts on the manager, a hook line
#   res         RSS, CPU and kernel drops of Suricata on both hosts
#   fresh       ISO install (0.5.0): Suricata came up at first boot; t0 = boot time, then every `on` check
#   reboot      cold reboot of cli2 then srv (final review I-3): Suricata back, rules loaded, eve read, no denials
# cli1 has no lab-adapter sudo: it stays on 0.4.0 without Suricata and must stay Active (mixed versions).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; F="$top/lab/iso5/ssh_config"
REPO_V=${REPO_V:-0.9.0}; STICK=/data/libvirt/images/iso5-stick.img; fails=0
SRV_IP=192.168.100.50; PORT=18080; SID=2017025
vm() { case $1 in srv) echo iso5-srv ;; cli2) echo iso5-cli2 ;; esac; }
X() {   # X HOST CMD: run CMD on a lab host (chpadmin, NOPASSWD sudo via the lab adapter)
  case $1 in
    srv) ssh -F "$F" -n -o ConnectTimeout=15 srv1 "$2" ;;
    cli2) ssh -F "$F" -n -o ConnectTimeout=15 client2 "$2" ;;
  esac 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true
}
A() { ssh -F "$F" -n aero "$1" 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true; }
check() { if [[ $2 == "$3" ]]; then echo "PASS $1"; else echo "FAIL $1: got '$2', want '$3'"; fails=$((fails+1)); fi; }
done_() { [[ $fails -eq 0 ]] && echo "stage $1: ALL PASS" || { echo "stage $1: $fails FAIL"; exit 1; }; }
T0='$(sudo cat /root/s1-t0 | awk "{split(\$1,d,\"-\"); print d[2]\"/\"d[3]\"/\"d[1], \$2}")'   # ausearch -ts form
case ${1:-} in
  repo)
    for h in srv cli2; do
      ssh -F "$F" -n aero "tar -C /data/chp-release/$REPO_V -czf - repo" 2>/dev/null | \
        ssh -F "$F" "$([[ $h == srv ]] && echo srv1 || echo client2)" \
          'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' 2>/dev/null
      X $h 'sudo sha256sum /var/ossec/etc/client.keys 2>/dev/null | cut -c1-16 | sudo tee /root/s1-keys-before >/dev/null; sudo dnf -q -y --refresh --enablerepo=chp upgrade >/dev/null 2>&1; rpm -q chp-site chp-security | tr "\n" " "; echo'
    done ;;
  enable)
    h=${2:?enable srv|cli2}; v=$(vm "$h")
    A "sudo virsh attach-disk $v $STICK sdz --targetbus usb --type disk --live >/dev/null && echo stick-attached-$v"; sleep 6
    X "$h" 'sudo date "+%F %T" | sudo tee /root/s1-t0 >/dev/null; sudo chp-site security enable; echo "RC=$?"'
    A "sudo virsh detach-disk $v sdz --live >/dev/null && echo stick-detached-$v" ;;
  on)
    for h in srv cli2; do
      ip=$([[ $h == srv ]] && echo $SRV_IP || echo 192.168.100.52)
      check "$h: suricata, rules, chp-security 0.3.0, chp-site 0.11.0" \
        "$(X $h 'rpm -q --qf "%{NAME}-%{VERSION} " suricata chp-suricata-rules chp-security chp-site')" \
        "suricata-7.0.17 chp-suricata-rules-2026.11.04 chp-security-0.3.0 chp-site-0.11.0 "
      check "$h: suricata active" "$(X $h 'systemctl is-active suricata')" "active"
      check "$h: suricata enabled at boot" "$(X $h 'systemctl is-enabled suricata')" "enabled"
      check "$h: runs the CHP config (drop-in), once" "$(X $h 'tr "\0" " " < /proc/$(systemctl show -p MainPID --value suricata)/cmdline | grep -o -- "-c [^ ]*" | paste -sd,')" "-c /etc/suricata/chp-suricata.yaml"
      check "$h: config passes suricata -T (as suricata, temp log dir)" "$(X $h 'd=$(sudo -u suricata mktemp -d); sudo -u suricata suricata -T -c /etc/suricata/chp-suricata.yaml -l $d >/dev/null 2>&1 && echo ok; sudo rm -rf $d')" "ok"
      check "$h: config interface holds the host address" "$(X $h "i=\$(sudo awk '/- interface:/{print \$3}' /etc/suricata/chp-suricata.yaml); ip -4 -o addr show dev \$i | grep -c ' $ip/'")" "1"
      check "$h: all rules loaded, 0 failed (suricata -T -v; the config logs to suricata.log only)" "$(X $h 'd=$(sudo -u suricata mktemp -d); sudo -u suricata suricata -T -v -c /etc/suricata/chp-suricata.yaml -l $d >/dev/null 2>&1; sudo rm -rf $d; sudo grep -o "[0-9]* rules successfully loaded, [0-9]* rules failed" /var/log/suricata/suricata.log | tail -1')" "52859 rules successfully loaded, 0 rules failed"
      check "$h: eve.json present, owned by suricata" "$(X $h 'sudo stat -c "%U %a" /var/log/suricata/eve.json')" "suricata 640"
      check "$h: logrotate file is ours (RETENTION_DAYS)" "$(X $h 'sudo grep -c -e "Managed by chp-security" -e "rotate 90" /etc/logrotate.d/suricata')" "2"
      check "$h: logrotate accepts it" "$(X $h 'sudo logrotate -d /etc/logrotate.conf 2>&1 | grep -c -i "duplicate\|error"')" "0"
      check "$h: 0 Suricata/Wazuh AVCs since enable" "$(X $h "sudo ausearch -m AVC -ts \"$T0\" 2>/dev/null | grep denied | grep -c -E 'suricata|ossec|wazuh'")" "0"
      check "$h: 0 fapolicyd denials since enable" "$(X $h "sudo ausearch -m FANOTIFY -ts \"$T0\" 2>/dev/null | grep -c 'type=FANOTIFY'")" "0"
      check "$h: 0 'No such tag' since enable" "$(X $h 'sudo awk -v t="$(sudo cat /root/s1-t0 | tr - /)" "\$0 >= t" /var/ossec/logs/ossec.log | grep -c "No such tag"')" "0"
      check "$h: agent keys unchanged" "$(X $h '[ "$(sudo sha256sum /var/ossec/etc/client.keys | cut -c1-16)" = "$(sudo cat /root/s1-keys-before)" ] && echo same || echo changed')" "same"
      check "$h: monitor 74 OK" "$(X $h 'sudo bash /usr/lib/chp/monitor.d/74-suricata.sh | cut -c1-2')" "OK"
      echo "$h: suricata RSS $(X $h 'ps -o rss= -p $(systemctl show -p MainPID --value suricata)') KB"
    done
    check "srv: Suricata alert rules present" "$(X srv 'sudo test -f /var/ossec/etc/rules/chp_suricata_rules.xml && echo yes')" "yes"
    check "srv: 0 Wazuh rule errors since enable" "$(X srv 'sudo awk -v t="$(sudo cat /root/s1-t0 | tr - /)" "\$0 >= t" /var/ossec/logs/ossec.log | grep -c -E "ERROR|CRITICAL"')" "0"
    check "srv: manager reads eve.json" "$(X srv 'sudo grep -c "Analyzing file: .*/var/log/suricata/eve.json" /var/ossec/logs/ossec.log | awk "{print (\$1>0)?\"yes\":\"no\"}"')" "yes"
    check "srv: both agents Active (cli1 still on 0.4.0)" "$(X srv 'sudo /var/ossec/bin/agent_control -l | grep -c ", Active$"')" "2"
    done_ on ;;
  hook)                    # as prove-y1.sh: a lab ALERT_HOOK on the server that appends to /var/log/lab-hook.log
    X srv 'printf "#!/bin/bash\necho \"\$(date +%%H:%%M:%%S) \$1\" >> /var/log/lab-hook.log\n" | sudo tee /usr/local/sbin/lab-hook >/dev/null; sudo chmod 0755 /usr/local/sbin/lab-hook; sudo touch /var/log/lab-hook.log; sudo sed -i "s#^ALERT_HOOK=.*#ALERT_HOOK=/usr/local/sbin/lab-hook#" /etc/chp/site.conf; sudo systemctl restart chp-wazuh-alerts'
    check "lab hook set" "$(X srv 'chp-site get ALERT_HOOK')" "/usr/local/sbin/lab-hook"
    done_ hook ;;
  catch)                   # S1 spike: SID 2017025 is priority 1; the bytes must be acknowledged (a real server)
    ts=$(date +%s); dashes=$(printf -- '-%.0s' $(seq 79))
    printf 'User accounts for \\\\LAB\r\n\r\n%s\r\nchp lab catch test %s\r\n' "$dashes" "$ts" | \
      ssh -F "$F" srv1 "rm -rf /tmp/s1c && mkdir /tmp/s1c && cat > /tmp/s1c/catch.txt" 2>/dev/null
    before_srv=$(X srv "sudo grep -c '\"signature_id\":$SID' /var/log/suricata/eve.json"); before_cli=$(X cli2 "sudo grep -c '\"signature_id\":$SID' /var/log/suricata/eve.json")
    before_w=$(X srv "sudo grep -c '\"id\":\"100510\"' /var/ossec/logs/alerts/alerts.json")
    X srv "sudo firewall-cmd -q --add-port=$PORT/tcp; cd /tmp/s1c && (setsid timeout 120 python3 -m http.server $PORT --bind $SRV_IP >/dev/null 2>&1 &)"
    sleep 2
    check "cli2: fetched the test body" "$(X cli2 "curl -s --max-time 10 http://$SRV_IP:$PORT/catch.txt | grep -c 'chp lab catch test $ts'")" "1"
    n=0; for _ in $(seq 12); do n=$(X cli2 "sudo grep -c '\"signature_id\":$SID' /var/log/suricata/eve.json"); [[ $n -gt $before_cli ]] && break; sleep 5; done
    check "cli2: eve alert SID $SID within 60 s" "$((n - before_cli))" "1"
    check "srv: eve alert SID $SID (it watches its own traffic)" "$(( $(X srv "sudo grep -c '\"signature_id\":$SID' /var/log/suricata/eve.json") - before_srv ))" "1"
    w=0; for _ in $(seq 12); do w=$(X srv "sudo grep -c '\"id\":\"100510\"' /var/ossec/logs/alerts/alerts.json"); [[ $((w - before_w)) -ge 2 ]] && break; sleep 5; done
    check "srv: two rule-100510 (level 12) alerts, from srv and cli2" "$((w - before_w))" "2"
    check "srv: alert level is 12" "$(X srv "sudo grep '\"id\":\"100510\"' /var/ossec/logs/alerts/alerts.json | tail -1 | grep -o '\"level\":12' | head -1")" '"level":12'
    sleep 10
    check "srv: hook got the Suricata alert" "$(X srv "sudo grep -c 'Suricata (high)' /var/log/lab-hook.log | awk '{print (\$1>0)?\"yes\":\"no\"}'")" "yes"
    X srv "pkill -f '[h]ttp.server $PORT' || true; sudo firewall-cmd -q --remove-port=$PORT/tcp; rm -rf /tmp/s1c"
    check "srv: test port closed again" "$(X srv "sudo firewall-cmd --list-ports | grep -c $PORT")" "0"
    done_ catch ;;
  res)
    for h in srv cli2; do
      X $h 'p=$(systemctl show -p MainPID --value suricata); echo "'$h': RSS $(ps -o rss= -p $p) KB, CPU time $(ps -o cputime= -p $p), up $(ps -o etime= -p $p)"
            sudo tail -n 400 /var/log/suricata/stats.log | awk -F"|" "/^capture.kernel_packets/{p=\$3} /^capture.kernel_drops/{d=\$3} END{printf \"  packets %d, kernel drops %d\n\", p, d}"'
      check "$h: monitor 74 OK" "$(X $h 'sudo bash /usr/lib/chp/monitor.d/74-suricata.sh | cut -c1-2')" "OK"
    done
    done_ res ;;
  fresh)
    for h in srv cli2; do
      X $h 'sudo date -d "@$(( $(date +%s) - $(cut -d. -f1 /proc/uptime) ))" "+%F %T" | sudo tee /root/s1-t0 >/dev/null; sudo sha256sum /var/ossec/etc/client.keys | cut -c1-16 | sudo tee /root/s1-keys-before >/dev/null'
      check "$h: security step of first boot succeeded" "$(X $h 'sudo journalctl --no-pager -u chp-server-firstboot -u chp-client-firstboot | grep -c "Suricata watches" | awk "{print (\$1>0)?\"yes\":\"no\"}"')" "yes"
    done
    bash "$0" on || fails=$((fails+1))
    done_ fresh ;;
  reboot)
    for h in cli2 srv; do
      X $h 'sudo systemctl reboot' >/dev/null; sleep 30
      for _ in $(seq 60); do [[ $(X $h 'echo up') == up ]] && break; sleep 10; done
      sleep 60                                   # Suricata needs ~20 s for the rules after the network is up
      check "$h: rebooted (uptime < 15 min)" "$(X $h 'awk "{print (\$1 < 900) ? \"yes\" : \"no\"}" /proc/uptime')" "yes"
      check "$h: suricata active after boot" "$(X $h 'systemctl is-active suricata')" "active"
      check "$h: rules loaded after boot" "$(X $h 'sudo journalctl -b -u suricata --no-pager | grep -c "Engine started"; sudo grep -o "[0-9]* rules successfully loaded, [0-9]* rules failed" /var/log/suricata/suricata.log | tail -1' | tail -1)" "52859 rules successfully loaded, 0 rules failed"
      check "$h: monitor 74 OK after boot" "$(X $h 'sudo bash /usr/lib/chp/monitor.d/74-suricata.sh | cut -c1-2')" "OK"
      check "$h: Wazuh reads eve.json since boot" "$(X $h 'b=$(date -d "@$(( $(date +%s) - $(cut -d. -f1 /proc/uptime) ))" "+%Y/%m/%d %H:%M:%S"); sudo awk -v t="$b" "\$0 >= t" /var/ossec/logs/ossec.log | grep -c "Analyzing file: .*/var/log/suricata/eve.json" | awk "{print (\$1>0)?\"yes\":\"no\"}"')" "yes"
      check "$h: 0 Suricata/Wazuh AVCs since boot" "$(X $h 'sudo ausearch -m AVC -ts boot 2>/dev/null | grep denied | grep -c -E "suricata|ossec|wazuh"')" "0"
      check "$h: 0 fapolicyd denials since boot" "$(X $h 'sudo ausearch -m FANOTIFY -ts boot 2>/dev/null | grep -c "type=FANOTIFY"')" "0"
    done
    check "srv: both agents Active after the reboots" "$(sleep 30; X srv 'sudo /var/ossec/bin/agent_control -l | grep -c ", Active$"')" "2"
    done_ reboot ;;
  *) sed -n '5,14p' "$0"; exit 2 ;;
esac
