#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# prove-w1.sh STAGE (RUNS ON THE MAC): security bundle Plan W1 proof 1 on the iso5 golden lab (repo 0.7.8).
#   repo        unpack signed repo 0.7.8 on all three hosts; upgrade chp-site + chp-integrity
#   enable H    attach the site stick (USB) to H's VM, run `chp-site security enable` there, detach it
#   evidence    print the proof-1 evidence (agents, mounts, ports, firewall, config tests, denials)
# Hosts: srv = iso5-srv, cli2 = iso5-cli2, cli1 = iso5-cli1 (reached with the client2 lab key and its IP).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; F="$top/lab/iso5/ssh_config"
REPO_V=${REPO_V:-0.7.8}; STICK=/data/libvirt/images/iso5-stick.img
vm() { case $1 in srv) echo iso5-srv ;; cli1) echo iso5-cli1 ;; cli2) echo iso5-cli2 ;; esac; }
X() {   # X HOST CMD: run CMD on a lab host (chpadmin, NOPASSWD sudo via the lab adapter)
  case $1 in
    srv) ssh -F "$F" -n -o ConnectTimeout=15 srv1 "$2" ;;
    cli2) ssh -F "$F" -n -o ConnectTimeout=15 client2 "$2" ;;
    cli1) ssh -F "$F" -n -o ConnectTimeout=15 -o HostName=192.168.100.51 client2 "$2" ;;
  esac 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true
}
A() { ssh -F "$F" -n aero "$1" 2>&1 | grep -v -E 'post-quantum|store now|pq.html|^\\S$|^Kernel|^$' || true; }
case ${1:-} in
  repo)
    for h in srv cli2 cli1; do
      ssh -F "$F" -n aero "tar -C /data/chp-release/$REPO_V -czf - repo" 2>/dev/null | \
        case $h in
          srv) ssh -F "$F" srv1 'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' ;;
          cli2) ssh -F "$F" client2 'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' ;;
          cli1) ssh -F "$F" -o HostName=192.168.100.51 client2 'sudo rm -rf /var/lib/chp/repo/* && sudo tar -xzf - -C /var/lib/chp/repo --strip-components=1' ;;
        esac 2>/dev/null
      X $h 'sudo dnf -q -y --enablerepo=chp upgrade chp-site chp-integrity && rpm -q chp-site chp-integrity'
    done ;;
  enable)
    h=${2:?enable srv|cli2|cli1}; v=$(vm "$h")
    A "sudo virsh attach-disk $v $STICK sdz --targetbus usb --type disk --live >/dev/null && echo stick-attached-$v"; sleep 6
    X "$h" 'sudo chp-site security enable; echo "RC=$?"'
    A "sudo virsh detach-disk $v sdz --live >/dev/null && echo stick-detached-$v" ;;
  evidence)
    T0=${T0:?set T0 to the proof start, e.g. "10/27/2026 16:00:00"}
    echo "== agents (server)"; X srv 'sudo /var/ossec/bin/agent_control -l | grep -E "ID:"'
    for h in srv cli2 cli1; do
      echo "== $h"
      X "$h" "findmnt -no SOURCE,TARGET /var/ossec; sudo ss -ltnp | grep -E ':(1514|1515|55000) ' | awk '{print \$4}'; \
        systemctl is-active wazuh-manager wazuh-agent chp-wazuh-alerts 2>/dev/null | tr '\n' ' '; echo; \
        sudo /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1 && echo analysisd-config-OK; \
        sudo /var/ossec/bin/wazuh-agentd -t >/dev/null 2>&1 && echo agentd-config-OK; \
        echo vuln-scanner-starts: \$(sudo grep -c 'vulnerability-scanner: INFO: Vulnerability scanner module started' /var/ossec/logs/ossec.log); \
        echo data: \$(sudo du -sh /var/ossec | cut -f1); \
        echo wazuh-AVC: \$(sudo ausearch -m AVC -ts '$T0' --input-logs 2>/dev/null | grep denied | grep -v kanidm_unixd | grep -c denied); \
        echo fapolicyd-deny: \$(sudo ausearch -m FANOTIFY -ts '$T0' --input-logs 2>/dev/null | grep -c 'type=FANOTIFY')"
    done
    echo "== server firewall rich rules"; X srv 'sudo firewall-cmd --permanent --list-rich-rules' ;;
  *) sed -n '5,9p' "$0"; exit 2 ;;
esac
