# fsmark-trial.sh PHASE (RUNS ON A LAB HOST AS ROOT, piped by plan2.sh): the allow_filesystem_mark trial (owner decision 1).
#   on    FSMARK=1 in /etc/chp/fapolicyd-fsmark.conf, run the shipped helper (it restarts fapolicyd), show the setting
#   act   exercise every service on this host (restart + a real action each), then report denials
#   off   FSMARK=0, helper again (undoes only its own change), denials after
PHASE=$1
den() { fapolicyd-cli --check-status 2>/dev/null | awk '/^Denied accesses:/ {print $3}'; }
case $PHASE in
  on)
    cp -n /etc/chp/fapolicyd-fsmark.conf /root/fapolicyd-fsmark.conf.orig
    sed -i 's/^[[:space:]]*FSMARK=.*/FSMARK=1/' /etc/chp/fapolicyd-fsmark.conf; grep ^FSMARK= /etc/chp/fapolicyd-fsmark.conf
    /usr/libexec/chp/fapolicyd-fsmark; echo helper-rc=$?
    grep -n "allow_filesystem_mark\|chp-managed" /etc/fapolicyd/fapolicyd.conf
    systemctl is-active fapolicyd; TZ=UTC systemctl show fapolicyd -p ActiveEnterTimestamp --value
    echo "denied after restart: $(den)"; date -u +%FT%TZ > /root/fsmark-t0 ;;
  act)
    t0=$(cat /root/fsmark-t0)
    for u in kanidmd named step-ca wazuh-manager wazuh-agent suricata sssd kanidm-unixd kanidm-unixd-tasks chronyd sshd usbguard auditd firewalld; do
      systemctl cat $u >/dev/null 2>&1 || continue
      if [ $u = auditd ]; then service auditd restart >/dev/null 2>&1; else systemctl restart $u; fi
      sleep 3; echo "$u: $(systemctl is-active $u) denied=$(den)"
    done
    systemctl start chp-monitor.service; echo "monitor: denied=$(den)"
    timeout 600 chp-site yara-scan /etc >/dev/null 2>&1; echo "yara-scan /etc rc=$? denied=$(den)"
    systemctl start chp-aide-check.service; while systemctl is-active -q chp-aide-check; do sleep 5; done; echo "aide check: denied=$(den)"
    chp-site security status >/dev/null 2>&1; echo "chp-site security status rc=$? denied=$(den)"
    chp-site validate --site /etc/chp >/dev/null 2>&1; echo "chp-site validate rc=$? denied=$(den)"
    kanidm-unix status >/dev/null 2>&1; getent passwd lab01 >/dev/null; id chpadmin >/dev/null; echo "unixd/nss lookups: denied=$(den)"
    [ -x /var/ossec/bin/agent_control ] && /var/ossec/bin/agent_control -l >/dev/null 2>&1; echo "wazuh tools: denied=$(den)"
    systemctl list-units --state=failed --no-legend
    echo "== denials since $t0 (audit FANOTIFY)"; ausearch -m FANOTIFY -ts $(date -d "$t0" +"%m/%d/%Y %H:%M:%S") -i 2>/dev/null | grep -oE 'exe=[^ ]+|name=[^ ]+|path=[^ ]+' | sort | uniq -c | sort -rn | head -40
    echo "== fapolicyd journal deny lines"; journalctl -u fapolicyd --since "$t0" --no-pager | grep -i "deny\|rule=" | head -40
    echo "TOTAL denied=$(den)" ;;
  off)
    sed -i 's/^[[:space:]]*FSMARK=.*/FSMARK=0/' /etc/chp/fapolicyd-fsmark.conf; /usr/libexec/chp/fapolicyd-fsmark; echo helper-rc=$?
    grep -c "allow_filesystem_mark = 1" /etc/fapolicyd/fapolicyd.conf; grep -c "chp-managed" /etc/fapolicyd/fapolicyd.conf
    systemctl is-active fapolicyd; echo "denied=$(den)" ;;
esac
