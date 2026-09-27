#!/usr/bin/env bash
# b5: aero's chrony serves the lab (no internet time source exists here).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
C=/etc/chrony.conf
# The CUI profile makes chrony client-only ("port 0"). aero must SERVE time to the lab,
# so that one line is commented out (a logged deviation; OpenSCAP will flag it).
grep -q '^port 0' "$C" && run "let chrony serve NTP (comment out CUI 'port 0')" \
  sed -i 's/^port 0$/# port 0   # lab deviation: aero serves NTP to 192.168.100.0\/24/' "$C"
grep -q '^allow 192.168.100.0/24' "$C" || run "allow lab clients" sh -c "echo 'allow 192.168.100.0/24' >> $C"
grep -q '^local stratum 10' "$C" || run "serve local time when unsynchronised" sh -c "echo 'local stratum 10' >> $C"
run "restart chronyd" systemctl restart chronyd
ZONE=$(firewall-cmd --get-zone-of-interface=br-lab 2>/dev/null || firewall-cmd --get-default-zone)
run "open ntp on $ZONE" firewall-cmd --permanent --zone="$ZONE" --add-service=ntp
run "reload firewall" firewall-cmd --reload
log "RTC mode (reported, not changed): LocalRTC=$(timedatectl show -p LocalRTC --value)"
log "b5 done"
