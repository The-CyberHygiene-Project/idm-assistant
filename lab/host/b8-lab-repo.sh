#!/usr/bin/env bash
# b8: serve /data/lab-inputs (DVD mount + lab-local rpms) read-only over HTTP on the lab bridge address only.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
UNIT=/etc/systemd/system/lab-repo.service
if (( CHECK )); then log "[check] would: write $UNIT (python3 http.server 192.168.100.1:8080 /data/lab-inputs), open 8080/tcp in firewalld"; exit 0; fi
cat > "$UNIT" <<'U'
[Unit]
Description=Lab package repo (DVD + lab-local) for br-lab VMs
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 8080 --bind 192.168.100.1 --directory /data/lab-inputs
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
U
run "enable lab-repo" systemctl daemon-reload
run "start lab-repo" systemctl enable --now lab-repo.service
zone=$(firewall-cmd --get-zone-of-interface=br-lab 2>/dev/null || firewall-cmd --get-default-zone)
run "open 8080/tcp in $zone" firewall-cmd --permanent --zone="$zone" --add-port=8080/tcp
run "reload firewall" firewall-cmd --reload
log "b8 done: http://192.168.100.1:8080/ (zone $zone)"
