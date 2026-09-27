#!/usr/bin/env bash
# b4: move 192.168.100.1 from enp49s0 onto bridge br-lab (for the lab VMs).
# Applies in the background and ROLLS BACK after 90 s unless /run/lab-net-ok appears.
# --rollback-test applies and deliberately never confirms, to prove the rollback works.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
OLD="Profile 1"; NIC=enp49s0; TEST=0
for a in "$@"; do [[ "$a" == "--rollback-test" ]] && TEST=1; done
nmcli -t -f NAME con show | grep -qx br-lab && { log "br-lab already exists"; exit 0; }
(( CHECK )) && { log "[check] would: create br-lab 192.168.100.1/24 on $NIC, rollback in 90 s unless confirmed"; exit 0; }
# In --rollback-test mode the wait loop never looks for the confirmation file.
# shellcheck disable=SC2016  # the loop text is written verbatim into the apply script
if (( TEST )); then WAIT='sleep 90'; else WAIT='for i in $(seq 90); do [[ -f /run/lab-net-ok ]] && exit 0; sleep 1; done'; fi
cat > /run/lab-net-apply.sh <<APPLY
#!/bin/bash
rm -f /run/lab-net-ok /run/lab-net-rolledback
nmcli con add type bridge ifname br-lab con-name br-lab ipv4.method manual ipv4.addresses 192.168.100.1/24 ipv6.method disabled bridge.stp no
nmcli con add type bridge-slave ifname $NIC master br-lab con-name br-lab-port
nmcli con mod "$OLD" connection.autoconnect no
nmcli con down "$OLD"; nmcli con up br-lab
$WAIT
nmcli con down br-lab; nmcli con delete br-lab-port br-lab
nmcli con mod "$OLD" connection.autoconnect yes; nmcli con up "$OLD"
echo "ROLLED BACK \$(date)" > /run/lab-net-rolledback
APPLY
chmod 700 /run/lab-net-apply.sh
nohup /run/lab-net-apply.sh >/run/lab-net-apply.log 2>&1 &
log "applying in background; confirm from the Mac within 90 s: ssh aero sudo touch /run/lab-net-ok"
