#!/usr/bin/env bash
# spike.sh STAGE (RUNS ON THE MAC, after install.sh scan + adapter): drive the NextCloud spike on iso5-docs.
#   dvd-on | dvd-off   attach the Rocky 9.8 DVD (aero:/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso) read-only as a CD and
#                      mount it on /mnt/dvd | unmount and detach it (the server's only package source; no network repo)
#   push               copy setup.sh, the egress rules and the spike RPM to /root/spike on the server
#   run STAGE          sudo bash /root/spike/setup.sh STAGE (packages|db|install|config|web)
#   egress             load pkg/nextcloud-egress.nft (SERVER_IP filled in) through stdin
#   denials [SINCE]    AVC + fapolicyd (FANOTIFY) records since SINCE (ausearch time, default: boot), one line each
#   sh CMD             sudo bash -c CMD on the server
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; F="$here/ssh_config"
SRV=iso5-docs; SIP=192.168.100.53; DVD=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso
RPM=/data/chp-release/built/spike/nextcloud-chp-35.0.3-0.spike5.el9.noarch.rpm
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
X() { ssh -F "$F" -o BatchMode=yes docs "$@"; }
case ${1:-} in
  dvd-on)
    A "sudo virsh attach-disk $SRV $DVD vdz --type disk --mode readonly --targetbus virtio --live >/dev/null"   # SATA cannot hot-plug; USBGuard blocks a USB disk (correctly)
    sleep 5; X 'd=$(sudo blkid -t TYPE=iso9660 -o device | head -1); sudo mkdir -p /mnt/dvd && { mountpoint -q /mnt/dvd || sudo mount -o ro "$d" /mnt/dvd; } && ls /mnt/dvd && head -3 /mnt/dvd/media.repo' ;;
  dvd-off)
    X 'sudo umount /mnt/dvd 2>/dev/null; true'; A "sudo virsh detach-disk $SRV vdz --live >/dev/null"
    A "sudo virsh domblklist $SRV" ;;
  push)
    A "cat $RPM" | X 'cat > ~/nc.rpm'
    X 'cat > ~/setup.sh' < "$here/setup.sh"
    X 'sudo install -d -m 0700 /root/spike && sudo install -m 0600 ~/setup.sh /root/spike/setup.sh && sudo install -m 0600 ~/nc.rpm /root/spike/nextcloud-chp-35.0.3-0.spike5.el9.noarch.rpm && rm -f ~/setup.sh ~/nc.rpm && sudo sh -c "sha256sum /root/spike/*"' ;;
  run) X "sudo bash /root/spike/setup.sh $2" ;;
  egress) sed "s/@SERVER_IP@/$SIP/" "$here/pkg/nextcloud-egress.nft" | X 'sudo bash /root/spike/setup.sh egress' ;;
  denials)
    X "sudo ausearch --input-logs -m AVC,USER_AVC,FANOTIFY -ts ${2:-boot} </dev/null 2>/dev/null | grep -E '^type=(AVC|USER_AVC|FANOTIFY)' | sed -E 's/msg=audit\\(([0-9.]+):[0-9]+\\)/t=\\1/'" ;;
  sh) X "sudo bash -c $(printf '%q' "$2")" ;;
  *) echo "usage: $0 dvd-on|dvd-off|push|run STAGE|egress|denials [SINCE]|sh CMD"; exit 2 ;;
esac
