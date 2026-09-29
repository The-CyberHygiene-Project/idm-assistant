#!/usr/bin/env bash
# readonly-proof.sh HOST [--user U]  (RUNS ON THE MAC): prove idm-collect changes nothing on HOST.
# Before/after: sha256 of identity config files + the systemd unit list; one collector run as `diag` in between;
# then files newer than a marker and leftover collector temp dirs. Prints a report; cleans up after itself.
set -Eeuo pipefail
host=${1:?usage: readonly-proof.sh HOST [--user U]}; shift
snap() {   # $1 = before|after
  ssh -n -o BatchMode=yes "$host" "sudo bash -c 'shopt -s nullglob
    { sha256sum /etc/kanidm/* /etc/nsswitch.conf /etc/authselect/* /etc/pam.d/* /etc/pki/kanidm/* \
        /etc/pki/ca-trust/source/anchors/* /etc/idm-collect/* /var/lib/ssh-ca/*/* /etc/ssh/sshd_config.d/* 2>/dev/null
      systemctl list-units --all --plain --no-legend | sort; } > /root/ro-$1'"
}
ssh -n -o BatchMode=yes "$host" 'sudo touch /root/ro-marker'
snap before
sleep 1
ssh -n -o BatchMode=yes "$host-diag" sudo -n /usr/sbin/idm-collect "$@" >/dev/null
snap after
ssh -n -o BatchMode=yes "$host" "sudo bash -c '
  echo \"== $host: state diff lines: \$(diff /root/ro-before /root/ro-after | grep -c \"^[<>]\")\"
  diff /root/ro-before /root/ro-after || true
  echo \"files newer than marker (excluding /proc,/sys,/run,journal,audit,lastlog, unixd cache):\"
  find /etc /var/lib /root /home /usr/local -xdev -newer /root/ro-marker -type f 2>/dev/null \
    | grep -vE \"^/var/lib/(chrony|systemd/timers|rsyslog|fapolicyd|kanidm-unixd)|^/var/log|^/root/ro-\" || true
  echo \"leftover temp dirs: \$(ls -d /tmp/idm-collect.* 2>/dev/null | wc -l)\"
  rm -f /root/ro-before /root/ro-after /root/ro-marker'"
