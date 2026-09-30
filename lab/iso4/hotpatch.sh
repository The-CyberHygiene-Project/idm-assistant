#!/usr/bin/env bash
# hotpatch.sh VM IP (RUNS ON THE MAC): LAB-ONLY. Load the FIXED chp_kanidm policy (from the newest unsigned build, staged at
# aero:/tmp/iso2/chp_kanidm.pp) into an installed iso4 VM, so the rest of the proof can find further bugs before the
# re-signed repo. semodule rebuilds the whole policy (> 3 min here), so it runs in the background and is polled.
# The final proof re-installs everything from the signed repo; this helper is then not used.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; eval "$(sed -n '/^S=~/,/^enrolled_checks/p' "$here/prove.sh" | sed '$d')"
VM=$1 IP=$2
ssh aero "cd /tmp && rm -rf hp && mkdir hp && cd hp && rpm2cpio \$(ls -1 /data/chp-release/built/chp-identity-client-*.rpm | sort -V | tail -1) | cpio -id --quiet ./usr/share/selinux/packages/chp_kanidm.pp && cp usr/share/selinux/packages/chp_kanidm.pp /tmp/iso2/ && rm -rf /tmp/hp" 2>/dev/null
A "cat /tmp/iso2/chp_kanidm.pp" | Vh "$IP" 'cat > ~/chp_kanidm.pp'
Rh "$VM" "$IP" 'rm -f /root/semodule.log; cp /home/chpadmin/chp_kanidm.pp /root/; rm -f /home/chpadmin/chp_kanidm.pp; (setsid nohup bash -c "semodule -i /root/chp_kanidm.pp > /root/semodule.log 2>&1; echo rc=\$? >> /root/semodule.log" >/dev/null 2>&1 &)' >/dev/null
for _ in $(seq 40); do sleep 15; r=$(Rh "$VM" "$IP" 'cat /root/semodule.log 2>/dev/null'); [[ $r == *rc=* ]] && break; done
echo "$VM semodule: $r"
Rh "$VM" "$IP" 'rm -f /root/chp_kanidm.pp /root/semodule.log; restorecon -R /run/kanidm-unixd; systemctl restart kanidm-unixd kanidm-unixd-tasks; sleep 3; ls -Zd /run/kanidm-unixd /run/kanidm-unixd/sock | cut -d" " -f1 | tr "\n" " "; kanidm-unix status | grep -c "Kanidm: online"'
