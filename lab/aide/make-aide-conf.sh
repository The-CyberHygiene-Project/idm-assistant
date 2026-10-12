#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# make-aide-conf.sh (RUNS ON THE MAC): produce appliance/rpm/chp-integrity/aide.conf from the Rocky 9.8 DVD's stock
# aide.conf + the SSG's OWN remediation for the 8 AIDE rules (so the scanner recognizes the result) + the CHP block.
# Uses iso5-cli2 (lab adapter: chpadmin NOPASSWD) and reverts it to golden at the end, whatever happened.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; F="$top/lab/iso5/ssh_config"
C() { ssh -F "$F" -n -o ConnectTimeout=10 client2 "$@"; }
trap 'ssh -n aero "sudo virsh snapshot-revert iso5-cli2 golden --running" >/dev/null 2>&1 || true' EXIT
DS=/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml; PROF=xccdf_net.cyberinabox_profile_cui_dc2
scp -q -F "$F" "$top/lab/kickstart/dc2-reference/dc2-cui-tailoring.xml" client2:/tmp/tailoring.xml   # selects the 8 rules (Step 2)
RULES="package_aide_installed aide_build_database aide_use_fips_hashes aide_check_audit_tools aide_verify_acls aide_verify_ext_attributes"
# 1. aide from the DVD (served by aero), the stock config
C 'sudo dnf -y -q --disablerepo="*" --repofrompath=dvd,http://192.168.100.1:8080/dvd/AppStream --repofrompath=dvdb,http://192.168.100.1:8080/dvd/BaseOS --setopt=dvd.gpgcheck=1 --setopt=dvdb.gpgcheck=1 install aide'
C 'sudo cp /etc/aide.conf /tmp/aide.conf.stock'
# 2. the SSG's own shell remediation for each rule, taken from the rule in the data stream (lab/aide/ssg-fix.py):
#    `oscap xccdf generate fix --tailoring-file` left the AIDE rules out (Plan A Task 9 ruling).
scp -q -F "$F" "$here/ssg-fix.py" client2:/tmp/ssg-fix.py
for r in $RULES; do
  C "python3 /tmp/ssg-fix.py $DS $r > /tmp/fix-$r.sh && sudo bash /tmp/fix-$r.sh >/tmp/fix-$r.out 2>&1; echo $r: fix-exit \$? \$(wc -l < /tmp/fix-$r.sh) lines"
done
# 3. CHP additions, inserted before the stock catch-all '/etc    PERMS' line
scp -q -F "$F" "$top/appliance/rpm/chp-integrity/chp-additions.conf" client2:/tmp/chp-additions.conf
C 'sudo python3 - <<EOF
p = "/etc/aide.conf"; s = open(p).read(); add = open("/tmp/chp-additions.conf").read()
lines = s.split("\n"); i = next(n for n, l in enumerate(lines) if l.split() == ["/etc", "PERMS"])
open(p, "w").write("\n".join(lines[:i] + add.rstrip("\n").split("\n") + lines[i:]))
EOF'
C 'sudo aide --config-check && echo CONFIG-OK'
C 'sudo cat /etc/aide.conf' > "$top/appliance/rpm/chp-integrity/aide.conf"
C 'sudo diff -u /tmp/aide.conf.stock /etc/aide.conf' > "$here/aide.conf.diff" || true
echo "wrote appliance/rpm/chp-integrity/aide.conf and lab/aide/aide.conf.diff (review the diff)"
