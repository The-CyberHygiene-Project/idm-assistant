#!/usr/bin/env bash
# install.sh STAGE (RUNS ON THE MAC): install the docs spike site (lab/docs-spike/hosts) from ISO 0.6.0, the iso5 way.
# A site has exactly one server, so the spike is its own site: iso5-docs (server, 1863 GiB sparse, size guard 50 GB)
# and iso5-dcli (client, 120 GiB, for row 36). Reuses the iso5 helpers already on aero in /tmp/iso2 (never deletes them).
#   prep      render the docs site, make the docs stick (aero:/data/libvirt/images/iso5-docs-stick.img), lab password
#   server    install iso5-docs FROM THE ISO (server entry), unlock the first boot with the escrowed passphrase
#   firstboot wait for the server first boot; detach the stick
#   export    export-client: secrets + the client token to the stick
#   client    install iso5-dcli FROM THE ISO + the stick
#   scan      OpenSCAP CUI (dc2 tailoring) on both PRISTINE hosts -> lab/docs-spike/scan-results/
#   adapter   lab adapter after the scan (chpadmin NOPASSWD sudo) + the idm_admin secret to ~/idm-lab-secrets/docs-idm_admin.json
#   root H C  run one root command C on H (docs|dcli) via the escrowed console password
#   mem       raise iso5-docs to 8 GiB / 4 vCPU (NextCloud + Wazuh manager + Suricata) and reboot (TPM unlock)
# Secrets move over pipes only (stick image -> expect), as in lab/iso5/prove.sh.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"
S=~/idm-lab-secrets; R=$S/docs-render; KEY=$S/iso2_chpadmin; DKEY=$S/iso5_diag_ecdsa
STICK=/data/libvirt/images/iso5-docs-stick.img; PYZ="$top/appliance/chp-site/dist/chp-site.pyz"
SRV=iso5-docs; SIP=192.168.100.53; SMAC=52:54:00:c4:05:53; CL=iso5-dcli; CIP=192.168.100.54; CMAC=52:54:00:c4:05:54
ISO=${ISO:-/var/lib/libvirt/images/chp-iso/0.6.0-rc2/cyberhygiene-lab-installer-el9.iso}; fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: ${2:-}"; fails=1; }
check() { if [[ $2 == "$3" ]]; then pass "$1"; else fail "$1" "got '$2', want '$3'"; fi; }
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
Vh() { local ip=$1; shift; ssh -o BatchMode=yes -J aero -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "chpadmin@$ip" "$@" 2>/dev/null; }
Rh() { local b; b=$(printf '%s' "$3" | base64 | tr -d '\n')
  A "sudo bash /tmp/iso2/stick.sh escrow $STICK $1.txt | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p' | expect /tmp/iso2/rootrun.exp $2 /tmp/iso2/iso2_chpadmin $b" \
    | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }
waitdone() {
  local s; for _ in $(seq 60); do if Vh "$2" true; then break; fi; sleep 10; done
  for _ in $(seq 80); do
    s=$(Rh "$1" "$2" "if [ -e /var/lib/chp/firstboot/$3 ]; then echo DONE; elif systemctl is-failed -q chp-server-firstboot chp-client-firstboot 2>/dev/null; then echo FAILED; else echo RUNNING; fi")
    [[ $s == DONE || $s == FAILED ]] && break; sleep 15
  done; echo "$s"; }
waitbase() { local b=""; for _ in $(seq 120); do
    b=$(Rh "$1" "$2" 'sed -n s/^BUILT_BY=//p /var/lib/chp/aide/baseline 2>/dev/null'); [[ -n $b ]] && break; sleep 30
  done; echo "${b:-NONE}"; }
detach_stick() { A "sudo virt-xml $1 --remove-device --disk path=$STICK --update >/dev/null 2>&1"; sleep 3
  check "$1: stick detached" "$(A "sudo virsh domblklist $1 --details" | grep -c "$STICK")" "0"; }
noleak() { grep -viE 'private key|passw|passphrase|secret|token|cred|[A-Za-z0-9+=]{20,}|=[^ ]{24,}'; }

case ${1:-} in
  prep)
    bash "$top/appliance/chp-site/build.sh" >/dev/null
    rm -rf "$R"; (umask 077; mkdir -p "$R")
    sed -e "s|@ADMIN_PUBKEY@|$(cut -d' ' -f1,2 "$KEY.pub")|" -e "s|@DIAG_PUBKEY@|$(cut -d' ' -f1,2 "$DKEY.pub")|" -e "s|@SECURITY_ADDONS@|yes|" "$here/site.conf.in" > "$R/site.conf"
    grep -v '^#' "$here/hosts" > "$R/hosts"
    out=$(python3 "$PYZ" validate --site "$R"); [[ $out == OK:* ]] && pass "chp-site validate (docs site)" || fail "validate" "$out"
    check "iso5 helpers present on aero" "$(A 'ls /tmp/iso2/stick.sh /tmp/iso2/install-iso.sh /tmp/iso2/size-guard.sh /tmp/iso2/unlock.sh /tmp/iso2/rootrun.exp /tmp/iso2/luks-send.exp /tmp/iso2/iso2_chpadmin | wc -l')" "7"
    A 'sudo rm -rf /tmp/iso2/docs-site'; scp -q -r "$R" aero:/tmp/iso2/docs-site
    out=$(A "sudo bash /tmp/iso2/stick.sh make /tmp/iso2/docs-site $STICK && sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./site.conf"* ]] && pass "docs stick made" || fail "stick" "$out" ;;
  server)
    out=$(A "sudo DISK_GB=1863 GUARD_GB=50 bash /tmp/iso2/install-iso.sh $SRV $SMAC 2 $STICK 1 $ISO '' --keep-stick")
    [[ $out == *"BOOTED: inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/server.ks"* && $out == *"INSTALLED and started $SRV"* ]] \
      && pass "$SRV: installed from the ISO" || { fail "$SRV: install" "$out"; exit 1; }
    out=$(A "sudo bash /tmp/iso2/unlock.sh $SRV $STICK $SRV")
    [[ $out == *"passphrase sent"* || $out == *"already unlocked"* ]] && pass "$SRV: first boot unlocked" || fail "$SRV: unlock" "$out" ;;
  firstboot)
    s=$(waitdone "$SRV" "$SIP" server.done); check "server first boot finished" "$s" "DONE"
    [[ $s == FAILED ]] && Rh "$SRV" "$SIP" 'journalctl -u chp-server-firstboot --no-pager | tail -25'
    check "server AIDE baseline built at first boot" "$(waitbase "$SRV" "$SIP")" "first-boot"
    check "fapolicyd no denials" "$(Rh "$SRV" "$SIP" 'ausearch --input-logs -m FANOTIFY </dev/null 2>/dev/null | grep -c type=FANOTIFY')" "0"
    check "SELinux no AVC since boot" "$(Rh "$SRV" "$SIP" 'ausearch --input-logs -m AVC -ts boot </dev/null 2>/dev/null | grep -c type=AVC')" "0"
    Rh "$SRV" "$SIP" 'findmnt -rno TARGET,SOURCE,OPTIONS /data /backup; vgs --noheadings -o vg_name,vg_size,vg_free'
    detach_stick "$SRV" ;;
  export)
    A "sudo virsh attach-disk $SRV $STICK sdz --targetbus usb --type disk --live >/dev/null"; sleep 5
    out=$(Rh "$SRV" "$SIP" 'chp-site export-client'); echo "$out" | noleak
    [[ $out == *"tokens moved to the stick: $CL"* ]] && pass "export-client moved the client token" || fail "export tokens" "$out"
    A "sudo virsh detach-disk $SRV sdz --live >/dev/null"; sleep 3
    check "nothing pending on the server" "$(Rh "$SRV" "$SIP" 'ls -A /root/chp-escrow-pending | wc -l')" "0" ;;
  client)
    out=$(A "sudo DISK_GB=120 bash /tmp/iso2/install-iso.sh $CL $CMAC 3 $STICK 1 $ISO '' --keep-stick")
    [[ $out == *"BOOTED: inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/client.ks"* && $out == *"INSTALLED and started $CL"* ]] \
      && pass "$CL: installed from the ISO" || { fail "$CL: install" "$out"; exit 1; }
    out=$(A "sudo bash /tmp/iso2/unlock.sh $CL $STICK $CL")
    [[ $out == *"passphrase sent"* || $out == *"already unlocked"* ]] && pass "$CL: first boot unlocked" || fail "$CL: unlock" "$out"
    s=$(waitdone "$CL" "$CIP" client.done); check "$CL: client first boot finished" "$s" "DONE"
    [[ $s == FAILED ]] && Rh "$CL" "$CIP" 'journalctl -u chp-client-firstboot --no-pager | tail -25'
    check "$CL: AIDE baseline built at first boot" "$(waitbase "$CL" "$CIP")" "first-boot"
    out=$(Rh "$CL" "$CIP" 'chp-site aide-pin'); [[ $out == pinned:* ]] && pass "$CL: aide-pin" || fail "$CL: aide-pin" "$out"
    detach_stick "$CL"
    check "$CL: kanidm-unixd online" "$(Rh "$CL" "$CIP" 'kanidm-unix status 2>/dev/null | grep -c "Kanidm: online"')" "1" ;;
  scan)
    out=$here/scan-results; mkdir -p "$out"
    DS=/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml; PROF=xccdf_net.cyberinabox_profile_cui_dc2
    tb=$(base64 < "$top/lab/kickstart/dc2-reference/dc2-cui-tailoring.xml" | tr -d '\n')
    for v in "$SRV $SIP" "$CL $CIP"; do
      read -r vm ip <<<"$v"
      rc=$(Rh "$vm" "$ip" "install -d -m 0700 /root/chp-scan && echo $tb | base64 -d > /root/chp-scan/tailoring.xml && oscap xccdf eval --tailoring-file /root/chp-scan/tailoring.xml --profile $PROF --results /root/chp-scan/$vm.xml $DS >/dev/null 2>&1; echo oscap-rc=\$?; install -m 0644 -o chpadmin /root/chp-scan/$vm.xml /home/chpadmin/$vm.xml")
      [[ $rc == oscap-rc=0 || $rc == oscap-rc=2 ]] && pass "$vm: oscap evaluated ($rc)" || fail "$vm: oscap" "$rc"
      Vh "$ip" "cat ~/$vm.xml && rm -f ~/$vm.xml" > "$out/$vm.xml"
      echo "$vm: $(grep -c '<result>fail</result>' "$out/$vm.xml") failing, $(grep -c '<result>pass</result>' "$out/$vm.xml") passing"
    done
    check "scan results hold no secrets" "$(grep -lE 'LUKS_PASSPHRASE|ROOT_CONSOLE_PASSWORD|GRUB_PASSWORD|PRIVATE KEY' "$out"/*.xml | wc -l | tr -d ' ')" "0" ;;
  adapter)
    for v in "$SRV $SIP" "$CL $CIP"; do
      read -r vm ip <<<"$v"
      [[ -f $here/scan-results/$vm.xml || -f $here/scan-results/$vm.xml.xz ]] || { fail "$vm: no CUI scan yet" "run 'install.sh scan' first"; exit 1; }
      check "$vm: lab adapter sudo rule" "$(Rh "$vm" "$ip" "printf 'chpadmin ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/.99-lab-adapter && chmod 0440 /etc/sudoers.d/.99-lab-adapter && visudo -cqf /etc/sudoers.d/.99-lab-adapter && mv /etc/sudoers.d/.99-lab-adapter /etc/sudoers.d/99-lab-adapter && echo installed")" "installed"
    done
    A "sudo bash /tmp/iso2/stick.sh escrow $STICK $SRV-server.txt | sed -n 's/^KANIDM_ADMINS_JSON=//p' | python3 -c 'import base64,json,sys; print(json.loads(base64.b64decode(sys.stdin.read()))[\"idm_admin\"])'" \
      | python3 -c 'import json,os,sys
pw=sys.stdin.read().strip(); assert pw, "no idm_admin password"
p=os.path.expanduser("~/idm-lab-secrets/docs-idm_admin.json"); fd=os.open(p, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)
os.write(fd, json.dumps({"password": pw}).encode()); os.close(fd)'
    check "idm_admin secret file (0600)" "$(stat -f %Lp ~/idm-lab-secrets/docs-idm_admin.json)" "600"
    for a in docs dcli; do check "$a: sudo works" "$(ssh -F "$here/ssh_config" -n $a 'sudo -n true && echo ok' 2>/dev/null)" "ok"; done ;;
  mem)
    A "sudo virsh shutdown $SRV >/dev/null"; for _ in $(seq 60); do [[ $(A "sudo virsh domstate $SRV") == "shut off" ]] && break; sleep 5; done
    A "sudo virsh setmaxmem $SRV 8G --config && sudo virsh setmem $SRV 8G --config && sudo virsh setvcpus $SRV 4 --config --maximum && sudo virsh setvcpus $SRV 4 --config && sudo virsh start $SRV" >/dev/null
    ok=no; for _ in $(seq 40); do if Vh "$SIP" true; then ok=yes; break; fi; sleep 10; done; check "$SRV: back up (TPM unlock)" "$ok" "yes"
    check "$SRV: 4 vCPU" "$(Vh "$SIP" nproc)" "4" ;;
  root)   # root VM-or-'docs'|'dcli' CMD: one root command through the escrowed console password (before the adapter)
    case $2 in docs|$SRV) Rh "$SRV" "$SIP" "$3" ;; dcli|$CL) Rh "$CL" "$CIP" "$3" ;; esac ;;
  *) echo "usage: $0 prep|server|firstboot|export|client|scan|adapter|mem|root"; exit 2 ;;
esac
exit $fails
