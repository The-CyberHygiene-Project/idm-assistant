#!/usr/bin/env bash
# prove.sh STAGE (RUNS ON THE MAC): ISO Plan 3a proof of the identity-server role on aero, one stage at a time.
#   prep       render the iso3 site, lab kickstarts (+ embedded chp-site), push helpers, make the stick
#   server     install iso3-srv from repo 0.3.0; unlock the first boot with the escrowed passphrase
#   firstboot  wait for the unattended server first boot, then check every part of it
#   reboot     reboot WITHOUT the passphrase: the TPM (bound on first boot) must unlock the disk
#   export     attach the stick; chp-site export-client moves the pending secrets offline; monitor goes quiet
#   renew      Review Focus 5: an ALREADY-EXPIRED Kanidm certificate is replaced by the renewal unit (ACME fallback)
#   cleanup    remove the iso3 VM, stick, helpers, key copy; shred the Mac render dir
# Every check prints PASS/FAIL; the stage exits 1 on any FAIL. Secrets stay on aero (piped from the stick image).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; iso2="$top/lab/iso2"
R=~/idm-lab-secrets/iso3-render; KEY=~/idm-lab-secrets/iso2_chpadmin; STICK=/data/libvirt/images/iso3-stick.img
PYZ="$top/appliance/chp-site/dist/chp-site.pyz"; IP=192.168.100.30; D=iso3.lab.test; VM=iso3-srv; fails=0
export CHP_REPO=0.3.1
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: ${2:-}"; fails=1; }
check() { if [[ $2 == "$3" ]]; then pass "$1"; else fail "$1" "got '$2', want '$3'"; fi; }
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
V() { ssh -o BatchMode=yes -J aero -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 "chpadmin@$IP" "$@" 2>/dev/null; }
# Root on the VM: su with the escrowed root console password (stick -> pipe on aero); the command travels base64-encoded.
Rt() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n')
  A "sudo bash /tmp/iso2/stick.sh escrow $STICK $VM.txt | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p' | expect /tmp/iso2/rootrun.exp $IP /tmp/iso2/iso2_chpadmin $b" | tr -d '\r'; }
Rv() { Rt "$1" | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }   # output only

case ${1:-} in
  prep)
    bash "$top/appliance/chp-site/build.sh" >/dev/null
    rm -rf "$R"; (umask 077; mkdir -p "$R")
    sed "s|@ADMIN_PUBKEY@|$(cut -d' ' -f1,2 "$KEY.pub")|" "$here/site.conf.in" > "$R/site.conf"; cp "$here/hosts" "$R/hosts"
    out=$(python3 "$PYZ" validate --site "$R"); [[ $out == OK:* ]] && pass "chp-site validate (iso3 site)" || fail "validate" "$out"
    A 'rm -rf /tmp/iso2 && mkdir -p -m 700 /tmp/iso2'
    for r in server client; do
      { echo "%pre --interpreter=/usr/bin/bash --erroronfail --log=/tmp/chp-lab-pre.log"
        echo "python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' > /tmp/chp-site.pyz 2>/dev/console <<'CHP_PYZ_B64'"
        base64 < "$PYZ" | fold -w 76; echo "CHP_PYZ_B64"; echo "%end"; echo; cat "$top/appliance/kickstart/$r.ks"; } > "$R/../iso3-$r.ks"
      scp -q "$R/../iso3-$r.ks" "aero:/tmp/iso2/$r.ks"; rm -f "$R/../iso3-$r.ks"
    done
    scp -q "$PYZ" "$iso2/stick.sh" "$iso2/install.sh" "$iso2/unlock.sh" "$iso2/luks-send.exp" "$here/rootrun.exp" "$KEY" aero:/tmp/iso2/
    scp -q -r "$R" aero:/tmp/iso2/site
    out=$(A "sudo bash /tmp/iso2/stick.sh make /tmp/iso2/site $STICK && sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./site.conf"* ]] && pass "stick image made" || fail "stick" "$out" ;;
  server)
    out=$(A "sudo CHP_REPO=$CHP_REPO bash /tmp/iso2/install.sh $VM 52:54:00:c4:03:30 server $STICK 1")
    [[ $out == *"INSTALLED and started $VM"* ]] && pass "$VM: install from repo $CHP_REPO finished" || { fail "$VM: install" "$out"; exit 1; }
    out=$(A "sudo bash /tmp/iso2/unlock.sh $VM $STICK $VM")
    [[ $out == *"passphrase sent"* || $out == *"already unlocked"* ]] && pass "$VM: first boot unlocked with the escrowed passphrase" || fail "$VM: unlock" "$out" ;;
  firstboot)
    for _ in $(seq 60); do if V true; then break; fi; sleep 10; done
    for _ in $(seq 80); do s=$(Rv 'if [ -e /var/lib/chp/firstboot/server.done ]; then echo DONE; elif systemctl is-failed -q chp-server-firstboot; then echo FAILED; else echo RUNNING; fi'); [[ $s == DONE || $s == FAILED ]] && break; sleep 15; done
    check "server first boot finished" "$s" "DONE"
    [[ $s == FAILED ]] && Rv 'journalctl -u chp-server-firstboot --no-pager | tail -20'
    check "every first-boot step marked done" "$(Rv 'ls /var/lib/chp/firstboot | tr "\n" " "')" "bind.done collector.done common.done kanidm-cert.done kanidmd.done recover.done server.done ssh-ca.done step-ca.done "
    check "one-time bind key gone" "$(Rv 'test -e /root/.chp-bind.key && echo KEY || echo NOKEY')" "NOKEY"
    check "LUKS: two keyslots (escrow passphrase + TPM), one clevis token" \
      "$(Rv 'd=$(lsblk -rpno NAME,FSTYPE | awk "\$2==\"crypto_LUKS\"{print \$1}"); cryptsetup luksDump $d | awk "/^Keyslots:/{k=1} /^Tokens:/{k=0; t=1} /^Digests:/{t=0} k && /^  [0-9]+: luks2/{n++} t && /clevis/{c++} END{print n\" \"c}"')" "2 1"
    check "installer kickstart copies shredded" "$(Rv 'ls /root/original-ks.cfg /root/anaconda-ks.cfg 2>/dev/null | wc -l')" "0"
    check "DNS: idm and ca resolve to the server" "$(V "dig +short @$IP idm.$D; dig +short @$IP ca.$D" | tr '\n' ' ')" "$IP $IP "
    check "step-ca healthy (intermediate only)" "$(Rv "step-cli ca health --ca-url https://ca.$D:9000 --root /etc/pki/ca-trust/source/anchors/chp-root.crt")" "ok"
    check "no root CA key anywhere under /etc/step-ca" "$(Rv 'find /etc/step-ca -name root_ca_key | wc -l')" "0"
    check "Kanidm /status over TLS verified by the site root" "$(V "curl -fsS --cacert /etc/pki/ca-trust/source/anchors/chp-root.crt https://idm.$D/status")" "true"
    check "renewal timer active" "$(Rv 'systemctl is-active cert-renew-kanidm.timer')" "active"
    check "collector reports no errors (read-only token, collect.conf)" "$(Rv 'idm-collect --user admin | python3 -c "import json,sys; print(json.load(sys.stdin)[\"errors\"])"')" "[]"
    check "three recovery secrets pending on the server" "$(Rv 'ls /root/chp-escrow-pending | tr "\n" " "')" "kanidm-admins.json root_ca_key step-ca-password "
    al=$(Rv 'for c in /usr/lib/chp/monitor.d/*; do "$c"; done | grep ^ALERT')
    [[ $(grep -c . <<<"$al") == 1 && $al == *"recovery secrets still on the server"* ]] && pass "monitor alerts only: secrets still on the server" || fail "monitor alerts" "$al"
    check "fapolicyd: no denials" "$(Rv 'ausearch --input-logs -m FANOTIFY </dev/null 2>/dev/null | grep -c type=FANOTIFY')" "0"
    check "SELinux: no AVC since boot" "$(Rv 'ausearch --input-logs -m AVC -ts boot </dev/null 2>/dev/null | grep -c type=AVC')" "0" ;;
  reboot)
    A "sudo virsh reboot $VM >/dev/null"; sleep 20
    ok=no; for _ in $(seq 30); do if V true; then ok=yes; break; fi; sleep 10; done
    check "after reboot the disk unlocked by the TPM (SSH back, no passphrase sent)" "$ok" "yes"
    check "no LUKS prompt was answered this boot" "$(A "sudo tail -c 20000 /var/log/libvirt/qemu/$VM-install.log | grep -c 'passphrase sent'")" "0" ;;
  export)
    A "sudo virsh attach-disk $VM $STICK sdz --targetbus usb --type disk --live >/dev/null"; sleep 5
    out=$(Rv 'chp-site export-client')
    [[ $out == *"moved to the stick: kanidm-admins.json, root_ca_key, step-ca-password"* ]] && pass "export-client moved the three secrets to the stick" || fail "export-client" "$out"
    A "sudo virsh detach-disk $VM sdz --live >/dev/null"; sleep 3
    out=$(A "sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./client.conf"* && $out == *"./escrow/$VM-server.txt"* ]] && pass "stick holds client.conf + escrow/$VM-server.txt" || fail "stick contents" "$out"
    check "no recovery secrets left on the server" "$(Rv 'ls -A /root/chp-escrow-pending | wc -l')" "0"
    check "monitor is quiet" "$(Rv '/usr/libexec/chp/monitor >/dev/null; echo $?')" "0"
    check "USBGuard: the stick was allowed only temporarily and blocked again" "$(Rv 'journalctl -t chp-site --no-pager -o cat | grep -c "USBGuard: blocked device"')" "1"
    check "step-ca still issues without the root key (ACME re-issue of idm)" "$(Rv '/usr/libexec/chp/cert-renew-kanidm --issue >/dev/null 2>&1 && openssl x509 -in /etc/pki/kanidm/chain.pem -noout -checkend 3600 >/dev/null && echo VALID')" "VALID" ;;
  renew)
    Rv "systemctl stop cert-renew-kanidm.timer; export STEPPATH=/root/.step; firewall-cmd -q --add-service=http; step-cli ca certificate idm.$D /etc/pki/kanidm/chain.pem /etc/pki/kanidm/key.pem --provisioner acme --kty EC --crv P-384 --not-after 5m --force >/dev/null 2>&1; firewall-cmd -q --remove-service=http; chmod 600 /etc/pki/kanidm/*.pem; systemctl restart kanidmd" >/dev/null
    check "short (5 min) certificate in place" "$(Rv 'openssl x509 -in /etc/pki/kanidm/chain.pem -noout -checkend 600 >/dev/null && echo LONG || echo SHORT')" "SHORT"
    sleep 360
    check "it has now expired" "$(Rv 'openssl x509 -in /etc/pki/kanidm/chain.pem -noout -checkend 0 >/dev/null && echo VALID || echo EXPIRED')" "EXPIRED"
    check "renewal unit replaces the EXPIRED certificate (ACME fallback)" "$(Rv 'systemctl start cert-renew-kanidm.service; openssl x509 -in /etc/pki/kanidm/chain.pem -noout -checkend 3600 >/dev/null && echo VALID')" "VALID"
    check "Kanidm serves the new certificate" "$(V "echo | openssl s_client -connect $IP:443 -servername idm.$D 2>/dev/null | openssl x509 -noout -checkend 3600 >/dev/null && echo VALID")" "VALID"
    Rv 'systemctl start cert-renew-kanidm.timer' >/dev/null ;;
  cleanup)
    A "sudo virsh destroy $VM >/dev/null 2>&1; sudo virsh undefine $VM --nvram >/dev/null 2>&1; sudo rm -f /data/libvirt/images/$VM-[0-9].qcow2 $STICK; sudo shred -u /tmp/iso2/iso2_chpadmin 2>/dev/null; sudo rm -rf /tmp/iso2"
    rm -P "$R"/* 2>/dev/null; rm -rf "$R"; pass "cleanup" ;;
  *) echo "usage: prove.sh prep|server|firstboot|reboot|export|renew|cleanup"; exit 2 ;;
esac
exit $fails
