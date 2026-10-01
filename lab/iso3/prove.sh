#!/usr/bin/env bash
# prove.sh STAGE (RUNS ON THE MAC): ISO Plan 3a/3b proof of the identity-server role on aero, one stage at a time.
#   prep       render the iso3 site, lab kickstarts (+ embedded chp-site), push helpers, make the stick
#   server     install iso3-srv from repo 0.3.0; unlock the first boot with the escrowed passphrase
#   firstboot  wait for the unattended server first boot, then check every part of it
#   reboot     reboot WITHOUT the passphrase: the TPM (bound on first boot) must unlock the disk
#   export     attach the stick; chp-site export-client moves the pending secrets offline; monitor goes quiet
#   ops        ISO Plan 3b: chp-site onboard / revoke / unexpire on the installed server (after export)
#   renew      Review Focus 5: an ALREADY-EXPIRED Kanidm certificate is replaced by the renewal unit (ACME fallback)
#   cleanup    remove the iso3 VM, stick, helpers, key copy; shred the Mac render dir
# Every check prints PASS/FAIL; the stage exits 1 on any FAIL. Secrets stay on aero (piped from the stick image).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; iso2="$top/lab/iso2"
R=~/idm-lab-secrets/iso3-render; KEY=~/idm-lab-secrets/iso2_chpadmin; STICK=/data/libvirt/images/iso3-stick.img
PYZ="$top/appliance/chp-site/dist/chp-site.pyz"; IP=192.168.100.30; D=iso3.lab.test; VM=iso3-srv; fails=0
export CHP_REPO=0.3.3
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
# Root with a SECOND secret from the stick (a KANIDM_ADMINS_JSON field, e.g. idm_admin) as "$CHP_SECRET" (lab/iso3/rs.sh).
Rs() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n'); A "sudo bash /tmp/iso2/rs.sh $STICK $VM $IP $2 $b" | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }

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
    scp -q "$PYZ" "$iso2/stick.sh" "$iso2/install.sh" "$iso2/unlock.sh" "$iso2/luks-send.exp" "$here/rootrun.exp" "$here/rs.sh" "$KEY" aero:/tmp/iso2/
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
    check "every first-boot step marked done" "$(Rv 'ls /var/lib/chp/firstboot | tr "\n" " "')" "bind.done cache-key.done collector.done common.done kanidm-cert.done kanidmd.done recover.done server.done ssh-ca.done step-ca.done "
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
    check "after reboot the disk unlocked by the TPM (SSH back; this stage never sends the passphrase)" "$ok" "yes" ;;
  export)
    A "sudo virsh attach-disk $VM $STICK sdz --targetbus usb --type disk --live >/dev/null"; sleep 5
    out=$(Rv 'chp-site export-client')
    [[ $out == *"moved to the stick: kanidm-admins.json, root_ca_key, step-ca-password"* ]] && pass "export-client moved the three secrets to the stick" || fail "export-client" "$out"
    A "sudo virsh detach-disk $VM sdz --live >/dev/null"; sleep 3
    out=$(A "sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./client.conf"* && $out == *"./escrow/$VM-server.txt"* ]] && pass "stick holds client.conf + escrow/$VM-server.txt" || fail "stick contents" "$out"
    check "client.conf on the stick pins the server's cache key (CACHE_PUBKEY)" \
      "$(A "sudo bash /tmp/iso2/stick.sh escrow $STICK ../client.conf" | sed -n 's/^CACHE_PUBKEY=//p' | cut -d' ' -f1,2)" "$(Rv 'cut -d" " -f1,2 /var/lib/chp/cache-key/id_ecdsa.pub')"
    check "cache key: private half 600 root, directory 700" "$(Rv 'stat -c "%a %U" /var/lib/chp/cache-key /var/lib/chp/cache-key/id_ecdsa | tr "\n" " "')" "700 root 600 root "
    check "no recovery secrets left on the server" "$(Rv 'ls -A /root/chp-escrow-pending | wc -l')" "0"
    check "monitor is quiet" "$(Rv '/usr/libexec/chp/monitor >/dev/null; echo $?')" "0"
    check "USBGuard: the stick was allowed only temporarily and blocked again" "$(Rv 'journalctl -t chp-site --no-pager -o cat | grep -c "USBGuard: blocked device"')" "1"
    check "step-ca still issues without the root key (ACME re-issue of idm)" "$(Rv '/usr/libexec/chp/cert-renew-kanidm --issue >/dev/null 2>&1 && openssl x509 -in /etc/pki/kanidm/chain.pem -noout -checkend 3600 >/dev/null && echo VALID')" "VALID" ;;
  ops)
    # ISO Plan 3b. The idm_admin password is on the stick only (after export): it reaches the VM over pipes (Rs).
    # Re-runnable: a fresh user per run (OPS_USER, default opsHHMM); audit/journal checks count what THIS run added.
    U=${OPS_USER:-ops$(date +%H%M)}; UK=~/idm-lab-secrets/iso3_ops_ecdsa
    [[ -f $UK ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C ops@iso3 -f "$UK"
    items() { grep -E '^ *\[[x ]\] ' <<<"$1" | sed -E 's/^ *//; s/  \(.*$//' | paste -sd'|' -; }
    V 'umask 077; mkdir -p ~/chp-lab; cat > ~/chp-lab/user.pub' < "$UK.pub"
    sed 's#/tmp/srv1/#/root/chp-lab/#g' "$top/lab/srv1/enrol-user.exp" | V 'cat > ~/chp-lab/enrol-user.exp'
    V 'cat > ~/chp-lab/totp.py' < "$top/lab/srv1/totp.py"
    Rv 'install -d -m 0700 /root/chp-lab && cp /home/chpadmin/chp-lab/* /root/chp-lab/ && chmod 600 /root/chp-lab/* && rm -rf /home/chpadmin/chp-lab' >/dev/null
    j0=$(Rv "journalctl -t chp-site --no-pager -o cat | grep -c '^chp-site unexpire user=\"$U\"'")
    out=$(Rv "kanidm logout -D idm_admin >/dev/null 2>&1; chp-site onboard $U; echo rc=\$?")
    [[ $out == *'run `kanidm login -D idm_admin` first'* && $out == *rc=2* ]] && pass "no Kanidm session: onboard refuses with 'log in first'" || fail "no-session refusal" "$out"
    check "idm_admin login (password from the stick, over pipes only)" "$(Rs 'printf "%s\n" "$CHP_SECRET" | expect /usr/libexec/chp/kanidm-login.exp idm_admin >/dev/null && echo LOGGEDIN' idm_admin)" "LOGGEDIN"
    out=$(Rv "chp-site onboard $U --display 'Ops Test User' --ssh-key /root/chp-lab/user.pub")
    check "onboard $U (new): checklist" "$(items "$out")" '[x] account|[x] POSIX enabled|[ ] primary credential|[ ] POSIX (unix) password|[x] SSH key registered|[x] SSH certificate issued|[ ] Google Authenticator'
    [[ $out != *use-reset-token* && $out != *token=* ]] && pass "reset token not shown (file path only)" || fail "token on screen" "(redacted)"
    check "onboard files: dir 700, token 600" "$(Rv "stat -c %a /root/chp-onboard /root/chp-onboard/$U.reset-token.txt | tr '\n' ' '")" "700 600 "
    # Lab stand-in for the user; the REPL log is kept root-only and shown (token redacted) only if enrolment fails.
    out=$(Rv "cd /root/chp-lab && sed 's/^log_user 0/log_user 1/' enrol-user.exp > e.exp && tok=\$(sed -n 's/.*use-reset-token \([A-Za-z0-9-]*\).*/\1/p' /root/chp-onboard/$U.reset-token.txt | head -1) && pw=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))') && upw=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))') && if printf '%s\n%s\n%s\ntotp\n' \"\$tok\" \"\$pw\" \"\$upw\" | expect e.exp > e.log 2>&1; then echo ENROLLED; else sed \"s/\$tok/<TOKEN>/g\" e.log | tr -d '\r' | grep -viE 'secret|otpauth|^[█▀▄ ]*\$' | tail -8; fi; rm -f e.exp; shred -u e.log")
    check "lab stand-in: $U used the reset token (password + TOTP + unix password)" "$out" "ENROLLED"
    m1=$(Rv "stat -c %Y /root/chp-onboard/$U.reset-token.txt")
    out=$(Rv "chp-site onboard $U")
    check "onboard $U (re-run): everything done but GA" "$(items "$out")" '[x] account|[x] POSIX enabled|[x] primary credential|[x] POSIX (unix) password|[x] SSH key registered|[x] SSH certificate issued|[ ] Google Authenticator'
    check "re-run wrote no new reset token" "$(Rv "stat -c %Y /root/chp-onboard/$U.reset-token.txt")" "$m1"
    check "certificate principals $U + $U@idm.$D" "$(Rv "ssh-keygen -L -f /var/lib/ssh-ca/issued/$U-cert.pub | sed -n '/Principals:/,/Critical/p' | grep -v : | tr -d ' ' | tr '\n' ' '")" "$U $U@idm.$D "
    out=$(Rv 'chp-site revoke idm_admin; echo rc=$?'); [[ $out == *refusing*built-in* && $out == *rc=2* ]] && pass "revoke idm_admin refused" || fail "revoke builtin" "$out"
    out=$(Rv "chp-site revoke $U --group nosuch; echo rc=\$?"); [[ $out == *"not a direct member of nosuch"* && $out == *rc=2* ]] && pass "revoke of a group the user is not in: refused" || fail "revoke group" "$out"
    out=$(Rv "chp-site revoke $U; echo rc=\$?")
    [[ $out == *"the Kanidm change IS in effect"*iso3-cli* && $out == *rc=2* ]] && pass "revoke: uninstalled client iso3-cli named, change still in effect (Review Focus 3)" || fail "revoke" "$out"
    check "revoke: $U expired in Kanidm" "$(Rv "kanidm person get $U -D idm_admin | grep -c ^account_expire:")" "1"
    check "revoke: SSH key out of service" "$(Rv "ls /var/lib/ssh-ca/keys/$U.pub 2>/dev/null | wc -l; ls /var/lib/ssh-ca/revoked/ | grep -c '^$U.pub.'" | tr '\n' ' ')" "0 1 "
    out=$(Rv "chp-site onboard $U; echo rc=\$?"); [[ $out == *"chp-site unexpire $U"* && $out == *rc=2* ]] && pass "onboard of the expired $U refused (no bypass of #32)" || fail "onboard expired" "$out"
    out=$(Rv "chp-site unexpire $U --approver 'Chris Admin' --reason 'please let me back in now'; echo rc=\$?"); [[ $out == *"not the ISSO"* && $out == *rc=2* ]] && pass "unexpire by a non-approver refused" || fail "unexpire approver" "$out"
    out=$(Rv "chp-site unexpire $U --approver 'D. Shannon' --reason 'expired by mistake in the Plan 3b proof'; echo rc=\$?")
    [[ $out == *"expiry cleared"* && $out == *rc=0* ]] && pass "unexpire approved by the ISSO" || fail "unexpire" "$out"
    check "unexpire: $U no longer expired" "$(Rv "kanidm person get $U -D idm_admin | grep -c ^account_expire:")" "0"
    check "audit log: 2 unexpire records for $U (request + done) naming approver and reason" "$(Rv "ausearch --input-logs -m USER </dev/null 2>/dev/null | grep 'chp-site unexpire[.a-z]* user=\"$U\"' | grep 'approver=\"D. Shannon\"' | grep -c 'reason=\"expired by mistake in the Plan 3b proof\"'")" "2"
    check "audit log: 2 revoke records for $U" "$(Rv "ausearch --input-logs -m USER </dev/null 2>/dev/null | grep -c 'chp-site revoke[.a-z]* user=\"$U\"'")" "2"
    check "journal (authpriv): the same 2 unexpire records" "$(( $(Rv "journalctl -t chp-site --no-pager -o cat | grep -c '^chp-site unexpire[.a-z]* user=\"$U\"'") - j0 ))" "2"
    Rv 'kanidm logout -D idm_admin' >/dev/null
    check "fapolicyd: no denials" "$(Rv 'ausearch --input-logs -m FANOTIFY </dev/null 2>/dev/null | grep -c type=FANOTIFY')" "0"
    check "SELinux: no AVC since boot" "$(Rv 'ausearch --input-logs -m AVC -ts boot </dev/null 2>/dev/null | grep -c type=AVC')" "0" ;;
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
