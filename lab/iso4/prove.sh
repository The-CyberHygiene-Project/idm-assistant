#!/usr/bin/env bash
# prove.sh STAGE (RUNS ON THE MAC): ISO Plan 4a proof of the client role on aero: an identity server + two clients.
#   prep      render the iso4 site (+ diag key), lab kickstarts (+ embedded chp-site), push helpers, make the stick
#   server    install iso4-srv from repo 0.4.0; unlock the first boot with the escrowed passphrase
#   firstboot wait for the server first boot (now incl. unixd-tokens + self-client); check it, incl. the server as client
#   reboot    TPM unlock
#   export    export-client: secrets AND the two client tokens to the stick
#   client1 / client2   install each client from the stick; wait for its first boot; check the enrolment
#   ga        ISO Plan 4b: the second factor (bootstrap, enrol, logins, scratch codes, row 36, break-glass, refusals)
#   ops       (Plan 4a, password-only; superseded by `ga` once GA is on) onboard / SSH cert+password logins / group + account revoke with fan-out / unexpire / admins sudo / diag / chpcache
#   negtrust  Review Focus 1 on iso4-cli2: a wrong CA_ROOT_SHA256 pin is refused, the right one restores the anchor
#   cleanup   remove the three VMs, the stick, helpers and lab secrets on aero; shred the Mac render dir
# Every check prints PASS/FAIL; the stage exits 1 on any FAIL. Secrets move over pipes only (stick image -> expect).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; iso2="$top/lab/iso2"; iso3="$top/lab/iso3"
S=~/idm-lab-secrets; R=$S/iso4-render; KEY=$S/iso2_chpadmin; DKEY=$S/iso4_diag_ecdsa; UKEY=$S/iso4_ops_ecdsa
STICK=/data/libvirt/images/iso4-stick.img; PYZ="$top/appliance/chp-site/dist/chp-site.pyz"; D=iso4.lab.test
SRV=iso4-srv; SIP=192.168.100.40; C1=iso4-cli1; C1IP=192.168.100.41; C2=iso4-cli2; C2IP=192.168.100.42; fails=0
export CHP_REPO=0.5.0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: ${2:-}"; fails=1; }
check() { if [[ $2 == "$3" ]]; then pass "$1"; else fail "$1" "got '$2', want '$3'"; fi; }
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
Vh() { local ip=$1; shift; ssh -o BatchMode=yes -J aero -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "chpadmin@$ip" "$@" 2>/dev/null; }
# Root on host VM (IP) with ITS escrowed root console password (stick -> pipe on aero); the command travels base64-encoded.
Rh() { local b; b=$(printf '%s' "$3" | base64 | tr -d '\n')
  A "sudo bash /tmp/iso2/stick.sh escrow $STICK $1.txt | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p' | expect /tmp/iso2/rootrun.exp $2 /tmp/iso2/iso2_chpadmin $b" \
    | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }
Rv() { Rh "$SRV" "$SIP" "$1"; }
# Server root with a SECOND secret as "$CHP_SECRET": Rs CMD FIELD (stick's KANIDM_ADMINS_JSON) / Rx CMD (lab users' password).
Rs() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n'); A "sudo bash /tmp/iso2/rs.sh $STICK $SRV $SIP $2 $b" | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }
Rx() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n'); A "sudo bash /tmp/iso2/rsx.sh $STICK $SRV $SIP /tmp/iso2/ops.pw $b" | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }
# login IP USER [id|sudo]: key + that user's certificate + the lab password (stdin) -> "LOGIN_OK <x>" | "LOGIN_REFUSED"
# (the password file is root-only: the redirect must happen in a ROOT shell, not in the ssh user's)
login() { A "sudo sh -c 'expect /tmp/iso2/ssh-ki.exp $1 $2 /tmp/iso2/ops_key /tmp/iso2/$2-cert.pub ${3:-id} < /tmp/iso2/ops.pw'" | tr -d '\r' | grep -E '^LOGIN_' | tail -1; }
# refused_within IP USER SECS: keep trying until LOGIN_REFUSED (prints the seconds it took) or give up (prints NEVER)
refused_within() { local t0=$SECONDS; while (( SECONDS - t0 <= $3 )); do [[ $(login "$1" "$2") == LOGIN_REFUSED ]] && { echo "$((SECONDS - t0))"; return; }; sleep 3; done; echo NEVER; }
waitdone() {   # waitdone VM IP MARKER: wait for the first boot to finish (DONE) or fail (FAILED)
  local s; for _ in $(seq 60); do if Vh "$2" true; then break; fi; sleep 10; done
  for _ in $(seq 80); do
    s=$(Rh "$1" "$2" "if [ -e /var/lib/chp/firstboot/$3 ]; then echo DONE; elif systemctl is-failed -q chp-server-firstboot chp-client-firstboot 2>/dev/null; then echo FAILED; else echo RUNNING; fi")
    [[ $s == DONE || $s == FAILED ]] && break; sleep 15
  done; echo "$s"; }
enrolled_checks() {   # enrolled_checks VM IP LABEL: the checks every enrolled host (server or client) must pass
  check "$3: kanidm-unixd online" "$(Rh "$1" "$2" 'kanidm-unix status 2>/dev/null | grep -c "Kanidm: online"')" "1"
  check "$3: authselect custom/kanidm + CUI features" "$(Rh "$1" "$2" 'authselect current -r | tr " " "\n" | sed "/^$/d" | tr "\n" " "')" "custom/kanidm with-faillock without-nullok "
  check "$3: nsswitch passwd/group/initgroups start with kanidm" "$(Rh "$1" "$2" 'awk "\$1==\"passwd:\"||\$1==\"group:\"||\$1==\"initgroups:\"{print \$2}" /etc/nsswitch.conf | tr "\n" " "')" "kanidm kanidm kanidm "
  check "$3: sshd methods (user / chpadmin)" "$(Rh "$1" "$2" 'for u in alice chpadmin; do sshd -T -C user=$u,host=x,addr=1.1.1.1 | awk "\$1==\"authenticationmethods\"{print \$2}"; done | tr "\n" " "')" "publickey,keyboard-interactive:pam publickey "
  check "$3: unixd token 600 root" "$(Rh "$1" "$2" 'stat -c "%a %U" /etc/kanidm/token')" "600 root"
  check "$3: chp_kanidm loaded, socket dir labelled" "$(Rh "$1" "$2" 'semodule -l | grep -c "^chp_kanidm"; ls -Zd /run/kanidm-unixd | grep -c kanidm_unixd_var_run_t' | tr '\n' ' ')" "1 1 "
  check "$3: fapolicyd no denials" "$(Rh "$1" "$2" 'ausearch --input-logs -m FANOTIFY </dev/null 2>/dev/null | grep -c type=FANOTIFY')" "0"
  check "$3: SELinux no AVC since boot" "$(Rh "$1" "$2" 'ausearch --input-logs -m AVC -ts boot </dev/null 2>/dev/null | grep -c type=AVC')" "0"
}

case ${1:-} in
  prep)
    bash "$top/appliance/chp-site/build.sh" >/dev/null
    [[ -f $DKEY ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C 'idm-assistant diag (iso4 lab)' -f "$DKEY"
    [[ -f $UKEY ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C 'ops user (iso4 lab)' -f "$UKEY"
    rm -rf "$R"; (umask 077; mkdir -p "$R")
    sed -e "s|@ADMIN_PUBKEY@|$(cut -d' ' -f1,2 "$KEY.pub")|" -e "s|@DIAG_PUBKEY@|$(cut -d' ' -f1,2 "$DKEY.pub")|" "$here/site.conf.in" > "$R/site.conf"
    cp "$here/hosts" "$R/hosts"
    out=$(python3 "$PYZ" validate --site "$R"); [[ $out == OK:* ]] && pass "chp-site validate (iso4 site, diag key)" || fail "validate" "$out"
    A 'sudo rm -rf /tmp/iso2 && mkdir -p -m 700 /tmp/iso2'
    for r in server client; do
      { echo "%pre --interpreter=/usr/bin/bash --erroronfail --log=/tmp/chp-lab-pre.log"
        echo "python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' > /tmp/chp-site.pyz 2>/dev/console <<'CHP_PYZ_B64'"
        base64 < "$PYZ" | fold -w 76; echo "CHP_PYZ_B64"; echo "%end"; echo; cat "$top/appliance/kickstart/$r.ks"; } > "$R/../iso4-$r.ks"
      scp -q "$R/../iso4-$r.ks" "aero:/tmp/iso2/$r.ks"; rm -f "$R/../iso4-$r.ks"
    done
    scp -q "$PYZ" "$iso2/stick.sh" "$iso2/install.sh" "$iso2/unlock.sh" "$iso2/luks-send.exp" "$iso3/rootrun.exp" "$iso3/rs.sh" \
      "$here/rsx.sh" "$here/ssh-ki.exp" "$top/lab/srv1/totp.py" "$top/lab/host/console-login.exp" "$KEY" aero:/tmp/iso2/
    scp -q "$UKEY" aero:/tmp/iso2/ops_key; A 'chmod 600 /tmp/iso2/ops_key /tmp/iso2/iso2_chpadmin'
    # the lab users' POSIX password: made on aero, root-only, never printed
    A "sudo sh -c 'umask 077; python3 -c \"import secrets; print(secrets.token_urlsafe(24))\" > /tmp/iso2/ops.pw'"
    scp -q -r "$R" aero:/tmp/iso2/site
    out=$(A "sudo bash /tmp/iso2/stick.sh make /tmp/iso2/site $STICK && sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./site.conf"* ]] && pass "stick image made" || fail "stick" "$out" ;;
  server)
    out=$(A "sudo CHP_REPO=$CHP_REPO bash /tmp/iso2/install.sh $SRV 52:54:00:c4:04:40 server $STICK 1")
    [[ $out == *"INSTALLED and started $SRV"* ]] && pass "$SRV: install from repo $CHP_REPO" || { fail "$SRV: install" "$out"; exit 1; }
    out=$(A "sudo bash /tmp/iso2/unlock.sh $SRV $STICK $SRV")
    [[ $out == *"passphrase sent"* || $out == *"already unlocked"* ]] && pass "$SRV: first boot unlocked" || fail "$SRV: unlock" "$out" ;;
  firstboot)
    s=$(waitdone "$SRV" "$SIP" server.done); check "server first boot finished" "$s" "DONE"
    [[ $s == FAILED ]] && Rv 'journalctl -u chp-server-firstboot --no-pager | tail -25'
    check "new first-boot steps done (unixd-tokens, self-client, client enrolment)" \
      "$(Rv 'cd /var/lib/chp/firstboot && ls unixd-tokens.done self-client.done client.done client-trust.done client-unixd.done client-authselect.done client-sshd.done client-accounts.done 2>/dev/null | wc -l')" "8"
    check "two client tokens pending (600)" "$(Rv 'stat -c "%n %a" /root/chp-escrow-pending/tokens/*.token | sed "s#.*/##" | tr "\n" " "')" "iso4-cli1.token 600 iso4-cli2.token 600 "
    enrolled_checks "$SRV" "$SIP" "server-as-client"
    check "server allows chp_admins only" "$(Rv 'grep -c "\"chp_admins\"" /etc/kanidm/unixd')" "1"
    check "chp_admins sudo rule installed (0440)" "$(Rv 'stat -c %a /etc/sudoers.d/60-chp-admins; cat /etc/sudoers.d/60-chp-admins' | tr '\n' ' ')" "440 %chp_admins ALL=(ALL) ALL "
    check "diag account + forced command on the server" "$(Rv 'grep -c "command=\"/usr/libexec/chp/diag-collect\"" /home/diag/.ssh/authorized_keys')" "1"
    check "no chpcache account on the server" "$(Rv 'id chpcache >/dev/null 2>&1 && echo yes || echo no')" "no"
    al=$(Rv 'for c in /usr/lib/chp/monitor.d/*; do "$c"; done | grep ^ALERT')
    [[ $(grep -c . <<<"$al") == 1 && $al == *"recovery secrets still on the server"* ]] && pass "monitor alerts only: secrets still on the server" || fail "monitor alerts" "$al" ;;
  reboot)
    A "sudo virsh reboot $SRV >/dev/null"; sleep 20
    ok=no; for _ in $(seq 30); do if Vh "$SIP" true; then ok=yes; break; fi; sleep 10; done
    check "after reboot the TPM unlocked the disk" "$ok" "yes"
    check "unixd online after reboot" "$(Rv 'for i in $(seq 15); do kanidm-unix status 2>/dev/null | grep -q "Kanidm: online" && break; sleep 2; done; kanidm-unix status 2>/dev/null | grep -c "Kanidm: online"')" "1" ;;
  export)
    A "sudo virsh attach-disk $SRV $STICK sdz --targetbus usb --type disk --live >/dev/null"; sleep 5
    out=$(Rv 'chp-site export-client')
    [[ $out == *"moved to the stick: kanidm-admins.json, root_ca_key, step-ca-password"* ]] && pass "export-client moved the server secrets" || fail "export secrets" "$out"
    [[ $out == *"tokens moved to the stick: iso4-cli1, iso4-cli2"* ]] && pass "export-client moved both client tokens" || fail "export tokens" "$out"
    A "sudo virsh detach-disk $SRV sdz --live >/dev/null"; sleep 3
    out=$(A "sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./tokens/iso4-cli1.token"* && $out == *"./tokens/iso4-cli2.token"* && $out == *"./client.conf"* ]] && pass "stick holds client.conf + both tokens" || fail "stick contents" "$out"
    check "nothing pending on the server" "$(Rv 'ls -A /root/chp-escrow-pending | wc -l')" "0"
    check "server monitor quiet" "$(Rv '/usr/libexec/chp/monitor >/dev/null; echo $?')" "0" ;;
  client1|client2)
    if [[ $1 == client1 ]]; then VM=$C1; IP=$C1IP; MAC=52:54:00:c4:04:41; else VM=$C2; IP=$C2IP; MAC=52:54:00:c4:04:42; fi
    out=$(A "sudo CHP_REPO=$CHP_REPO bash /tmp/iso2/install.sh $VM $MAC client $STICK 1")
    [[ $out == *"INSTALLED and started $VM"* ]] && pass "$VM: install from repo $CHP_REPO (stick: client.conf + its token)" || { fail "$VM: install" "$out"; exit 1; }
    out=$(A "sudo bash /tmp/iso2/unlock.sh $VM $STICK $VM")
    [[ $out == *"passphrase sent"* || $out == *"already unlocked"* ]] && pass "$VM: first boot unlocked" || fail "$VM: unlock" "$out"
    s=$(waitdone "$VM" "$IP" client.done); check "$VM: client first boot finished" "$s" "DONE"
    [[ $s == FAILED ]] && Rh "$VM" "$IP" 'journalctl -u chp-client-firstboot --no-pager | tail -25'
    pin=$(A "sudo bash /tmp/iso2/stick.sh escrow $STICK ../client.conf" | sed -n 's/^CA_ROOT_SHA256=//p')
    check "$VM: anchor = pinned root" "$(Rh "$VM" "$IP" 'openssl x509 -in /etc/pki/ca-trust/source/anchors/chp-root.crt -outform DER | sha256sum | cut -d" " -f1')" "$pin"
    check "$VM: no staged token copy left" "$(Rh "$VM" "$IP" 'ls /tmp/chp 2>/dev/null | wc -l')" "0"
    enrolled_checks "$VM" "$IP" "$VM"
    check "$VM: clients allow chp_users" "$(Rh "$VM" "$IP" 'grep -c "\"chp_users\"" /etc/kanidm/unixd')" "1"
    check "$VM: chpcache pinned to the server + exact sudo" "$(Rh "$VM" "$IP" "grep -c 'from=\"$SIP\",command=\"sudo -n /usr/sbin/kanidm-unix cache-invalidate\"' /home/chpcache/.ssh/authorized_keys; cat /etc/sudoers.d/62-chp-cache" | tr '\n' ' ')" "1 chpcache ALL=(root) NOPASSWD: /usr/sbin/kanidm-unix cache-invalidate "
    check "$VM: monitors quiet" "$(Rh "$VM" "$IP" '/usr/libexec/chp/monitor >/dev/null; echo $?')" "0"
    A "sudo virsh reboot $VM >/dev/null"; sleep 20
    ok=no; for _ in $(seq 30); do if Vh "$IP" true; then ok=yes; break; fi; sleep 10; done
    check "$VM: TPM unlock after reboot" "$ok" "yes" ;;
  ops)
    U=u$(date +%H%M); G=g$(date +%H%M); AD=a$(date +%H%M)
    V2() { Vh "$SIP" "$@"; }
    V2 'umask 077; mkdir -p ~/chp-lab; cat > ~/chp-lab/user.pub' < "$UKEY.pub"
    sed 's#/tmp/srv1/#/root/chp-lab/#g' "$top/lab/srv1/enrol-user.exp" | V2 'cat > ~/chp-lab/enrol-user.exp'
    V2 'cat > ~/chp-lab/totp.py' < "$top/lab/srv1/totp.py"
    Rv 'install -d -m 0700 /root/chp-lab && cp /home/chpadmin/chp-lab/* /root/chp-lab/ && chmod 600 /root/chp-lab/* && rm -rf /home/chpadmin/chp-lab' >/dev/null
    check "idm_admin login (password from the stick, pipes only)" "$(Rs 'printf "%s\n" "$CHP_SECRET" | expect /usr/libexec/chp/kanidm-login.exp idm_admin >/dev/null && echo LOGGEDIN' idm_admin)" "LOGGEDIN"
    for x in "$U" "$G" "$AD"; do
      extra=""; [[ $x == "$AD" ]] && extra="--group chp_admins"
      out=$(Rv "chp-site onboard $x --display 'Ops $x' --ssh-key /root/chp-lab/user.pub $extra")
      [[ $out == *"[x] SSH certificate issued"* ]] || fail "onboard $x" "$out"
      out=$(Rx "cd /root/chp-lab && sed 's/^log_user 0/log_user 1/' enrol-user.exp > e.exp && tok=\$(sed -n 's/.*use-reset-token \([A-Za-z0-9-]*\).*/\1/p' /root/chp-onboard/$x.reset-token.txt | head -1) && pw=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))') && if printf '%s\n%s\n%s\ntotp\n' \"\$tok\" \"\$pw\" \"\$CHP_SECRET\" | expect e.exp > e.log 2>&1; then echo ENROLLED; else sed \"s/\$tok/TOKEN/g\" e.log | tr -d '\\r' | grep -viE 'secret|otpauth' | tail -6; fi; rm -f e.exp; shred -u e.log")
      check "onboard + lab stand-in enrolment: $x" "$out" "ENROLLED"
      Rv "cat /root/chp-onboard/$x-cert.pub" | A "sudo tee /tmp/iso2/$x-cert.pub >/dev/null"
    done
    check "SSH cert + Kanidm password: $U on $C1" "$(login $C1IP "$U")" "LOGIN_OK $U"
    check "SSH cert + Kanidm password: $U on $C2" "$(login $C2IP "$U")" "LOGIN_OK $U"
    check "SSH cert + Kanidm password: $G on $C1" "$(login $C1IP "$G")" "LOGIN_OK $G"
    out=$(A "sudo sh -c 'expect /tmp/iso2/ssh-ki.exp $C1IP $U /tmp/iso2/ops_key /dev/null id < /tmp/iso2/ops.pw'" | tr -d '\r' | grep -E '^LOGIN_' | tail -1)
    check "key without the CA certificate: refused" "$out" "LOGIN_REFUSED"
    out=$(Rv "chp-site revoke $G --group chp_users; echo rc=\$?")
    [[ $out == *"ok   $C1"* && $out == *"ok   $C2"* && $out == *rc=0* ]] && pass "revoke $G --group chp_users: fan-out reached both clients" || fail "revoke group" "$out"
    t=$(refused_within $C1IP "$G" 30); [[ $t != NEVER ]] && pass "$G (no longer in chp_users) refused on $C1 within 30 s (${t}s)" || fail "group revoke effect" "$t"
    out=$(Rv "chp-site revoke $U; echo rc=\$?")
    [[ $out == *"ok   $C1"* && $out == *"ok   $C2"* && $out == *rc=0* ]] && pass "revoke $U: fan-out reached both clients" || fail "revoke account" "$out"
    t1=$(refused_within $C1IP "$U" 30); t2=$(refused_within $C2IP "$U" 30)
    [[ $t1 != NEVER && $t2 != NEVER ]] && pass "$U refused on both clients within 30 s (${t1}s, ${t2}s)" || fail "account revoke effect" "$t1 $t2"
    out=$(Rv "chp-site unexpire $U --approver 'D. Shannon' --reason 'expired by mistake in the Plan 4a proof'; echo rc=\$?")
    [[ $out == *"expiry cleared"* && $out == *rc=0* ]] && pass "unexpire $U (ISSO)" || fail "unexpire" "$out"
    out=$(Rv "chp-site onboard $U --ssh-key /root/chp-lab/user.pub"); Rv "cat /root/chp-onboard/$U-cert.pub" | A "sudo tee /tmp/iso2/$U-cert.pub >/dev/null"
    check "after unexpire + key re-registered: $U logs in again on $C1" "$(login $C1IP "$U")" "LOGIN_OK $U"
    check "admin $AD logs in to the server" "$(login $SIP "$AD")" "LOGIN_OK $AD"
    check "admin $AD: sudo with the Kanidm password" "$(login $SIP "$AD" sudo)" "LOGIN_OK SUDO_OK"
    check "chp_users-only $U refused on the server" "$(login $SIP "$U")" "LOGIN_REFUSED"
    DI="-i $DKEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -J aero"
    # shellcheck disable=SC2086
    out=$(ssh $DI "diag@$C1IP" 'sudo -n /usr/sbin/idm-collect' 2>/dev/null | tail -1)
    [[ $out == *'"schema":"idm-report/1"'* ]] && pass "diag: collector report from $C1" || fail "diag report" "$(head -c 200 <<<"$out")"
    # shellcheck disable=SC2086
    out=$(ssh $DI "diag@$SIP" "sudo -n /usr/sbin/idm-collect --user $U" 2>/dev/null | tail -1)
    [[ $out == *'"schema":"idm-report/1"'* && $out == *"\"name\":\"$U\""* ]] && pass "diag: --user report from the server" || fail "diag --user" "$(head -c 200 <<<"$out")"
    for bad in "bash" "idm-collect --user x;id" "sudo -n /bin/sh"; do
      # shellcheck disable=SC2086
      out=$(ssh $DI "diag@$C1IP" "$bad" 2>&1; echo "rc=$?")
      [[ $out == *"refused"* && $out != *'"schema"'* ]] && pass "diag forced command refuses: $bad" || fail "diag refuse $bad" "$(head -c 200 <<<"$out")"
    done
    V2 'umask 077; cat > ~/dk' < "$DKEY"
    out=$(V2 "ssh -i ~/dk -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes diag@$C1IP true; echo rc=\$?; shred -u ~/dk")
    [[ $out == *rc=255* ]] && pass "diag key refused from the server's address (from= pin)" || fail "diag from=" "$out"
    Rv 'cat /var/lib/chp/cache-key/id_ecdsa' | A 'sudo sh -c "umask 077; cat > /tmp/iso2/cachekey"'
    out=$(A "sudo ssh -i /tmp/iso2/cachekey -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes chpcache@$C1IP x; echo rc=\$?; sudo shred -u /tmp/iso2/cachekey")
    [[ $out == *rc=255* ]] && pass "chpcache key refused from anywhere but the server (from= pin)" || fail "chpcache from=" "$out"
    for ip in $SIP $C1IP $C2IP; do check "chpadmin key-only break-glass on $ip" "$(Vh "$ip" 'echo ok')" "ok"; done
    Rv 'kanidm logout -D idm_admin' >/dev/null
    for h in "$SRV $SIP" "$C1 $C1IP" "$C2 $C2IP"; do set -- $h
      check "$1: fapolicyd 0 / AVC 0" "$(Rh "$1" "$2" 'ausearch --input-logs -m FANOTIFY </dev/null 2>/dev/null | grep -c type=FANOTIFY; ausearch --input-logs -m AVC -ts boot </dev/null 2>/dev/null | grep -c type=AVC' | tr '\n' ' ')" "0 0 "
    done ;;
  ga)
    # ISO Plan 4b. GA is on everywhere from install (0.5.0). The lab stand-in for each user's phone is the token's secret,
    # copied as root to aero (/tmp/iso2/<vm>-<user>.ga, 0600); real users scan the QR code instead.
    U=u$(date +%H%M); AD=a$(date +%H%M)
    fresh_window() { sleep $(( 31 - $(date +%s) % 30 )); }
    Rhx() { local b; b=$(printf '%s' "$3" | base64 | tr -d '\n'); A "sudo bash /tmp/iso2/rsx.sh $STICK $1 $2 /tmp/iso2/ops.pw $b" | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }
    gasecret() { Rh "$1" "$2" "head -1 /var/lib/google-authenticator/$3" | A "sudo sh -c 'umask 077; cat > /tmp/iso2/$1-$3.ga'"; }
    # gal IP VM USER [id|sudo|enrol] [SECRET_FILE]: login with key + cert + code + password -> "PROMPTS=… LOGIN_…"
    gal() { A "sudo sh -c 'ENROL_USER=${ENROL_USER:-} expect /tmp/iso2/ssh-ki.exp $1 $3 /tmp/iso2/ops_key /tmp/iso2/$3-cert.pub ${4:-id} ${5:-/tmp/iso2/$2-$3.ga} < /tmp/iso2/ops.pw'" | tr -d '\r' | grep -E '^(LOGIN_|PROMPTS=)' | tr '\n' ' '; }
    console() { A "sudo sh -c 'bash /tmp/iso2/stick.sh escrow $STICK $1.txt | sed -n s/^ROOT_CONSOLE_PASSWORD=//p | { cat; echo; } | expect /tmp/iso2/console-login.exp $1 root'" | tr -d '\r' | grep -E '^(PROMPT|RESULT)' | tr '\n' ' '; }
    for h in "$SIP" "$C1IP" "$C2IP"; do Vh "$h" 'umask 077; mkdir -p ~/m; cat > ~/m/totp.py' < "$top/lab/srv1/totp.py"; done
    for v in "$SRV $SIP" "$C1 $C1IP" "$C2 $C2IP"; do set -- $v; Rh "$1" "$2" 'install -d -m 0700 /root/chp-lab && cp /home/chpadmin/m/totp.py /root/chp-lab/ && rm -rf /home/chpadmin/m' >/dev/null; done
    V2() { Vh "$SIP" "$@"; }
    V2 'umask 077; mkdir -p ~/chp-lab; cat > ~/chp-lab/user.pub' < "$UKEY.pub"
    sed 's#/tmp/srv1/#/root/chp-lab/#g' "$top/lab/srv1/enrol-user.exp" | V2 'cat > ~/chp-lab/enrol-user.exp'
    Rv 'cp /home/chpadmin/chp-lab/* /root/chp-lab/ && chmod 600 /root/chp-lab/* && rm -rf /home/chpadmin/chp-lab' >/dev/null
    for _ in 1 2 3; do li=$(Rs 'printf "%s\n" "$CHP_SECRET" | expect /usr/libexec/chp/kanidm-login.exp idm_admin >/dev/null && echo LOGGEDIN' idm_admin); [[ $li == LOGGEDIN ]] && break; sleep 10; done
    check "idm_admin login" "$li" "LOGGEDIN"
    for x in "$U" "$AD"; do
      extra=""; [[ $x == "$AD" ]] && extra="--group chp_admins"
      Rv "chp-site onboard $x --display 'Ops $x' --ssh-key /root/chp-lab/user.pub $extra" >/dev/null
      out=$(Rx "cd /root/chp-lab && tok=\$(sed -n 's/.*use-reset-token \([A-Za-z0-9-]*\).*/\1/p' /root/chp-onboard/$x.reset-token.txt | head -1) && pw=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))') && printf '%s\n%s\n%s\ntotp\n' \"\$tok\" \"\$pw\" \"\$CHP_SECRET\" | expect enrol-user.exp > $x.totp && echo ENROLLED")
      check "onboard + Kanidm enrolment: $x" "$out" "ENROLLED"
      Rv "cat /root/chp-onboard/$x-cert.pub" | A "sudo tee /tmp/iso2/$x-cert.pub >/dev/null"
    done
    # 1. bootstrap (Review Focus 5): root enrols the first admin on the server
    check "root bootstraps $AD on the server (ga-enrol)" "$(Rv "chp-site ga-enrol $AD --no-confirm >/dev/null 2>&1; echo rc=\$?")" "rc=0"
    gasecret "$SRV" "$SIP" "$AD"; fresh_window
    check "$AD on the server: cert + code + password" "$(gal $SIP $SRV $AD)" "PROMPTS=Verification code|Password LOGIN_OK $AD "
    fresh_window
    out=$(gal $SIP $SRV $AD sudo); [[ $out == *"LOGIN_OK SUDO_OK"* && $out == *"Verification code|Password|Verification code|Password"* ]] && pass "$AD sudo on the server asks code + password" || fail "admin sudo" "$out"
    # 2. an enrolled admin enrols a user over SSH with sudo (after root bootstraps the admin on that host)
    check "root bootstraps $AD on $C1" "$(Rh $C1 $C1IP "chp-site ga-enrol $AD --no-confirm >/dev/null 2>&1; echo rc=\$?")" "rc=0"
    gasecret "$C1" "$C1IP" "$AD"; fresh_window
    out=$(ENROL_USER=$U gal $C1IP $C1 $AD enrol); [[ $out == *"LOGIN_OK ENROLLED"* ]] && pass "$AD enrols $U on $C1 with sudo (code + password asked)" || fail "admin enrol" "$out"
    check "audit on $C1: ga-enrol of $U by $AD (request + done)" "$(Rh $C1 $C1IP "ausearch --input-logs -m USER </dev/null 2>/dev/null | grep 'chp-site ga-enrol[.a-z]* user=\"$U\"' | grep -c 'operator=\"$AD\"'")" "2"
    gasecret "$C1" "$C1IP" "$U"
    # 3. logins, replay, wrong code
    fresh_window
    check "$U on $C1: cert + code + password" "$(gal $C1IP $C1 $U)" "PROMPTS=Verification code|Password LOGIN_OK $U "
    # replay = the IDENTICAL code twice (window timing can't be aligned: codes are computed on aero's clock)
    fresh_window; A "sudo sh -c 'umask 077; echo CODE:\$(python3 /tmp/iso2/totp.py - sha1 < /tmp/iso2/$C1-$U.ga) > /tmp/iso2/replay.ga'"
    check "a fresh code: accepted" "$(gal $C1IP $C1 $U id /tmp/iso2/replay.ga)" "PROMPTS=Verification code|Password LOGIN_OK $U "
    out=$(gal $C1IP $C1 $U id /tmp/iso2/replay.ga); [[ $out == *LOGIN_REFUSED* ]] && pass "the same code again: refused (no reuse)" || fail "replay" "$out"
    # a 4th attempt inside 30 s is refused by GA's rate limit (-r 3 -R 30) WITHOUT a code prompt: test that, then wait it out
    out=$(gal $C1IP $C1 $U id /tmp/iso2/replay.ga); [[ $out == *LOGIN_REFUSED* && $out != *Verification* ]] && pass "rate limit: a 4th attempt within 30 s is refused without a code prompt" || fail "rate limit" "$out"
    A "sudo sh -c 'umask 077; echo AAAAAAAAAAAAAAAAAAAAAAAAAA > /tmp/iso2/wrong.ga'"; sleep 31
    out=$(gal $C1IP $C1 $U id /tmp/iso2/wrong.ga); [[ $out == *"Verification code|Password"* && $out == *LOGIN_REFUSED* ]] && pass "wrong code: refused, password still asked (no early signal)" || fail "wrong code" "$out"
    # the CUI lockout counts the three refusals above (replay, rate limit, wrong code): U is now locked; an admin clears it
    check "faillock counted the 3 GA failures (account locked)" "$(Rh $C1 $C1IP "faillock --user $U | grep -cE '^[0-9]{4}-'")" "3"
    out=$(gal $C1IP $C1 $U); [[ $out == *LOGIN_REFUSED* ]] && pass "while locked even a correct code + password is refused" || fail "lockout" "$out"
    Rh $C1 $C1IP "faillock --user $U --reset" >/dev/null
    # 4. host-local: no token on cli2 until enrolled there
    fresh_window
    out=$(gal $C2IP $C2 $U id /tmp/iso2/$C1-$U.ga); [[ $out == *LOGIN_REFUSED* ]] && pass "$U has no token on $C2: refused (Review Focus 1)" || fail "no token" "$out"
    check "root enrols $U on $C2" "$(Rh $C2 $C2IP "chp-site ga-enrol $U --no-confirm >/dev/null 2>&1; echo rc=\$?")" "rc=0"
    gasecret "$C2" "$C2IP" "$U"; fresh_window
    check "$U on $C2 with its own token" "$(gal $C2IP $C2 $U)" "PROMPTS=Verification code|Password LOGIN_OK $U "
    # 5. scratch code: works once
    sc=$(Rh $C1 $C1IP "grep -E '^[0-9]{8}\$' /var/lib/google-authenticator/$U | head -1")
    A "sudo sh -c 'umask 077; echo CODE:$sc > /tmp/iso2/scratch.ga'"; fresh_window
    check "scratch code #1: accepted" "$(gal $C1IP $C1 $U id /tmp/iso2/scratch.ga)" "PROMPTS=Verification code|Password LOGIN_OK $U "
    fresh_window
    out=$(gal $C1IP $C1 $U id /tmp/iso2/scratch.ga); [[ $out == *LOGIN_REFUSED* ]] && pass "scratch code #1 again: refused (one use)" || fail "scratch reuse" "$out"
    check "scratch codes left on $C1: 4" "$(Rh $C1 $C1IP "grep -cE '^[0-9]{8}\$' /var/lib/google-authenticator/$U")" "4"
    # 6. row 36: the gdm-password / login / sudo stacks, and the token afterwards
    for spec in "gdm-password $U" "login $U" "sudo $AD"; do set -- $spec; fresh_window
      out=$(Rhx $C1 $C1IP "code=\$(python3 /root/chp-lab/totp.py - sha1 < /var/lib/google-authenticator/$2); printf '%s\n%s\n' \"\$CHP_SECRET\" \"\$code\" | chp-site pam-test $1 $2")
      [[ $out == "PAM_OK prompts=Verification code:|Password:" ]] && pass "pam-test $1 $2 on $C1: PAM_OK (code, then password)" || fail "pam-test $1" "$out"
    done
    check "$U token after logins: 400 root root var_auth_t" "$(Rh $C1 $C1IP "stat -c '%a %U %G' /var/lib/google-authenticator/$U; ls -Z /var/lib/google-authenticator/$U | cut -d: -f3" | tr '\n' ' ')" "400 root root var_auth_t "
    # 7. local accounts exempt; 7b break-glass explicitly (user review)
    out=$(Rhx $C1 $C1IP "printf '%s\n' \"\$CHP_SECRET\" | chp-site pam-test login $U")
    [[ $out == "PAM_FAIL"*"Verification code"* ]] && pass "no bypass: $U without a code fails, code asked" || fail "bypass" "$out"
    for v in "$SRV $SIP" "$C1 $C1IP" "$C2 $C2IP"; do set -- $v
      check "break-glass $1: chpadmin SSH key-only" "$(Vh "$2" 'echo ok')" "ok"
      check "break-glass $1: chpadmin + su - (Password only)" "$(Rh "$1" "$2" 'id -u')" "0"
      out=$(console "$1"); [[ $out == "PROMPT: Password RESULT: logged in as root " ]] && pass "break-glass $1: root console, password only" || fail "root console $1" "$out"
    done
    Rh $C2 $C2IP 'systemctl stop kanidm-unixd-tasks kanidm-unixd' >/dev/null
    check "Kanidm down on $C2: unixd stopped" "$(Rh $C2 $C2IP 'systemctl is-active kanidm-unixd')" "inactive"
    check "Kanidm down: chpadmin SSH key-only" "$(Vh "$C2IP" 'echo ok')" "ok"
    check "Kanidm down: chpadmin + su -" "$(Rh $C2 $C2IP 'id -u')" "0"
    out=$(console "$C2"); [[ $out == "PROMPT: Password RESULT: logged in as root " ]] && pass "Kanidm down: root console, password only" || fail "root console, Kanidm down" "$out"
    check "unixd back online" "$(Rh $C2 $C2IP 'systemctl start kanidm-unixd kanidm-unixd-tasks; for i in $(seq 15); do kanidm-unix status 2>/dev/null | grep -q "Kanidm: online" && break; sleep 2; done; kanidm-unix status | grep -c "Kanidm: online"')" "1"
    DI="-i $DKEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -J aero"
    # shellcheck disable=SC2086
    out=$(ssh $DI "diag@$C1IP" 'sudo -n /usr/sbin/idm-collect' 2>/dev/null | tail -1)
    [[ $out == *'"schema":"idm-report/1"'* ]] && pass "diag (local, forced command): report from $C1" || fail "diag" "$(head -c 160 <<<"$out")"
    # 8. ga-enrol refusals and --reset
    check "ga-enrol chpadmin refused (local)" "$(Rh $C1 $C1IP 'chp-site ga-enrol chpadmin --no-confirm 2>&1 | grep -c "local account"')" "1"
    check "ga-enrol of an unknown user refused" "$(Rh $C1 $C1IP 'chp-site ga-enrol nosuch99 --no-confirm 2>&1 | grep -c "does not resolve"')" "1"
    check "ga-enrol $U again without --reset refused" "$(Rh $C1 $C1IP "chp-site ga-enrol $U --no-confirm 2>&1 | grep -c -- '--reset'")" "1"
    A "sudo cp -p /tmp/iso2/$C1-$U.ga /tmp/iso2/$C1-$U.old.ga"
    check "ga-enrol $U --reset" "$(Rh $C1 $C1IP "chp-site ga-enrol $U --reset --no-confirm >/dev/null 2>&1; echo rc=\$?")" "rc=0"
    fresh_window
    out=$(gal $C1IP $C1 $U id /tmp/iso2/$C1-$U.old.ga); [[ $out == *LOGIN_REFUSED* ]] && pass "after --reset the old secret no longer works" || fail "reset old" "$out"
    gasecret "$C1" "$C1IP" "$U"; fresh_window
    check "after --reset the new secret works" "$(gal $C1IP $C1 $U)" "PROMPTS=Verification code|Password LOGIN_OK $U "
    # I1 (final review): a Kanidm person + group with LOCAL names, created directly (bypassing chp-site's guard) —
    # with short names on the hosts, the LOCAL account/group must still win (GA exemption and sudo rules go by name)
    Rv "for c in 'person create chpcache Collision' 'person posix set chpcache' 'group add-members chp_users chpcache' 'group create wheel' 'group posix set wheel' 'group add-members wheel $U'; do kanidm \$c -D idm_admin >/dev/null 2>&1; done; echo ok" >/dev/null
    for v in "$C1 $C1IP" "$C2 $C2IP"; do set -- $v; Rh "$1" "$2" 'kanidm-unix cache-invalidate >/dev/null 2>&1; true' >/dev/null; done
    check "collision: Kanidm 'chpcache' exists" "$(Rv "kanidm person get chpcache -D idm_admin | grep -c '^name: chpcache'")" "1"
    check "collision: on $C1 'chpcache' still resolves to the LOCAL account" "$(Rh $C1 $C1IP "getent passwd chpcache | cut -d: -f3"):$(Rh $C1 $C1IP "awk -F: '\$1==\"chpcache\"{print \$3}' /etc/passwd")" "$(Rh $C1 $C1IP "awk -F: '\$1==\"chpcache\"{print \$3}' /etc/passwd"):$(Rh $C1 $C1IP "awk -F: '\$1==\"chpcache\"{print \$3}' /etc/passwd")"
    check "collision: Kanidm group 'wheel' does not give $U the local wheel group on $C1" "$(Rh $C1 $C1IP "id -G $U | tr ' ' '\n' | grep -cx \$(getent group wheel | cut -d: -f3)")" "0"
    check "collision: chp-site onboard refuses the local name" "$(Rv 'chp-site onboard diag 2>&1 | grep -c "local account"')" "1"
    # 9. revoke fan-out still reaches both clients; then monitors and denials
    out=$(Rv "chp-site revoke $U; echo rc=\$?"); [[ $out == *"ok   $C1"* && $out == *"ok   $C2"* && $out == *rc=0* ]] && pass "revoke $U: fan-out reached both clients (chpcache, local)" || fail "revoke" "$out"
    Rv 'kanidm logout -D idm_admin' >/dev/null
    for v in "$SRV $SIP" "$C1 $C1IP" "$C2 $C2IP"; do set -- $v
      check "$1: monitors quiet" "$(Rh "$1" "$2" '/usr/libexec/chp/monitor >/dev/null; echo $?')" "0"
      check "$1: fapolicyd 0 / AVC 0" "$(Rh "$1" "$2" 'ausearch --input-logs -m FANOTIFY </dev/null 2>/dev/null | grep -c type=FANOTIFY; ausearch --input-logs -m AVC -ts boot </dev/null 2>/dev/null | grep -c type=AVC' | tr '\n' ' ')" "0 0 "
    done
    A "sudo rm -f /tmp/iso2/*.ga" ;;
  negtrust)
    out=$(Rh "$C2" "$C2IP" 'A=/etc/pki/ca-trust/source/anchors/chp-root.crt; cp -p /etc/chp/client.conf /root/cc.bak; mv $A /root/anchor.bak
      sed -i "s/^CA_ROOT_SHA256=.*/CA_ROOT_SHA256=$(printf "0%.0s" $(seq 64))/" /etc/chp/client.conf
      /usr/libexec/chp/client-enrol --step trust >/dev/null 2>&1; echo "rc=$?"; test -e $A && echo ANCHOR || echo NOANCHOR
      journalctl -t chp-client-enrol --since "-2min" --no-pager -o cat | grep -c "refusing: step-ca"
      cp -p /root/cc.bak /etc/chp/client.conf; /usr/libexec/chp/client-enrol --step trust >/dev/null 2>&1; echo "rc2=$?"
      openssl x509 -in $A -outform DER | sha256sum | cut -d" " -f1; sed -n "s/^CA_ROOT_SHA256=//p" /etc/chp/client.conf
      rm -f /root/cc.bak /root/anchor.bak' | tr '\n' ' ')
    read -r rc a n rc2 got want <<<"$out"
    [[ $rc != rc=0 && $a == NOANCHOR && $n -ge 1 ]] && pass "wrong pin: enrolment refused, no anchor installed, journal says why" || fail "wrong pin" "$out"
    [[ $rc2 == rc2=0 && -n $got && $got == "$want" ]] && pass "right pin: anchor restored and matches" || fail "restore" "$out"
    check "$C2: unixd online again" "$(Rh "$C2" "$C2IP" 'systemctl restart kanidm-unixd; for i in $(seq 15); do kanidm-unix status 2>/dev/null | grep -q "Kanidm: online" && break; sleep 2; done; kanidm-unix status 2>/dev/null | grep -c "Kanidm: online"')" "1" ;;
  cleanup)
    for v in $SRV $C1 $C2; do A "sudo virsh destroy $v >/dev/null 2>&1; sudo virsh undefine $v --nvram >/dev/null 2>&1; sudo rm -f /data/libvirt/images/$v-[0-9].qcow2"; done
    A "sudo rm -f $STICK; sudo shred -u /tmp/iso2/iso2_chpadmin /tmp/iso2/ops_key /tmp/iso2/ops.pw 2>/dev/null; sudo rm -rf /tmp/iso2"
    rm -P "$R"/* 2>/dev/null; rm -rf "$R"; pass "cleanup" ;;
  *) echo "usage: prove.sh prep|server|firstboot|reboot|export|client1|client2|ops|negtrust|cleanup"; exit 2 ;;
esac
exit "$fails"
