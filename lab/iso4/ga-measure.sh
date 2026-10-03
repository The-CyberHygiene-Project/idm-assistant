#!/usr/bin/env bash
# ga-measure.sh (RUNS ON THE MAC): ISO Plan 4b Task 4. LAB-ONLY spike: hand-apply the second factor (dev chp-site.pyz) on an
# installed iso4-cli1 (repo 0.4.1) and measure, per login stack, whether SELinux denies anything. Run after
# `prove.sh prep server firstboot reboot export client1`. Prints PASS/FAIL lines and the AVC count per stack.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"
eval "$(sed -n '/^S=~/,/^enrolled_checks/p' "$here/prove.sh" | sed '$d')"
C=$C1; CIP=$C1IP; U=gm$(date +%H%M); AD=gma$(date +%H%M)
Rc() { Rh "$C" "$CIP" "$1"; }
Rcx() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n'); A "sudo bash /tmp/iso2/rsx.sh $STICK $C $CIP /tmp/iso2/ops.pw $b" | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }
fresh_window() { local s; s=$(( 31 - $(date +%s) % 30 )); sleep "$s"; }   # a new TOTP window: no code reuse (-d)
avc() { Rc "ausearch --input-logs -m AVC -ts $1 </dev/null 2>/dev/null | grep -c type=AVC"; }

# --- hand-apply the 4b changes on the client (lab only) --------------------------------------------------------------
bash "$top/appliance/chp-site/build.sh" >/dev/null
scp -q "$top/lab/srv1/totp.py" "$top/lab/host/console-login.exp" aero:/tmp/iso2/
Vh "$CIP" 'umask 077; mkdir -p ~/m' ; Vh "$CIP" 'cat > ~/m/chp-site-dev.pyz' < "$PYZ"; Vh "$CIP" 'cat > ~/m/totp.py' < "$top/lab/srv1/totp.py"
Rc 'install -d -m 0700 /root/chp-lab && cp /home/chpadmin/m/* /root/chp-lab/ && rm -rf /home/chpadmin/m' >/dev/null
out=$(Rc "dnf -y -q --disablerepo='*' --repofrompath=chp41,http://192.168.100.1:8080/chp/0.4.1 --setopt=chp41.gpgcheck=1 --setopt=chp41.gpgkey=http://192.168.100.1:8080/chp/RPM-GPG-KEY-EPEL-9 install google-authenticator >/dev/null 2>&1; rpm -q google-authenticator")
[[ $out == google-authenticator-* ]] && pass "google-authenticator installed (EPEL-signed, from the chp repo)" || fail "GA install" "$out"
Rc 'install -d -m 0700 /var/lib/google-authenticator && restorecon -R /var/lib/google-authenticator' >/dev/null
out=$(Rc 'python3 /root/chp-lab/chp-site-dev.pyz authselect-patch /etc/authselect/custom/kanidm >/dev/null && authselect apply-changes >/dev/null && grep -c "pam_google_authenticator.so secret=/var/lib/google-authenticator/\${USER} user=root" /etc/pam.d/system-auth /etc/pam.d/password-auth | tr "\n" " "')
check "GA lines active in system-auth + password-auth" "$out" "/etc/pam.d/system-auth:1 /etc/pam.d/password-auth:1 "

# --- two Kanidm users on the server (as Plan 4a ops), U in chp_users, AD in chp_admins + chp_users ----------------------
V2() { Vh "$SIP" "$@"; }
V2 'umask 077; mkdir -p ~/chp-lab; cat > ~/chp-lab/user.pub' < "$UKEY.pub"
sed 's#/tmp/srv1/#/root/chp-lab/#g' "$top/lab/srv1/enrol-user.exp" | V2 'cat > ~/chp-lab/enrol-user.exp'
V2 'cat > ~/chp-lab/totp.py' < "$top/lab/srv1/totp.py"
Rv 'install -d -m 0700 /root/chp-lab && cp /home/chpadmin/chp-lab/* /root/chp-lab/ && chmod 600 /root/chp-lab/* && rm -rf /home/chpadmin/chp-lab' >/dev/null
for _ in 1 2 3; do li=$(Rs 'printf "%s\n" "$CHP_SECRET" | expect /usr/libexec/chp/kanidm-login.exp idm_admin >/dev/null && echo LOGGEDIN' idm_admin); [[ $li == LOGGEDIN ]] && break; sleep 10; done
check "idm_admin login (retried: a first login can time out while Kanidm is busy)" "$li" "LOGGEDIN"
for x in "$U" "$AD"; do
  extra=""; [[ $x == "$AD" ]] && extra="--group chp_admins"
  Rv "chp-site onboard $x --display 'GA $x' --ssh-key /root/chp-lab/user.pub $extra" >/dev/null
  out=$(Rx "cd /root/chp-lab && tok=\$(sed -n 's/.*use-reset-token \([A-Za-z0-9-]*\).*/\1/p' /root/chp-onboard/$x.reset-token.txt | head -1) && pw=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))') && printf '%s\n%s\n%s\ntotp\n' \"\$tok\" \"\$pw\" \"\$CHP_SECRET\" | expect enrol-user.exp > $x.totp && echo ENROLLED")
  check "onboard + Kanidm enrolment: $x" "$out" "ENROLLED"
  Rv "cat /root/chp-onboard/$x-cert.pub" | A "sudo tee /tmp/iso2/$x-cert.pub >/dev/null"
done
Rv 'kanidm logout -D idm_admin' >/dev/null

# --- ga-enrol on the client (dev pyz), the secret to aero as the stand-in phone ----------------------------------------
for x in "$U" "$AD"; do
  out=$(Rc "python3 /root/chp-lab/chp-site-dev.pyz ga-enrol $x --no-confirm > /dev/null 2>/tmp/ge.err; echo rc=\$?; cat /tmp/ge.err; stat -c '%a %U %G' /var/lib/google-authenticator/$x; ls -Z /var/lib/google-authenticator/$x | cut -d: -f3")
  [[ $out == *rc=0*"400 root root"*var_auth_t* ]] && pass "ga-enrol $x: token 400 root root var_auth_t" || fail "ga-enrol $x" "$out"
  Rc "head -1 /var/lib/google-authenticator/$x" | A "sudo sh -c 'umask 077; cat > /tmp/iso2/$C-$x.ga'"
done

T0=$(Rc 'date +%H:%M:%S'); sleep 1
# 1. sshd_t: a real SSH login, certificate + code + password
fresh_window
out=$(A "sudo sh -c 'expect /tmp/iso2/ssh-ki.exp $CIP $U /tmp/iso2/ops_key /tmp/iso2/$U-cert.pub id /tmp/iso2/$C-$U.ga < /tmp/iso2/ops.pw'" | tr -d '\r' | grep -E '^(LOGIN_|PROMPTS=)' | tr '\n' ' ')
check "sshd: cert + code + Kanidm password" "$out" "PROMPTS=Verification code|Password LOGIN_OK $U "
check "sshd_t: AVC since $T0" "$(avc "$T0")" "0"
# 2. local_login_t: a real console login
fresh_window
code=$(A "sudo sh -c 'python3 /tmp/iso2/totp.py - sha1 < /tmp/iso2/$C-$U.ga'")
out=$(A "sudo sh -c '{ head -1 /tmp/iso2/ops.pw; echo $code; } | expect /tmp/iso2/console-login.exp $C $U'" | tr -d '\r' | grep -E '^(PROMPT|RESULT)' | tr '\n' ' ')
[[ $out == *"PROMPT: Verification code"*"PROMPT: Password"*"RESULT: logged in as $U"* ]] && pass "console login: code + password" || fail "console login" "$out"
check "local_login_t: AVC since $T0" "$(avc "$T0")" "0"
# 3. the gdm-password and login STACKS (pam-test runs as root, unconfined_t: proves the stack; xdm_t rights from policy)
for svc in gdm-password login; do
  fresh_window
  out=$(Rcx "code=\$(python3 /root/chp-lab/totp.py - sha1 < /var/lib/google-authenticator/$U); printf '%s\n%s\n' \"\$CHP_SECRET\" \"\$code\" | python3 /root/chp-lab/chp-site-dev.pyz pam-test $svc $U")
  [[ $out == "PAM_OK prompts="*"Verification code"*Password* ]] && pass "pam-test $svc $U: PAM_OK (code then password)" || fail "pam-test $svc" "$out"
done
fresh_window
out=$(Rcx "code=\$(python3 /root/chp-lab/totp.py - sha1 < /var/lib/google-authenticator/$AD); printf '%s\n%s\n' \"\$CHP_SECRET\" \"\$code\" | python3 /root/chp-lab/chp-site-dev.pyz pam-test sudo $AD")
[[ $out == "PAM_OK prompts="*"Verification code"* ]] && pass "pam-test sudo $AD: PAM_OK" || fail "pam-test sudo" "$out"
check "token after logins: 400 root root var_auth_t" "$(Rc "stat -c '%a %U %G' /var/lib/google-authenticator/$U; ls -Z /var/lib/google-authenticator/$U | cut -d: -f3" | tr '\n' ' ')" "400 root root var_auth_t "
check "all stacks: AVC since $T0" "$(avc "$T0")" "0"
# 4. break-glass quick check: local accounts never see a code prompt
check "chpadmin SSH key-only" "$(Vh "$CIP" 'echo ok')" "ok"
check "chpadmin + su - (escrowed root password; rootrun expects ONLY a Password prompt)" "$(Rc 'id -u')" "0"
out=$(A "sudo sh -c 'bash /tmp/iso2/stick.sh escrow $STICK $C.txt | sed -n s/^ROOT_CONSOLE_PASSWORD=//p | { cat; echo; } | expect /tmp/iso2/console-login.exp $C root'" | tr -d '\r' | grep -E '^(PROMPT|RESULT)' | tr '\n' ' ')
[[ $out == *"RESULT: logged in as root"* && $out != *erification* ]] && pass "root console: password only, no code" || fail "root console" "$out"
out=$(Rcx "printf '%s\n' wrongpw | python3 /root/chp-lab/chp-site-dev.pyz pam-test login $U")
[[ $out == "PAM_FAIL"*"Verification code"* ]] && pass "no bypass: a Kanidm user is always asked for the code" || fail "bypass check" "$out"
check "AVC since $T0 (whole run)" "$(avc "$T0")" "0"
exit "$fails"
