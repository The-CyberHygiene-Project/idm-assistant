#!/usr/bin/env bash
# plan2.sh STAGE (RUNS ON THE MAC): ISO 0.7.0 Plan 2 Task 9 lab driver, after lab/iso5/prove.sh's install chain
# (prep, server, firstboot, export, client1, client2, wazuh-on) on the 0.6.0-rc2 ISO. Root via each host's escrowed
# root console password (stick -> pipe on aero, as prove.sh's Rh); no lab adapter needed before the CUI scan.
#   repo        copy the owner-signed repo 0.12.0 to every host, unpack over /var/lib/chp/repo, dnf --refresh upgrade
#   docs-site   DOCUMENTS=yes in site.conf on the lab stick and on the server (/etc/chp/site.conf)
#   enable      Kanidm admin session (idm_admin) + stick attached + `chp-site documents enable` (in a transient unit,
#               log /root/docs-enable-<n>.log on the server; this prints it)
#   R CMD       run CMD as root on the server (output only)   /  RH VM IP CMD on any host
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
STICK=/data/libvirt/images/iso5-stick.img; KEY=~/idm-lab-secrets/iso2_chpadmin
SRV=iso5-srv; SIP=192.168.100.50; C1=iso5-cli1; C1IP=192.168.100.51; C2=iso5-cli2; C2IP=192.168.100.52
REPO_V=${REPO_V:-0.12.0}
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
Vh() { local ip=$1; shift; ssh -o BatchMode=yes -J aero -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "chpadmin@$ip" "$@" 2>/dev/null; }
Rh() { local b; b=$(printf '%s' "$3" | base64 | tr -d '\n')
  A "sudo bash /tmp/iso2/stick.sh escrow $STICK $1.txt | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p' | expect /tmp/iso2/rootrun.exp $2 /tmp/iso2/iso2_chpadmin $b" \
    | tr -d '\r' | sed '/^[[:space:]]*$/d'; }
Rs() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n'); A "sudo bash /tmp/iso2/rs.sh $STICK $SRV $SIP $2 $b" | tr -d '\r' | sed '/^[[:space:]]*$/d'; }
# long command on a host: a transient root unit writing LOG; wait for it (<= 60 min) and print the log
Rlong() { local vm=$1 ip=$2 unit=$3 cmd=$4 log=/root/$3.log
  Rh "$vm" "$ip" "systemctl reset-failed $unit 2>/dev/null; systemd-run --unit=$unit -E HOME=/root -p WorkingDirectory=/root bash -c $(printf %q "($cmd) > $log 2>&1; echo EXIT=\$? >> $log")" >/dev/null
  for _ in $(seq 240); do sleep 15; [[ $(Rh "$vm" "$ip" "grep -c '^EXIT=' $log 2>/dev/null") == 1* ]] && break; done
  Fetch "$vm" "$ip" "$log"; }
# like Rlong, but detached from the root console shell (keeps the admin shell's SELinux context, unconfined_t)
Rbg() { local vm=$1 ip=$2 name=$3 cmd=$4 log=/root/$3.log
  Rh "$vm" "$ip" "rm -f $log; HOME=/root setsid nohup bash -c $(printf %q "($cmd) > $log 2>&1; echo EXIT=\$? >> $log") >/dev/null 2>&1 < /dev/null & sleep 1; echo started" >/dev/null
  for _ in $(seq 240); do sleep 15; [[ $(Rh "$vm" "$ip" "grep -c '^EXIT=' $log 2>/dev/null") == 1* ]] && break; done
  Fetch "$vm" "$ip" "$log"; }
# Rh output passes through expect (buffer ~2 KB): large root files are fetched instead (copied to chpadmin's home, read, removed)
Fetch() { local vm=$1 ip=$2 f=$3 n; n=lab-fetch-$RANDOM
  Rh "$vm" "$ip" "install -m 0600 -o chpadmin $f /home/chpadmin/$n" >/dev/null; Vh "$ip" "cat ~/$n; rm -f ~/$n"; }
H() { ssh -F "$here/../iso5/ssh_config" -o BatchMode=yes srv1 "$@" 2>/dev/null; }
case ${1:-} in
  repo)
    A "cd /data/chp-release/$REPO_V && tar -czf /tmp/iso2/repo-$REPO_V.tgz repo && chmod 644 /tmp/iso2/repo-$REPO_V.tgz"
    for h in "$SRV $SIP" "$C1 $C1IP" "$C2 $C2IP"; do set -- $h
      A "scp -q -i /tmp/iso2/iso2_chpadmin -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /tmp/iso2/repo-$REPO_V.tgz chpadmin@$2:/home/chpadmin/repo.tgz"
      echo "== $1"
      Rlong "$1" "$2" lab-repo-upgrade "rm -rf /var/lib/chp/repo/* && tar -xzf /home/chpadmin/repo.tgz -C /var/lib/chp/repo --strip-components=1 && rm -f /home/chpadmin/repo.tgz && dnf --refresh -y --enablerepo=chp upgrade; rpm -q chp-site chp-base chp-identity-server chp-identity-client chp-security; ls -l /var/lib/chp/fapolicyd-restart-pending 2>&1; fapolicyd-cli --check-status 2>/dev/null | grep -E '^Denied|^Allowed'"
    done ;;
  docs-site)
    A "sudo bash -c 'm=\$(mktemp -d); mount -o loop $STICK \$m && { grep -q ^DOCUMENTS= \$m/site.conf || echo DOCUMENTS=yes >> \$m/site.conf; grep ^DOCUMENTS= \$m/site.conf; sync; umount \$m; }; rmdir \$m'"
    Rh "$SRV" "$SIP" 'grep -q ^DOCUMENTS= /etc/chp/site.conf || echo DOCUMENTS=yes >> /etc/chp/site.conf; grep ^DOCUMENTS= /etc/chp/site.conf; chp-site validate --site /etc/chp' ;;
  login)
    for _ in 1 2 3; do li=$(Rs 'printf "%s\n" "$CHP_SECRET" | expect /usr/libexec/chp/kanidm-login.exp idm_admin >/dev/null && echo LOGGEDIN' idm_admin); [[ $li == *LOGGEDIN* ]] && break; sleep 10; done
    echo "kanidm login: $li" ;;
  enable)
    n=${2:-1}
    bash "$0" login
    A "sudo virsh attach-disk $SRV $STICK sdz --targetbus usb --type disk --live >/dev/null && echo stick-attached"; sleep 6
    # run 1 showed: files written from a transient unit get etc_runtime_t (init_t), not etc_t as from a root shell
    # (logs/15): a LAB artifact; and runcon from the unit is refused. So run it from the root console shell itself,
    # detached (setsid nohup), as an admin's terminal would, and wait for its log.
    Rbg "$SRV" "$SIP" "docs-enable-$n" "date -u +%FT%TZ; chp-site documents enable; echo enable-rc=\$?; date -u +%FT%TZ"
    A "sudo virsh detach-disk $SRV sdz --live >/dev/null && echo stick-detached" ;;
  # ---- after the lab adapter + fixtures: the harness ssh_config (chpadmin + adapter sudo) ----
  groups)   # Kanidm memberships of the lab users: lab01 cui-users; lab02 none; lab03 doc-reviewers; lab04 both
    H "sudo kanidm group add-members cui-users lab01 lab04 -D idm_admin && sudo kanidm group add-members doc-reviewers lab03 lab04 -D idm_admin && for g in cui-users doc-reviewers chp_users; do sudo kanidm group get \$g -D idm_admin | grep -E '^(name|member):' | sed 's/@.*//' | tr '\n' ' '; echo; done" ;;
  tunnel)   # NextCloud :8443 -> 18443, Kanidm :443 -> 18444 on the Mac
    pkill -f "18443:$SIP:8443" 2>/dev/null; ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -f -N -L 18443:$SIP:8443 -L 18444:$SIP:443 aero && echo "tunnel up" ;;
  ca)       H 'cat /etc/pki/ca-trust/source/anchors/chp-root.crt' > ~/idm-lab-secrets/iso5-root-ca.pem; grep -c "BEGIN CERTIFICATE" ~/idm-lab-secrets/iso5-root-ca.pem ;;
  signin)   # signin USER [extra oidc_login args]: scripted browser sign-in through Kanidm (password + TOTP from the fixtures file)
    u=$2; shift 2
    python3 -c 'import json,os,sys; d=json.load(open(os.path.expanduser(f"~/idm-lab-secrets/iso5-{sys.argv[1]}.json"))); d["user"]=sys.argv[1]; print(json.dumps(d))' "$u" \
      | python3 -I "$here/oidc_login.py" ~/idm-lab-secrets/iso5-root-ca.pem 18443 18444 "$@" ;;
  apppw)    # an app password per lab user -> ~/idm-lab-secrets/iso5-nc-<u>-app.txt (0600, never printed)
    for u in ${2:-lab01 lab02 lab03 lab04}; do
      H "sudo occ user:auth-tokens:add -n --name plan2-lab $u" | tail -1 | (umask 077; cat > ~/idm-lab-secrets/iso5-nc-$u-app.txt)
      [[ $(wc -c < ~/idm-lab-secrets/iso5-nc-$u-app.txt) -gt 20 ]] && echo "app password for $u stored (0600, not printed)" || echo "FAIL app password $u"
    done ;;
  proofs)   shift; python3 -I "$here/proofs.py" ~/idm-lab-secrets/iso5-root-ca.pem 18443 "$@" ;;
  H)        shift; H "$*" ;;
  R)  shift; Rh "$SRV" "$SIP" "$*" | sed '/^RC=/d' ;;
  RH) shift; vm=$1 ip=$2; shift 2; Rh "$vm" "$ip" "$*" | sed '/^RC=/d' ;;
  RL) shift; Rlong "$SRV" "$SIP" "$1" "$2" ;;
  RLH) shift; Rlong "$1" "$2" "$3" "$4" ;;
  RBG) shift; Rbg "$1" "$2" "$3" "$4" ;;
  fetch) shift; Fetch "$@" ;;
  fsmark)   # fsmark VM IP PHASE: lab/docs-proof/fsmark-trial.sh PHASE on that host (as a transient unit)
    b=$(base64 < "$here/fsmark-trial.sh" | tr -d '\n')
    Rh "$2" "$3" "echo $b | base64 -d > /root/fsmark-trial.sh" >/dev/null
    Rlong "$2" "$3" "lab-fsmark-$4-$(date +%H%M%S)" "bash /root/fsmark-trial.sh $4" ;;
  *) echo "usage: $0 repo|docs-site|login|enable [N]|R CMD|RH VM IP CMD|RL UNIT CMD"; exit 2 ;;
esac
