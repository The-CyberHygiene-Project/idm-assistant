#!/usr/bin/env bash
# plan3.sh STAGE (RUNS ON THE MAC): ISO 0.7.0 Plan 3 Task 11c lab driver (controlled-document workflow), after
# lab/iso5/prove.sh's install chain on the 0.6.0-rc2 ISO. Reuses plan2.sh (repo, docs-site, login, enable, R/RH/RL/RBG,
# tunnel, ca, signin, apppw) and adds what Plan 3 needs:
#   repo            the owner-signed repo 0.13.0 on every host (plan2.sh repo with REPO_V=0.13.0) + the versions
#   sitekeys K=V..  set (or, with K=, clear) site keys on the lab stick's site.conf AND the server's /etc/chp/site.conf
#   wskeys VM IP K=V..  the same keys in a workstation's /etc/chp/site.conf (the lab stand-in for enrolling it with the
#                   new stick: the clients were enrolled from the 0.6.0 stick)
#   ooenable VM IP N    `chp-site onlyoffice enable` on a workstation (root console shell, detached; log printed)
#   W CMD           client2 through the harness ssh_config (chpadmin + lab adapter sudo), after the adapter
#   anchor U        client2: a lasting logind session for lab user U (systemd-run -p PAMName=login -p User=U: a logind session in unconfined_t, as a real login; su from a unit exits 203), so /run/user/<uid> and the
#                   doc tokens outlive single commands, as a desktop session would
#   U USER CMD      client2: CMD as USER in a NEW logind session (systemd-run --wait --pipe, PAMName=login); stdout+stderr
#   login USER      client2: `chp-site doc login` as USER, signed in by doc_browser.py with the user's lab password +
#                   TOTP (fixtures file ~/idm-lab-secrets/iso5-USER.json, via a 0600 file in the user's runtime dir)
#   unanchor U      end the anchor session (the tokens go with the last session)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"
STICK=/data/libvirt/images/iso5-stick.img
SRV=iso5-srv; SIP=192.168.100.50; C1=iso5-cli1; C1IP=192.168.100.51; C2=iso5-cli2; C2IP=192.168.100.52
P2="$here/plan2.sh"
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
W() { ssh -F "$top/lab/iso5/ssh_config" -o BatchMode=yes client2 "$@" 2>/dev/null; }
# keys K=V ... -> a sed program file body (one key per line: replace, add, or delete with K=)
keyprog() { local kv k v; for kv in "$@"; do k=${kv%%=*}; v=${kv#*=}
  if [[ -z $v ]]; then printf 'sed -i "/^%s=/d" "$f"\n' "$k"
  else printf 'if grep -q "^%s=" "$f"; then sed -i "s|^%s=.*|%s=%s|" "$f"; else echo "%s=%s" >> "$f"; fi\n' "$k" "$k" "$k" "$v" "$k" "$v"; fi; done; }
uid_of() { W "id -u $1"; }
case ${1:-} in
  repo)
    REPO_V=0.13.0 bash "$P2" repo
    for h in "$SRV $SIP" "$C1 $C1IP" "$C2 $C2IP"; do set -- $h; echo "== $1"
      bash "$P2" RH "$1" "$2" 'rpm -q chp-site chp-base chp-integrity chp-identity-client chp-templates chp-documents nextcloud-chp chp-onlyoffice 2>&1 | tr "\n" " "; echo'
    done ;;
  sitekeys)
    shift; prog=$(keyprog "$@"); b=$(printf '%s' "$prog" | base64 | tr -d '\n')
    A "sudo bash -c 'm=\$(mktemp -d); mount -o loop $STICK \$m && { f=\$m/site.conf; echo $b | base64 -d > /tmp/kp.sh; . /tmp/kp.sh; rm -f /tmp/kp.sh; grep -E \"^(DOCUMENTS|DOC_|CUI_|SECURITY_ALERT_LEVEL|ALERT_HOOK)\" \$f | sed \"s/^/stick: /\"; sync; umount \$m; }; rmdir \$m'"
    bash "$P2" R "f=/etc/chp/site.conf; echo $b | base64 -d > /root/kp.sh; . /root/kp.sh; rm -f /root/kp.sh; restorecon \$f; grep -E '^(DOCUMENTS|DOC_|CUI_|SECURITY_ALERT_LEVEL|ALERT_HOOK)' \$f | sed 's/^/server: /'; chp-site validate --site /etc/chp" ;;
  wskeys)
    vm=$2 ip=$3; shift 3; prog=$(keyprog "$@"); b=$(printf '%s' "$prog" | base64 | tr -d '\n')
    bash "$P2" RH "$vm" "$ip" "f=/etc/chp/site.conf; echo $b | base64 -d > /root/kp.sh; . /root/kp.sh; rm -f /root/kp.sh; restorecon \$f; grep -E '^(DOCUMENTS|DOC_|CUI_)' \$f | sed 's/^/$vm: /'; chp-site validate --site /etc/chp" ;;
  ooenable)
    bash "$P2" RBG "$2" "$3" "oo-enable-$4" "date -u +%FT%TZ; chp-site onlyoffice enable; echo enable-rc=\$?; date -u +%FT%TZ" ;;
  W) shift; W "$*" ;;
  anchor)
    W "sudo systemctl reset-failed lab-anchor-$2 2>/dev/null; sudo systemd-run --quiet --unit=lab-anchor-$2 -p PAMName=login -p User=$2 /usr/bin/sleep infinity; sleep 2; u=\$(id -u $2); loginctl list-sessions --no-legend | grep -c \" $2 \"; stat -c '%U %a' /run/user/\$u; findmnt -no FSTYPE /run/user/\$u" ;;
  unanchor) W "sudo systemctl stop lab-anchor-$2; sleep 2; ls -d /run/user/\$(id -u $2) 2>&1 | sed 's/^/runtime dir: /'" ;;
  U)  u=$2; shift 2; c=$(printf '%s' "$*" | base64 | tr -d '\n')
      W "sudo systemd-run --quiet --wait --pipe --collect -p PAMName=login -p User=$u /bin/bash -lc \"cd; { \$(echo $c | base64 -d); } 2>&1\"" ;;
  login)
    u=$2; uid=$(uid_of "$u"); mode=${3:-sign}
    W "sudo install -m 0600 -o $u /dev/stdin /run/user/$uid/lab-cred.json" \
      < <(python3 -c 'import json,os,sys; d=json.load(open(os.path.expanduser(f"~/idm-lab-secrets/iso5-{sys.argv[1]}.json"))); d["user"]=sys.argv[1]; print(json.dumps(d))' "$u")
    W "sudo systemctl reset-failed lab-login-$u 2>/dev/null; sudo rm -f /run/user/$uid/lab-login.out; sudo systemd-run --quiet --unit=lab-login-$u -p PAMName=login -p User=$u /bin/bash -lc 'cd; PYTHONUNBUFFERED=1 chp-site doc login > /run/user/$uid/lab-login.out 2>&1; echo EXIT=\$? >> /run/user/$uid/lab-login.out'"
    url=""; for _ in $(seq 30); do url=$(W "sudo grep -o 'https://[^ ]*/ui/oauth2?[^ ]*' /run/user/$uid/lab-login.out 2>/dev/null | head -1"); [[ -n $url ]] && break; sleep 1; done
    [[ -n $url ]] || { echo "FAILED: no sign-in URL printed"; W "sudo cat /run/user/$uid/lab-login.out"; exit 1; }
    echo "sign-in URL printed (redirect_uri $(python3 -c 'import sys,urllib.parse as u; print(u.parse_qs(u.urlsplit(sys.argv[1]).query)["redirect_uri"][0])' "$url"))"
    # the scripted browser runs as root (it only needs Kanidm and the loopback port; the script comes on stdin, so
    # fapolicyd never sees an untrusted .py file open)
    W "cd /tmp && sudo env LAB_CRED=/run/user/$uid/lab-cred.json LAB_BROWSER_LOG=/run/user/$uid/lab-browser.log LAB_BROWSER_MODE=$mode python3 -I - '$url'" < "$here/doc_browser.py"
    for _ in $(seq 60); do W "sudo grep -q ^EXIT= /run/user/$uid/lab-login.out" && break; sleep 2; done
    W "sudo cat /run/user/$uid/lab-browser.log 2>/dev/null | sed 's/^/browser: /'; sudo rm -f /run/user/$uid/lab-browser.log /run/user/$uid/lab-cred.json; sudo grep -v 'https://' /run/user/$uid/lab-login.out" ;;
  *) exec bash "$P2" "$@" ;;
esac
