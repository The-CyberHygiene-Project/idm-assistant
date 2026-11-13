#!/usr/bin/env bash
# kanidm.sh STAGE (RUNS ON THE MAC): Kanidm side of the spike, on iso5-docs (kanidm CLI logged in as idm_admin).
#   login    log the server's kanidm CLI in as idm_admin (password: ~/idm-lab-secrets/docs-idm_admin.json, over stdin)
#   users    groups cui-users + doc-reviewers; people lab01..lab04 with a Kanidm password + TOTP (their ONE extra
#            credential); lab01 also POSIX (host sign-in, row 36). Secrets -> ~/idm-lab-secrets/docs-<user>.json (0600)
#   oauth2   the NextCloud OAuth2/OIDC client; its secret -> /root/spike/oidc-secret on the server only (never printed)
#   show     the client's settings (no secret)
# Every kanidm command is echoed (that IS the record of "the exact Kanidm commands"); no secret is ever an argument.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; F="$here/ssh_config"; S=~/idm-lab-secrets
X() { ssh -F "$F" -o BatchMode=yes docs "$@"; }
K() { echo "+ kanidm $* -D idm_admin" >&2; X "sudo kanidm $(printf '%q ' "$@") -D idm_admin"; }
ORIGIN=https://files.docs.lab.test:8443
# user -> groups (all are in chp_users, the site's login group) and enrolment mode
grp() { case $1 in lab01) echo cui-users ;; lab03) echo doc-reviewers ;; lab04) echo doc-reviewers cui-users ;; esac; }
mode() { [[ $1 == lab01 ]] && echo totp || echo totp-no-posix; }   # (macOS bash 3.2: no associative arrays)
case ${1:-} in
  login)
    python3 -c 'import json,os; print(json.load(open(os.path.expanduser("~/idm-lab-secrets/docs-idm_admin.json")))["password"])' \
      | X 'sudo expect /usr/libexec/chp/kanidm-login.exp idm_admin' ;;
  users)
    for g in cui-users doc-reviewers; do K group get "$g" 2>/dev/null | grep -q "^name: $g" || K group create "$g"; done
    for u in lab01 lab02 lab03 lab04; do
      K person get "$u" 2>/dev/null | grep -q "^name: $u" || K person create "$u" "Docs Lab ${u#lab}"
      K group add-members chp_users "$u"
      for g in $(grp $u); do K group add-members "$g" "$u"; done
      [[ $(mode $u) == totp ]] && K person posix set "$u"
      tok=$(K person credential create-reset-token "$u" | grep -oE 'use-reset-token [A-Za-z0-9-]+' | awk '{print $2}')
      [[ -n $tok ]] || { echo "FAIL $u: no reset token"; exit 1; }
      pw=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))'); upw=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
      out=$(printf '%s\n%s\n%s\n%s\n' "$tok" "$pw" "$upw" "$(mode $u)" | X 'sudo expect /root/k/enrol-user.exp')
      sec=$(sed -n 's/^TOTP_SECRET=//p' <<<"$out"); [[ -n $sec ]] || { echo "FAIL $u: enrolment"; exit 1; }
      PW=$pw UPW=$upw SEC=$sec U=$u MODE=$(mode $u) python3 -c 'import json,os
p=os.path.expanduser(f"~/idm-lab-secrets/docs-{os.environ["U"]}.json"); fd=os.open(p, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)
d={"user": os.environ["U"], "password": os.environ["PW"], "totp_secret": os.environ["SEC"], "totp_algorithm": "sha256"}
if os.environ["MODE"] == "totp": d["posix_password"] = os.environ["UPW"]
os.write(fd, json.dumps(d).encode()); os.close(fd)'
      echo "PASS $u: Kanidm person, password + TOTP$( [[ $(mode $u) == totp ]] && echo ' + POSIX'); groups: chp_users $(grp $u)"
    done ;;
  oauth2)
    K system oauth2 get nextcloud 2>/dev/null | grep -q "^name: nextcloud" || K system oauth2 create nextcloud "NextCloud" "$ORIGIN"
    K system oauth2 add-redirect-url nextcloud "$ORIGIN/index.php/apps/user_oidc/code"
    K system oauth2 update-scope-map nextcloud chp_users openid profile email groups
    K system oauth2 prefer-short-username nextcloud
    # clean group names in their own claim (the standard "groups" claim carries name@domain SPNs and UUIDs)
    K system oauth2 update-claim-map nextcloud chp_groups cui-users cui-users
    K system oauth2 update-claim-map nextcloud chp_groups doc-reviewers doc-reviewers
    K system oauth2 update-claim-map-join nextcloud chp_groups array
    echo "+ kanidm system oauth2 show-basic-secret nextcloud -D idm_admin > /root/spike/oidc-secret (0600, never printed)" >&2
    X 'sudo sh -c "umask 077; kanidm system oauth2 show-basic-secret nextcloud -D idm_admin | tail -1 > /root/spike/oidc-secret; wc -c < /root/spike/oidc-secret"' ;;
  show) K system oauth2 get nextcloud | grep -viE "secret|key" ;;
  *) echo "usage: $0 login|users|oauth2|show"; exit 2 ;;
esac
