#!/usr/bin/env bash
# RUNS ON THE MAC. Creates lab01-lab06 on srv1 (idm_admin session already logged in there) and enrols credentials
# with enrol-user.exp. Secrets: generated here, stored ONLY in ~/idm-lab-secrets/labNN.json (0600), fed over ssh stdin.
#   lab01-04: password + TOTP + POSIX password; lab05: no credential (WebAuthn: pending hardware);
#   lab06: password + TOTP + POSIX password. (A password-only primary credential was tried first: Kanidm 1.11.2
#   refuses to commit it - "Multi-factor authentication required" - recorded in the Q1/Q2 runtime notes.)
#   lab01 also in lab_admins.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; S=~/idm-lab-secrets
rsync -a "$here/" srv1:/tmp/srv1/
# Fresh idm_admin session first: an expired one makes every kanidm command try to prompt and panic (exit 101).
python3 -c 'import json,os;print(json.load(open(os.path.expanduser("~/idm-lab-secrets/idm_admin.json")))["password"])' \
  | ssh srv1 'expect /tmp/srv1/kanidm-login.exp idm_admin' >/dev/null
k() { ssh -n srv1 "kanidm $* -D idm_admin" >/dev/null 2>&1; }
for n in 1 2 3 4 5 6; do
  u=lab0$n
  if [[ -s $S/$u.json ]]; then echo "$u: already enrolled (secrets file present), skipped"; continue; fi
  # An existing account without a secrets file has credentials nobody holds (e.g. an aborted run): recreate it.
  if ssh -n srv1 "kanidm person get $u -D idm_admin 2>/dev/null | grep -q '^name: $u\$'"; then
    ssh -n srv1 "expect /tmp/srv1/kanidm-delete.exp person $u"   # delete asks y/n and panics without a terminal
  fi
  k person create "$u" "'Lab User $n'"
  k group add-members lab_users "$u"
  k person posix set "$u"
  [[ $n == 1 ]] && k group add-members lab_admins "$u"
  if [[ $n == 5 ]]; then echo '{"note":"no credential: WebAuthn pending hardware"}' > "$S/$u.json"; echo "$u: created, no credential (WebAuthn pending hardware)"; continue; fi
  mode=totp
  pw=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))'); upw=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
  tok=$(ssh -n srv1 "kanidm person credential create-reset-token $u -D idm_admin 2>&1" | grep -oE 'use-reset-token [a-z0-9-]+' | cut -d' ' -f2)
  [[ -n $tok ]] || { echo "$u: no reset token" >&2; exit 1; }
  out=$(printf '%s\n%s\n%s\n%s\n' "$tok" "$pw" "$upw" "$mode" | ssh srv1 'expect /tmp/srv1/enrol-user.exp')   # all secrets via stdin
  sec=$(sed -n 's/^TOTP_SECRET=//p' <<<"$out")
  umask 077
  [[ $mode != totp || -n $sec ]] || { echo "$u: TOTP enrolled but no secret captured" >&2; exit 1; }
  # Secrets go to python through the environment, not argv (argv is visible in ps).
  PW=$pw UPW=$upw SEC=$sec OUT=$S/$u.json python3 -c 'import json,os; e=os.environ; json.dump({"password":e["PW"],"posix_password":e["UPW"],"totp_secret":e["SEC"] or None,"totp_algorithm":"sha256"}, open(e["OUT"],"w"))'
  echo "$u: enrolled ($mode)"
done
