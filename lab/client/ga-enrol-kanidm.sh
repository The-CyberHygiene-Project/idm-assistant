#!/usr/bin/env bash
# ga-enrol-kanidm.sh HOST USER  (RUNS ON THE MAC): Google Authenticator for a KANIDM user on a CHP-kit host.
# Creates the user's home (root su -> pam_kanidm/unixd-tasks + mkhomedir), enrols a TOTP as the user (seed never
# echoed), and writes ~/idm-lab-secrets/HOST-USER.json = {posix_password (from USER.json), totp_secret, sha1}.
set -Eeuo pipefail
host="${1:?host}"; user="${2:?user}"; S=~/idm-lab-secrets; out=$S/$host-$user.json
[[ $user =~ ^lab0[0-9]$ ]] || { echo "lab users only" >&2; exit 1; }
[[ -s $S/$user.json ]] || { echo "no Kanidm secrets for $user" >&2; exit 1; }
ssh -n "$host" "sudo su - $user -c true >/dev/null 2>&1 || true; getent passwd $user | cut -d: -f6" > /tmp/ga-home.$$
home=$(tail -1 /tmp/ga-home.$$); rm -f /tmp/ga-home.$$
[[ $home == /home/* ]] || { echo "no home for $user ($home)" >&2; exit 1; }
# shellcheck disable=SC2029  # values expand on the Mac by design (validated above)
ssh -n "$host" "set -e; sudo test -d '$home'; printf -- '-1\\n' | sudo -u $user google-authenticator -t -d -f -r 3 -R 30 -W -Q NONE -s '$home/.google_authenticator' >/dev/null"
# shellcheck disable=SC2029
sec=$(ssh -n "$host" "sudo head -1 '$home/.google_authenticator'")
[[ $sec =~ ^[A-Z2-7]{16,}$ ]] || { echo "unexpected seed format" >&2; exit 1; }
( umask 077; SEC=$sec IN=$S/$user.json OUT=$out python3 -c 'import json,os;e=os.environ;d=json.load(open(e["IN"]));json.dump({"posix_password":d["posix_password"],"totp_secret":e["SEC"],"totp_algorithm":"sha1"},open(e["OUT"],"w"))' )
echo "$host/$user: GA enrolled in $home (secrets $out)"
