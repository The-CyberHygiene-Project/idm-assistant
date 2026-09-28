#!/usr/bin/env bash
# chp-access-prep.sh [HOST] [USER]  (RUNS ON THE MAC). Before the CHP kit's harden: the kit switches sshd to PAM-only
# (PasswordAuthentication no, KbdInteractiveAuthentication yes, AuthenticationMethods keyboard-interactive:pam), so an
# SSH-key-only admin is locked out the moment sshd reloads (seen 2026-09-28). Give USER a password and a Google
# Authenticator TOTP first. Secrets: ~/idm-lab-secrets/HOST-USER.json {posix_password, totp_secret, totp_algorithm}.
set -Eeuo pipefail
host="${1:-client1}"; user="${2:-itadmin}"; S=~/idm-lab-secrets/$host-$user.json
[[ -s $S ]] && { echo "$S exists; not re-enrolling"; exit 0; }
pw=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
printf '%s:%s\n' "$user" "$pw" | ssh "$host" 'sudo chpasswd'           # password via stdin, never argv
ssh -n "$host" 'rpm -q google-authenticator >/dev/null || sudo dnf -y -q install google-authenticator'
# Time-based, no reuse, rate-limited, minimal window, no QR on screen; the seed is the file's first line.
ssh -n "$host" "printf -- '-1\\n' | sudo -u $user google-authenticator -t -d -f -r 3 -R 30 -W -Q NONE -s /home/$user/.google_authenticator >/dev/null"   # -1 = skip the 'enter code from app' check
sec=$(ssh -n "$host" "sudo head -1 /home/$user/.google_authenticator")
[[ $sec =~ ^[A-Z2-7]{16,}$ ]] || { echo "unexpected seed format" >&2; exit 1; }
( umask 077; PW=$pw SEC=$sec OUT=$S python3 -c 'import json,os;e=os.environ;json.dump({"posix_password":e["PW"],"totp_secret":e["SEC"],"totp_algorithm":"sha1"},open(e["OUT"],"w"))' )
echo "$host/$user: password + Google Authenticator enrolled (secrets in $S)"
