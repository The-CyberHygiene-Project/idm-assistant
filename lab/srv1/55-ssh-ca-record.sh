#!/usr/bin/env bash
# 55-ssh-ca-record.sh (on srv1, as root): directories where the SSH CA records what it issues (public data only):
#   /var/lib/ssh-ca/keys/<user>.pub         the user's REGISTERED public key (the only key re-issue may sign)
#   /var/lib/ssh-ca/issued/<user>-cert.pub  the newest certificate issued to <user> (read by idm-collect)
set -Eeuo pipefail
install -d -m 0755 /var/lib/ssh-ca /var/lib/ssh-ca/keys /var/lib/ssh-ca/issued
restorecon -R /var/lib/ssh-ca
ls -ldZ /var/lib/ssh-ca/keys /var/lib/ssh-ca/issued
