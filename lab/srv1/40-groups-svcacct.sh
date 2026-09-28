#!/usr/bin/env bash
# srv1, as itadmin with a logged-in idm_admin session: lab POSIX groups and the read-only unixd service account
# for CLIENT (default client2): 40-groups-svcacct.sh [CLIENT].
# Prints ONLY the new API token on stdout (captured by the Mac into ~/idm-lab-secrets); everything else goes to stderr.
set -Eeuo pipefail
c="${1:-client2}"; [[ $c =~ ^[a-z0-9]+$ ]] || { echo "bad client name" >&2; exit 1; }
k() { kanidm "$@" -D idm_admin 1>&2; }
# `kanidm … get` exits 0 even when nothing matches ("No matching …"), so look for the entry itself.
exists() { kanidm "$1" get "$2" -D idm_admin 2>/dev/null | grep -q "^name: $2$"; }
for g in lab_users lab_admins; do
  exists group "$g" || k group create "$g"
  k group posix set "$g"
done
exists service-account "unixd-$c" || k service-account create "unixd-$c" "unixd on $c" idm_admins
k group add-members idm_unix_authentication_read "unixd-$c"
kanidm service-account api-token generate "unixd-$c" "$c-unixd" -D idm_admin 2>/dev/null | grep -oE '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' | tail -1
