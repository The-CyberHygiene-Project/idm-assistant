#!/usr/bin/env bash
# srv1, as itadmin with a logged-in idm_admin session: the collector's READ-ONLY Kanidm service account.
# Least privilege, found empirically on Kanidm 1.11.2 (Plan 5 Task 4):
#   no groups                     -> the person is invisible
#   idm_unix_authentication_read  -> posix visible; unix_password + primary_credential HIDDEN (false "missing")
#   + idm_people_pii_read / idm_people_admins -> still hidden
#   idm_service_desk              -> primary_credential visible
#   idm_unix_admins               -> unix_password visible
# Both needed groups can write; the API token is generated WITHOUT --readwrite, so writes are refused (HTTP 403,
# proven). Prints ONLY the new token on stdout (the Mac stores it in ~/idm-lab-secrets and installs it via stdin).
set -Eeuo pipefail
k() { kanidm "$@" -D idm_admin 1>&2; }
kanidm service-account get idm-collect -D idm_admin 2>/dev/null | grep -q '^name: idm-collect$' \
  || k service-account create idm-collect "idm-assistant read-only collector" idm_admins
for g in idm_service_desk idm_unix_admins; do k group add-members "$g" idm-collect; done
kanidm service-account api-token generate idm-collect collector-ro -D idm_admin 2>/dev/null \
  | grep -oE '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' | tail -1
