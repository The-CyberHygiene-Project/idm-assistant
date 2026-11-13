#!/usr/bin/env bash
# proto/auth-setup.sh STAGE (RUNS ON THE MAC; Task 2 SPIKE, throwaway): server side of the doc commands' sign-in routes.
#   discovery  what Kanidm 1.11 offers a CLI (device flow? public clients? localhost redirects?)
#   kanidm     a PUBLIC Kanidm OAuth2 client "chp-doc" (PKCE, localhost redirects, same scope/claim maps as nextcloud)
#   nextcloud  a second user_oidc provider "kanidm-cli" for chp-doc that only CHECKS BEARER tokens (no login button use)
#   show       both clients and providers (no secrets)
# Every kanidm/occ command is echoed; no secret is ever printed (a public client has none).
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; F="$here/ssh_config"
X() { ssh -F "$F" -o BatchMode=yes docs "$@"; }
K() { echo "+ kanidm $* -D idm_admin" >&2; X "sudo kanidm $(printf '%q ' "$@") -D idm_admin"; }
O() { echo "+ occ $*" >&2; X "sudo occ $(printf '%q ' "$@")"; }
ORIGIN=https://files.docs.lab.test:8443
case ${1:-} in
  discovery)
    for c in nextcloud; do
      echo "+ GET https://idm.docs.lab.test/oauth2/openid/$c/.well-known/openid-configuration (keys of interest)"
      X "curl -s https://idm.docs.lab.test/oauth2/openid/$c/.well-known/openid-configuration" | python3 -c '
import json,sys; d=json.load(sys.stdin)
for k in ("grant_types_supported","token_endpoint_auth_methods_supported","code_challenge_methods_supported","revocation_endpoint","introspection_endpoint"):
    print(f"  {k}: {d.get(k)}")
print("  device_authorization_endpoint:", d.get("device_authorization_endpoint", "ABSENT (no RFC 8628 device flow)"))'
    done
    echo "+ curl -s -o /dev/null -w %{http_code} -X POST https://idm.docs.lab.test/oauth2/device (guess at a device endpoint)"
    X 'curl -s -o /dev/null -w "  -> %{http_code}\n" -X POST -d client_id=nextcloud https://idm.docs.lab.test/oauth2/device'
    X 'sudo kanidm system oauth2 --help -D idm_admin' | grep -E 'create-public|localhost|refresh-token' ;;
  kanidm)
    K system oauth2 get chp-doc 2>/dev/null | grep -q '^name: chp-doc' || K system oauth2 create-public chp-doc "CHP doc commands" "$ORIGIN"
    K system oauth2 enable-localhost-redirects chp-doc
    K system oauth2 add-redirect-url chp-doc http://localhost:8400/callback
    K system oauth2 update-scope-map chp-doc chp_users openid profile groups
    K system oauth2 prefer-short-username chp-doc
    K system oauth2 update-claim-map chp-doc chp_groups cui-users cui-users
    K system oauth2 update-claim-map chp-doc chp_groups doc-reviewers doc-reviewers
    K system oauth2 update-claim-map chp-doc chp_groups chp_users chp-users
    K system oauth2 update-claim-map-join chp-doc chp_groups array
    K system oauth2 set-refresh-token-expiry chp-doc 28800
    K system oauth2 get chp-doc | grep -vi secret ;;
  nextcloud)
    # a public client has no secret; user_oidc insists on one, and never uses it for a bearer-only provider
    O user_oidc:provider kanidm-cli --clientid=chp-doc --clientsecret=unused-public-client \
      --discoveryuri=https://idm.docs.lab.test/oauth2/openid/chp-doc/.well-known/openid-configuration \
      --mapping-uid=preferred_username --unique-uid=0 --check-bearer=1 --bearer-provisioning=0 \
      --mapping-groups=chp_groups --scope='openid profile groups'
    # Kanidm's access token (typ at+jwt, ES256) carries sub (a UUID) but NOT preferred_username, so the self-encoded
    # check finds no user id (logs/45); ask Kanidm's userinfo endpoint instead (every API call, so a Kanidm-side
    # revocation is felt at once). The self-encoded check is switched off so a token is never mapped by sub.
    O config:system:set user_oidc userinfo_bearer_validation --type=boolean --value=true
    O config:system:set user_oidc selfencoded_bearer_validation --type=boolean --value=false
    O user_oidc:provider ;;
  show)
    K system oauth2 get chp-doc | grep -vi secret; O user_oidc:provider ;;
  *) echo "usage: $0 discovery|kanidm|nextcloud|show"; exit 2 ;;
esac
