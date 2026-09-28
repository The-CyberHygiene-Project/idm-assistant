#!/usr/bin/env bash
# install-collect-token.sh (RUNS ON THE MAC): install the read-only collector token on srv1 via stdin.
# The token never appears in argv or in the repo; source: ~/idm-lab-secrets/idm-collect.token (0600).
set -Eeuo pipefail
tok=~/idm-lab-secrets/idm-collect.token
[[ -s $tok ]] || { echo "missing $tok (run 45-diag-svcacct.sh first)" >&2; exit 1; }
ssh -o BatchMode=yes srv1 'sudo sh -c "install -d -m 0700 /etc/idm-collect && umask 077 && cat > /etc/idm-collect/kanidm.token.new && mv /etc/idm-collect/kanidm.token.new /etc/idm-collect/kanidm.token"' < "$tok"
echo "installed /etc/idm-collect/kanidm.token on srv1"
