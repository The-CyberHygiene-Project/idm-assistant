#!/usr/bin/env bash
# folders.sh STAGE (RUNS ON THE MAC): team folders, tags and sharing settings on iso5-docs, all by occ (scriptable;
# no web UI, no app password). Kanidm groups arrive through the chp_groups claim (kanidm.sh oauth2 + chp-users below).
#   groups    Kanidm: chp_users -> "chp-users" in the claim; NextCloud's user_oidc whitelist gains chp-users
#   folders   CUI, FCI, Archive (cui-users: read write delete, NO share; groupfolders' "write" = update + create) and Operations, Internal, Public
#             (chp-users: read write delete share); advanced permissions on; doc-reviewers read-only by ACL
#   tags      system tags CUI and FCI: visible, NOT user-assignable (only admins can add or remove them);
#             chp_foldertag rules {CUI folder: CUI tag, FCI folder: FCI tag}
#   apppw     an app password per lab user (occ user:auth-tokens:add) -> ~/idm-lab-secrets/docs-<user>-app.txt (0600)
#   show      the folder list (json) and the tag list
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; F="$here/ssh_config"
X() { ssh -F "$F" -o BatchMode=yes docs "$@"; }
O() { echo "+ occ $*" >&2; X "sudo occ $(printf '%q ' "$@")"; }
fid() { X "sudo occ groupfolders:list --output=json" | python3 -c 'import json,sys; n=sys.argv[1]; print(next((str(f["id"]) for f in json.load(sys.stdin) if f["mountPoint"]==n), ""))' "$1"; }
case ${1:-} in
  groups)
    echo "+ kanidm system oauth2 update-claim-map nextcloud chp_groups chp_users chp-users -D idm_admin" >&2
    X 'sudo kanidm system oauth2 update-claim-map nextcloud chp_groups chp_users chp-users -D idm_admin'
    O user_oidc:provider kanidm --group-whitelist-regex='^(cui-users|doc-reviewers|chp-users)$' >/dev/null
    X 'sudo occ group:info chp-users >/dev/null 2>&1' || O group:add chp-users ;;   # made now so folders can name it
  folders)
    for n in CUI FCI Archive Operations Internal Public; do
      id=$(fid "$n"); [[ -n $id ]] || id=$(O groupfolders:create "$n")
      case $n in
        CUI|FCI|Archive) O groupfolders:group "$id" cui-users read write delete ;;   # no "share"
        *)               O groupfolders:group "$id" chp-users read write delete share ;;
      esac
      O groupfolders:permissions "$id" --enable
      # the reviewer layer: an ACL on the folder root for doc-reviewers that takes away everything but read
      O groupfolders:permissions "$id" --group doc-reviewers -- / +read -write -create -delete -share
      echo "folder $n = id $id"
    done ;;
  tags)
    for t in CUI FCI; do
      X "sudo occ tag:list --output=json" | grep -q "\"$t\"" || O tag:add "$t" restricted
    done
    tags=$(X "sudo occ tag:list --output=json")
    cui=$(python3 -c 'import json,sys; print(next(k for k,v in json.loads(sys.argv[1]).items() if v["name"]==sys.argv[2]))' "$tags" CUI)
    fci=$(python3 -c 'import json,sys; print(next(k for k,v in json.loads(sys.argv[1]).items() if v["name"]==sys.argv[2]))' "$tags" FCI)
    rules="{\"$(fid CUI)\":\"$cui\",\"$(fid FCI)\":\"$fci\"}"
    O config:app:set chp_foldertag rules --value="$rules"
    echo "tag ids: CUI=$cui FCI=$fci; rules=$rules" ;;
  apppw)
    for u in lab01 lab02 lab03 lab04; do
      X "sudo occ user:auth-tokens:add -n --name spike $u" | tail -1 \
        | (umask 077; cat > ~/idm-lab-secrets/docs-$u-app.txt)
      [[ -s ~/idm-lab-secrets/docs-$u-app.txt ]] && echo "app password for $u stored (0600, not printed)" || echo "FAIL app password $u"
    done ;;
  show) X 'sudo occ groupfolders:list; sudo occ tag:list' ;;
  *) echo "usage: $0 groups|folders|tags|apppw|show"; exit 2 ;;
esac
