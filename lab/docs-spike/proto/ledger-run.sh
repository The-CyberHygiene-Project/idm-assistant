#!/usr/bin/env bash
# proto/ledger-run.sh STAGE (RUNS ON THE MAC; Task 2 SPIKE): the ledger proofs. Needs logs/55 (four route-1 sessions).
#   l1      route L1: author/approver/publisher rules, forged names, people who cannot see the document, app password
#   l2      route L2: the drop folder, a forged name, overwrite/delete, a request put on the disk behind NextCloud's back
#   anchor  show + verify; export the head to the stick stand-in; tamper with a COPY (cut / rewrite) and catch it
#   apache  what the web server's user can do to the ledger
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; F="$here/../ssh_config"
X() { ssh -F "$F" -o BatchMode=yes docs "$@"; }
C() { local u=$1; shift; ENVS="CHP_DOC_AS=$u" bash "$here/on-dcli.sh" doc_auth.py+doc_ledger_cli.py "$@"; }
L() { echo "+ (root) docs_ledger.py $*"; X "sudo python3 -I /usr/local/libexec/chp-spike/docs_ledger.py $*"; }
DOC=CUI/Compliance/CUI_spike-ssp_v1.0.docx
case ${1:-} in
  l1)
    echo "## 1. lab01 checks the document out (records lab01 as its author)"; C lab01 l1 checkout $DOC
    echo "## 2. lab01 approves their own document: refused"; C lab01 l1 approve $DOC --notes "self"
    echo "## 3. lab01 approves again, claiming to be lab04 (user=lab04 in the request): the app ignores the claim"
    C lab01 l1 approve $DOC --claim lab04 --notes "forged"
    echo "## 4. lab01 tries the ISSO override: refused (not the ISSO)"; C lab01 l1 override $DOC --reason "no one else"
    echo "## 5. lab01 publishes before any approval: refused"; C lab01 l1 publish $DOC
    echo "## 6. lab02 (not cui-users) and lab03 (doc-reviewers, not cui-users) cannot see the CUI document: refused"
    C lab02 l1 approve $DOC; C lab03 l1 approve $DOC
    echo "## 7. lab04 (approver, cui-users) approves: appended, with the Kanidm session behind the Bearer"
    C lab04 l1 approve $DOC --notes "reviewed v1.0"
    echo "## 8. lab04 (the ISSO here) override: refused, other approvers exist"; C lab04 l1 override $DOC --reason "test"
    echo "## 9. lab01 publishes a DIFFERENT file than the approved one: refused"; C lab01 l1 publish $DOC --sha $(printf 'f%.0s' {1..64})
    echo "## 10. lab01 publishes the approved file: appended"; C lab01 l1 publish $DOC
    echo "## 11. no credentials at all"
    X "curl -s -o /dev/null -w 'unauthenticated POST -> %{http_code}\n' -H 'OCS-APIRequest: true' -d action=approve -d fileid=119 -d sha256=$(printf '0%.0s' {1..64}) https://files.docs.lab.test:8443/ocs/v2.php/apps/chp_ledger/api/v1/request"
    echo "## 12. lab04 by app password instead of Bearer (the entry records which; policy could demand Bearer)"
    python3 -I - ~/idm-lab-secrets/docs-root-ca.pem <<'PY'
import base64, http.client, json, os, socket, ssl, sys, urllib.parse
ctx = ssl.create_default_context(cafile=sys.argv[1]); H = "files.docs.lab.test"
c = http.client.HTTPSConnection("127.0.0.1", 18443, context=ctx); c.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 18443)), server_hostname=H)
pw = open(os.path.expanduser("~/idm-lab-secrets/docs-lab04-app.txt")).read().strip()
c.request("POST", "/ocs/v2.php/apps/chp_ledger/api/v1/request?format=json", urllib.parse.urlencode({"action": "checkout", "fileid": "119", "sha256": "0" * 64}),
          {"Host": H + ":8443", "OCS-APIRequest": "true", "Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.b64encode(f"lab04:{pw}".encode()).decode()})
r = c.getresponse(); print("lab04 app-password checkout POST ->", r.status, json.loads(r.read())["ocs"]["data"])
PY
    sleep 3; L show ;;
  l2)
    echo "## 1. lab04 drops an approval request (as the approver)"; C lab01 l1 checkout $DOC >/dev/null; n1=$(C lab04 l2 approve $DOC --notes "drop route" | tee /dev/stderr | grep -oE '[0-9a-f]{32}\.json')
    echo "## 2. lab01 drops a request for its own document claiming user lab04"; C lab01 l2 approve $DOC --claim lab04
    echo "## 3. lab01 tries to change or delete lab04's waiting request"; C lab01 l2-try-overwrite "$n1"; C lab01 l2-try-delete "$n1"
    echo "## 4. what a user sees in the drop folder"; C lab01 l2-list
    echo "## 5. a request written straight onto the server's disk (no NextCloud upload, so no audit record)"
    X 'printf "%s" "{\"action\":\"approve\",\"fileid\":119,\"sha256\":\"'$(printf 'a%.0s' {1..64})'\",\"user\":\"lab04\"}" | sudo tee /data/nextcloud/data/__groupfolders/7/files/0000disk0000.json >/dev/null && sudo chown apache:apache /data/nextcloud/data/__groupfolders/7/files/0000disk0000.json && sudo occ groupfolders:scan 7 >/dev/null; echo "placed 0000disk0000.json + rescan"'
    echo "## 6. the root job reads the drop folder"; L drop 7
    L show ;;
  anchor)
    L verify; L export /root/spike/stick; X 'sudo cat /root/spike/stick/docs-ledger/heads.txt'
    echo "## tamper with a COPY of the ledger (CHP_DOCS_BASE=/root/spike/tamper), never the real one"
    X 'sudo rm -rf /root/spike/tamper && sudo mkdir -p /root/spike/tamper && sudo cp -a /var/lib/chp-docs/ledger /root/spike/tamper/'
    echo "## a. the last entry cut off (head witness still says N)"
    X 'sudo sed -i "\$d" /root/spike/tamper/ledger/ledger.jsonl; sudo CHP_DOCS_BASE=/root/spike/tamper python3 -I /usr/local/libexec/chp-spike/docs_ledger.py verify'
    echo "## b. ... and the head witness rewritten to match (someone with root on the server): only the stick notices"
    printf '%s\n' 'cd /root/spike/tamper/ledger && n=$(wc -l < ledger.jsonl) && h=$(tail -1 ledger.jsonl | tr -d "\n" | sha256sum | cut -d" " -f1) && echo "$n $h" > ledger.head && echo "witness rewritten: $n entries"' | X 'sudo bash'; X 'sudo CHP_DOCS_BASE=/root/spike/tamper python3 -I /usr/local/libexec/chp-spike/docs_ledger.py verify; sudo CHP_DOCS_BASE=/root/spike/tamper python3 -I /usr/local/libexec/chp-spike/docs_ledger.py verify-heads /root/spike/stick'
    echo "## c. an entry's approver changed in place (lab04 -> lab03): the chain breaks"
    X 'sudo rm -rf /root/spike/tamper/ledger && sudo cp -a /var/lib/chp-docs/ledger /root/spike/tamper/ && sudo sed -i "0,/\"user\":\"lab04\"/s//\"user\":\"lab03\"/" /root/spike/tamper/ledger/ledger.jsonl; sudo CHP_DOCS_BASE=/root/spike/tamper python3 -I /usr/local/libexec/chp-spike/docs_ledger.py verify'
    echo "## the real ledger is untouched"; L verify; L verify-heads /root/spike/stick ;;
  apache)
    X 'sudo -u apache sh -c "cat /var/lib/chp-docs/ledger/ledger.jsonl" 2>&1 | head -1; sudo -u apache sh -c "echo forged >> /var/lib/chp-docs/ledger/ledger.jsonl" 2>&1; sudo -u apache sh -c "ls /var/lib/chp-docs/spool" 2>&1; sudo -u apache sh -c "echo x > /var/lib/chp-docs/out/forged.json" 2>&1; ls -laZ /var/lib/chp-docs/ledger 2>&1 | tail -2; sudo ls -laZ /var/lib/chp-docs/ledger | tail -2' ;;
  *) echo "usage: $0 l1|l2|anchor|apache"; exit 2 ;;
esac
