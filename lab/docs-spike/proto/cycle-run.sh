#!/usr/bin/env bash
# proto/cycle-run.sh (RUNS ON THE MAC; fix 4 SPIKE): the per-cycle author rule on a new non-CUI controlled document
# (Internal/Compliance: lab02 can write it; lab04 = approver + ISSO; lab01 = another user). Needs logs/68 sessions.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
C() { local u=$1; shift; ENVS="CHP_DOC_AS=$u" bash "$here/on-dcli.sh" doc_auth.py+doc_ledger_cli.py "$@"; }
D=Internal/Compliance/Internal_spike-cycle_v1.0.docx
echo "## 0. lab02 writes a new controlled document and records its creation"; C lab02 put $D "v1.0 draft"; C lab02 l1 create $D
echo "## A. the self-approval sequence (A = lab04, an approver, authors; C = lab02 checks out after; A approves A's own hash)"
C lab04 l1 checkout $D; C lab02 l1 checkout $D; C lab04 l1 approve $D --notes "approving my own edit"
echo "   (the first rule, 'author = the latest checkout', said author = lab02 here and would have let lab04 approve)"
echo "## B. a non-author cannot publish; an approval made BEFORE the cycle's last checkout does not count"
C lab01 l1 publish $D
echo "## C. a clean cycle: publish by lab02 (an author) after the approver ... but lab04 is an author of THIS cycle, so"
echo "##    the cycle must close first: nobody can approve it now (lab04 is the only CUI-free approver who can see it)"
C lab02 l1 publish $D
echo "## D. reviewers read with a plain fetch (GET), which records nothing; then a fresh document shows the clean path"
D2=Internal/Compliance/Internal_spike-cycle2_v1.0.docx
C lab02 put $D2 "v1.0 draft"; C lab02 l1 create $D2
C lab04 l1 approve $D2 --notes "reviewed (read by a plain fetch)"
echo "## E. lab02 checks out again AFTER the approval: the approval no longer counts"; C lab02 l1 checkout $D2; C lab02 l1 publish $D2
echo "## F. lab04 approves again after that checkout; lab02 publishes"; C lab04 l1 approve $D2 --notes "re-reviewed"; C lab02 l1 publish $D2
echo "## G. approve without a Bearer (lab04 by app password): refused"
python3 -I - ~/idm-lab-secrets/docs-root-ca.pem <<'PY'
import base64, http.client, json, os, socket, ssl, sys, time, urllib.parse
ctx = ssl.create_default_context(cafile=sys.argv[1]); H = "files.docs.lab.test"
au = "Basic " + base64.b64encode(f"lab04:{open(os.path.expanduser('~/idm-lab-secrets/docs-lab04-app.txt')).read().strip()}".encode()).decode()
def rq(m, p, b=None, h=None):
    c = http.client.HTTPSConnection("127.0.0.1", 18443, context=ctx); c.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 18443)), server_hostname=H)
    hh = {"Host": H + ":8443", "Authorization": au, "OCS-APIRequest": "true", "Accept": "application/json"}; hh.update(h or {}); c.request(m, p, b, hh); r = c.getresponse(); return r.status, r.read()
import re
st, d = rq("PROPFIND", "/remote.php/dav/files/lab04/Internal/Compliance/Internal_spike-cycle2_v1.0.docx", '<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>', {"Depth": "0"})
fid = re.search(rb"<oc:fileid>(\d+)", d).group(1).decode()
st, d = rq("POST", "/ocs/v2.php/apps/chp_ledger/api/v1/request?format=json", urllib.parse.urlencode({"action": "approve", "fileid": fid, "sha256": "0" * 64}), {"Content-Type": "application/x-www-form-urlencoded"})
i = json.loads(d)["ocs"]["data"]["id"]; time.sleep(1.5)
st, d = rq("GET", f"/ocs/v2.php/apps/chp_ledger/api/v1/result/{i}?format=json")
print("lab04 approve by app password ->", json.loads(d)["ocs"]["data"])
PY
