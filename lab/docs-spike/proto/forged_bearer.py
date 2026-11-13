"""proto/forged_bearer.py (Task 2 fix 3 SPIKE; RUNS ON THE MAC, python3 -I, over the tunnel): a BROWSER-SESSION request to
chp_ledger that also carries a forged `Authorization: Bearer <header>.<claims>.<bad signature>`. What does NextCloud
authenticate, and what lands in the ledger entry? Signs in lab01 with oidc_login.py's scripted browser (cookie session),
then POSTs a checkout of file 119 with the forged header. argv: ROOT_CA FILES_PORT IDM_PORT ; stdin: lab01's JSON line."""
import base64
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import oidc_login as ol   # noqa: E402

CAP = {}


class B(ol.Browser):
    def __init__(self, *a):
        super().__init__(*a); CAP["b"] = self


ol.Browser = B
sys.argv = sys.argv[:4]
rc = ol.main()
b = CAP["b"]
enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
forged = enc({"alg": "ES256", "typ": "at+jwt"}) + "." + enc({"sub": "00000000-forged-sub", "auth_time": 1,
         "session_id": "forged-session", "client_id": "chp-doc", "preferred_username": "lab04"}) + ".bad-signature"
url = f"https://{ol.FILES}:8443/ocs/v2.php/apps/chp_ledger/api/v1/request?format=json"
body = urllib.parse.urlencode({"action": "checkout", "fileid": "119", "sha256": "0" * 64, "notes": "forged-bearer test"})
for label, extra in (("cookie session only", {}), ("cookie session + forged Bearer", {"Authorization": "Bearer " + forged})):
    h = {"OCS-APIRequest": "true", "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    h.update(extra)
    st, _, data = b.req("POST", url, body, h)
    try:
        d = json.loads(data)["ocs"]["data"]
    except Exception:
        d = data[:160]
    print(f"{label}: POST -> {st} {d}")
