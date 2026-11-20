"""doc_req.py (lab/docs-proof, Plan 3 11c; on a workstation as the signed-in lab user: python3 -I - ARGS < doc_req.py):
a RAW ledger request with the user's own chp-doc Bearer, bypassing every local check of chp-site doc (for the
SERVER-side refusals: a -DRAFT name, missing marks, an unapproved hash, a forged sha). Posts to chp_ledger's
/request and polls /result/<id> until done or refused (60 s).
  doc_req.py KIND FOLDER_ID NAME [--file F] [--pdf P] [--sha HEX] [--rid HEX] [--set k=v]...
Run a chp-site doc command first so the access token is fresh. Never prints the token."""
import base64
import hashlib
import http.client
import json
import os
import secrets
import ssl
import sys
import time

DOMAIN = open("/etc/chp/site.conf").read().split("DOMAIN=", 1)[1].split()[0]
FILES, CA = "files." + DOMAIN, "/etc/pki/ca-trust/source/anchors/chp-root.crt"
L = "/ocs/v2.php/apps/chp_ledger/api/v1"


def call(method, path, body=None):
    tok = json.load(open(os.path.join(os.environ["XDG_RUNTIME_DIR"], "chp-doc", "session.json")))["access_token"]
    c = http.client.HTTPSConnection(FILES, 8443, context=ssl.create_default_context(cafile=CA), timeout=120)
    c.request(method, path, body=body, headers={"Authorization": "Bearer " + tok, "OCS-APIRequest": "true",
                                                "Accept": "application/json", "Content-Type": "application/json"})
    r = c.getresponse(); d = r.read()
    try:
        return r.status, json.loads(d)["ocs"]["data"]
    except Exception:                                   # noqa: BLE001
        return r.status, d[:300].decode("utf-8", "replace")


def main():
    a = sys.argv[1:]
    kind, folder, name = a[0], int(a[1]), a[2]
    f = {"kind": kind, "file_id": folder, "path": name}
    i = 3
    while i < len(a):
        if a[i] == "--file":
            data = open(a[i + 1], "rb").read(); f["sha256"] = hashlib.sha256(data).hexdigest()
            if kind == "publish":
                f["content"] = base64.b64encode(data).decode()
        elif a[i] == "--pdf":
            f["pdf_content"] = base64.b64encode(open(a[i + 1], "rb").read()).decode()
        elif a[i] == "--sha":
            f["sha256"] = a[i + 1]
        elif a[i] == "--rid":
            f["request_id"] = a[i + 1]
        elif a[i] == "--set":
            k, v = a[i + 1].split("=", 1); f[k] = v
        i += 2
    f.setdefault("request_id", secrets.token_hex(16))
    st, d = call("POST", f"{L}/request?format=json", json.dumps(f))
    print(f"POST HTTP {st}: {d if not isinstance(d, dict) else {k: d[k] for k in d if k != 'entry'}}")
    if st != 200:
        return
    for _ in range(30):
        time.sleep(2)
        st, d = call("GET", f"{L}/result/{f['request_id']}?format=json")
        if isinstance(d, dict) and d.get("state") in ("done", "refused"):
            print(f"RESULT {d.get('state')}: {d.get('message')}")
            return
    print(f"RESULT none after 60 s: HTTP {st} {d}")


if __name__ == "__main__":
    main()
