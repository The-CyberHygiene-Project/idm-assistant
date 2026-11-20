"""doc_api.py (lab/docs-proof, Plan 3 Task 11c; RUNS ON A LAB WORKSTATION as the signed-in lab user, python3 -I - ARGS
with this script on stdin): raw HTTPS calls to NextCloud with the user's OWN `chp-site doc login` Bearer (the access
token in $XDG_RUNTIME_DIR/chp-doc/session.json; run a chp-site doc command first so it is fresh). For the refusal
tests that the client refuses locally before sending (a -DRAFT name, an unapproved hash, a forged body ...), the
WebDAV hand-off, and the API checks (status codes, 413, 429, request_id validation).
  doc_api.py METHOD PATH [BODY] [--h Name:Value]... [--auth bearer|basic:<file>|none] [--out FILE]
BODY: @file (bytes), json:<inline JSON>, gen:<N> (N bytes of 'A'), or nothing. Prints "HTTP <status>" and the first
600 bytes of the answer (never the token)."""
import base64
import http.client
import json
import os
import ssl
import sys

FILES = "files." + open("/etc/chp/site.conf").read().split("DOMAIN=", 1)[1].split()[0]
CA = "/etc/pki/ca-trust/source/anchors/chp-root.crt"


def main():
    a = sys.argv[1:]
    method, path = a[0], a[1]
    body, headers, auth, out = None, {"OCS-APIRequest": "true", "User-Agent": "CHP plan3 lab api"}, "bearer", None
    i = 2
    while i < len(a):
        x = a[i]
        if x == "--h":
            k, v = a[i + 1].split(":", 1); headers[k] = v.strip(); i += 2; continue
        if x == "--auth":
            auth = a[i + 1]; i += 2; continue
        if x == "--out":
            out = a[i + 1]; i += 2; continue
        if x.startswith("@"):
            body = open(x[1:], "rb").read()
        elif x.startswith("json:"):
            body = x[5:].encode(); headers.setdefault("Content-Type", "application/json")
        elif x.startswith("gen:"):
            body = b"A" * int(x[4:])
        i += 1
    if auth == "bearer":
        s = json.load(open(os.path.join(os.environ["XDG_RUNTIME_DIR"], "chp-doc", "session.json")))
        headers["Authorization"] = "Bearer " + s["access_token"]
    elif auth.startswith("basic:"):
        u, pw = open(auth[6:]).read().strip().split(":", 1)
        headers["Authorization"] = "Basic " + base64.b64encode(f"{u}:{pw}".encode()).decode()
    elif auth.startswith("bearerfile:"):
        headers["Authorization"] = "Bearer " + open(auth[11:]).read().strip()
    c = http.client.HTTPSConnection(FILES, 8443, context=ssl.create_default_context(cafile=CA), timeout=300)
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse(); data = r.read()
    print(f"HTTP {r.status}")
    if out:
        open(out, "wb").write(data)
    else:
        print(data[:600].decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
