import json, os, ssl, urllib.parse, http.client
s = json.load(open(os.path.join(os.environ["XDG_RUNTIME_DIR"], "chp-doc", "session.json")))
d = open("/etc/chp/site.conf").read().split("DOMAIN=",1)[1].split()[0]
ctx = ssl.create_default_context(cafile="/etc/pki/ca-trust/source/anchors/chp-root.crt")
for kind in ("refresh_token", "access_token"):
    c = http.client.HTTPSConnection("idm." + d, 443, context=ctx)
    c.request("POST", "/oauth2/token/introspect", urllib.parse.urlencode({"token": s[kind], "token_type_hint": kind, "client_id": "chp-doc"}),
              {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    r = c.getresponse(); b = r.read()
    try: j = json.loads(b); j = {k: j[k] for k in j if k in ("active","exp","iat","client_id","token_type","error","scope")}
    except Exception: j = b[:200]
    print(kind, "introspect: HTTP", r.status, j)
print("session_expires_at stored:", s.get("session_expires_at"), "access expires_at:", s.get("expires_at"))
