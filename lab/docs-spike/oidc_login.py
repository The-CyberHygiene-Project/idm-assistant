"""oidc_login.py (RUNS ON THE MAC, python3 -I): a scripted BROWSER sign-in to NextCloud through Kanidm (OIDC), over SSH
tunnels to the lab (spike.sh tunnel). It follows the same redirects and posts the same HTML forms as a browser:
NextCloud /apps/user_oidc/login -> Kanidm /ui/oauth2 -> /ui/login (username, password, TOTP) -> consent -> NextCloud.
stdin (one JSON line): {"user": ..., "password": ..., "totp_secret": ..., "totp_algorithm": "sha256"} - never logged.
argv: ROOT_CA_PEM FILES_PORT IDM_PORT [--then PATH ...]; prints each step (paths only) and, at the end, the NextCloud
user id and groups from the OCS API (proving the session) or FAIL. Hosts files.<d>/idm.<d> are mapped to the tunnels."""
import base64
import hashlib
import hmac
import html.parser
import http.client
import json
import ssl
import struct
import sys
import time
import urllib.parse

D = "docs.lab.test"
FILES, IDM = f"files.{D}", f"idm.{D}"


OFFSET = [0.0]   # server clock - Mac clock (from the HTTP Date header; the lab clocks differ by seconds)


def now():
    return time.time() + OFFSET[0]


def totp(secret, alg="sha256", step=30, digits=6):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", int(now()) // step)
    h = hmac.new(key, msg, getattr(hashlib, alg)).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.forms = []; self.cur = None; self.title = ""; self._t = False
    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "form":
            self.cur = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "fields": {}, "buttons": []}
            self.forms.append(self.cur)
        elif tag in ("input", "button", "select", "textarea") and self.cur is not None and a.get("name"):
            if tag == "button" or a.get("type") == "submit":
                self.cur["buttons"].append((a["name"], a.get("value", "")))
            elif a.get("type") not in ("checkbox", "radio") or "checked" in a:
                self.cur["fields"][a["name"]] = a.get("value", "")
        elif tag == "title":
            self._t = True
    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None
        if tag == "title":
            self._t = False
    def handle_data(self, d):
        if self._t:
            self.title += d.strip()


class Browser:
    def __init__(self, ca, ports):
        self.ctx = ssl.create_default_context(cafile=ca); self.ports = ports; self.jar = {}
    def req(self, method, url, body=None, headers=None):
        u = urllib.parse.urlsplit(url); host = u.hostname
        c = http.client.HTTPSConnection("127.0.0.1", self.ports[host], context=self.ctx, timeout=30)
        c.sock = None; c.connect = lambda: setattr(c, "sock", self.ctx.wrap_socket(
            __import__("socket").create_connection(("127.0.0.1", self.ports[host]), 30), server_hostname=host))
        h = {"Host": u.netloc, "User-Agent": "Mozilla/5.0 (CHP spike scripted browser)", "Accept": "text/html,*/*"}
        if self.jar.get(host):
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar[host].items())
        h.update(headers or {})
        c.request(method, (u.path or "/") + ("?" + u.query if u.query else ""), body=body, headers=h)
        r = c.getresponse(); data = r.read()
        if r.getheader("date") and host == IDM:
            import email.utils
            OFFSET[0] = email.utils.parsedate_to_datetime(r.getheader("date")).timestamp() - time.time() + 0.5
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                n, _, val = v.split(";", 1)[0].partition("=")
                self.jar.setdefault(host, {})[n.strip()] = val.strip()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data
    def go(self, method, url, body=None, headers=None, log=print, hops=15):
        for _ in range(hops):
            if urllib.parse.urlsplit(url).path == "/claimprobe":
                return 0, url, b""
            st, h, data = self.req(method, url, body, headers)
            log(f"  {method} {urllib.parse.urlsplit(url).netloc}{urllib.parse.urlsplit(url).path} -> {st}")
            if st in (301, 302, 303, 307, 308) and "location" in h:
                url = urllib.parse.urljoin(url, h["location"])
                if st in (301, 302, 303):
                    method, body, headers = "GET", None, None
                continue
            return st, url, data
        raise RuntimeError("too many redirects")


def main():
    ca, fport, iport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    probe = "--probe" in sys.argv   # claims probe: client "claimprobe" (same scope + claim maps); stdin line 2 = its secret
    cred = json.loads(sys.stdin.readline())
    b = Browser(ca, {FILES: fport, IDM: iport})
    if probe:
        import os, secrets
        psec = sys.stdin.readline().strip(); ver = secrets.token_urlsafe(48)
        chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
        redir = f"https://{FILES}:8443/claimprobe"
        q = urllib.parse.urlencode({"response_type": "code", "client_id": "claimprobe", "redirect_uri": redir,
                                    "scope": "openid profile email groups", "state": secrets.token_urlsafe(8),
                                    "nonce": secrets.token_urlsafe(8), "code_challenge": chal, "code_challenge_method": "S256"})
        url = f"https://{IDM}/ui/oauth2?{q}"; st, url, data = b.go("GET", url)
    else:
        st, url, data = b.go("GET", f"https://{FILES}:8443/index.php/apps/user_oidc/login/1")
    for step in range(8):
        p = Forms(); p.feed(data.decode("utf-8", "replace"))
        host = urllib.parse.urlsplit(url).hostname
        if host == FILES:
            break
        if not p.forms:
            import re
            txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"(?s)<(script|style).*?</\1>", "", data.decode("utf-8", "replace"))))
            print(f"FAIL: no form at {urllib.parse.urlsplit(url).path} (title {p.title!r}): {txt.strip()[:400]}"); return 1
        f = p.forms[0]; fields = dict(f["fields"])
        names = set(fields)
        if "username" in names:
            fields["username"] = cred["user"]
        if "password" in names:
            fields["password"] = cred["password"]
        if "totp" in names:
            # a fresh TOTP window, so a code is never reused (Kanidm refuses replays)
            time.sleep(31 - now() % 30) if step > 0 or "password" not in names else None
            fields["totp"] = totp(cred["totp_secret"], cred.get("totp_algorithm", "sha256"))
        if f["buttons"] and f["buttons"][0][0] not in fields:
            fields[f["buttons"][0][0]] = f["buttons"][0][1]
        print(f"  form {f['action']} fields={sorted(k for k in fields)}")
        body = urllib.parse.urlencode(fields)
        st, url, data = b.go("POST", urllib.parse.urljoin(url, f["action"]), body,
                             {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"https://{host}"})
    if urllib.parse.urlsplit(url).hostname != FILES:
        print("FAIL: never got back to NextCloud"); return 1
    if probe:
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["code"][0]
        auth = base64.b64encode(f"claimprobe:{psec}".encode()).decode()
        st, _, data = b.go("POST", f"https://{IDM}/oauth2/token", urllib.parse.urlencode(
            {"grant_type": "authorization_code", "code": code, "redirect_uri": redir, "code_verifier": ver}),
            {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + auth, "Accept": "application/json"})
        tok = json.loads(data); idt = tok["id_token"].split(".")
        hdr = json.loads(base64.urlsafe_b64decode(idt[0] + "=" * (-len(idt[0]) % 4)))
        pay = json.loads(base64.urlsafe_b64decode(idt[1] + "=" * (-len(idt[1]) % 4)))
        for k in ("nonce", "at_hash", "s_hash", "c_hash"):
            pay.pop(k, None) if k == "nonce" else None
        print("ID TOKEN header:", json.dumps({k: hdr[k] for k in ("alg", "typ") if k in hdr}))
        print("ID TOKEN claims:", json.dumps(pay, sort_keys=True))
        return 0
    st, _, data = b.go("GET", f"https://{FILES}:8443/ocs/v2.php/cloud/user?format=json",
                       headers={"OCS-APIRequest": "true", "Accept": "application/json"})
    if st != 200:
        print(f"FAIL: OCS /cloud/user -> {st}"); return 1
    d = json.loads(data)["ocs"]["data"]
    if "--assets" in sys.argv:   # load the Files page and every script/style it names, as a browser would
        import re
        st, _, page = b.go("GET", f"https://{FILES}:8443/index.php/apps/files/", log=lambda m: None)
        refs = sorted(set(re.findall(r'(?:src|href)="(/[^"]+\.(?:m?js|css)[^"]*)"', page.decode("utf-8", "replace"))))
        codes = {}
        for r in refs:
            s2, _, _ = b.go("GET", f"https://{FILES}:8443" + r.replace("&amp;", "&"), log=lambda m: None)
            codes[s2] = codes.get(s2, 0) + 1
        print(f"ASSETS: files page {st}; {len(refs)} scripts/styles referenced; status counts {codes}")
    print(f"SIGNED IN: id={d['id']} display={d.get('displayname')!r} groups={sorted(d.get('groups', []))} backend={d.get('backend')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
