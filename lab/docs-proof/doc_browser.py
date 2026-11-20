"""doc_browser.py (lab/docs-proof, Plan 3 Task 11c; RUNS ON A LAB WORKSTATION as the lab user, python3 -I): the
scripted BROWSER for `chp-site doc login`. chp-site opens the Kanidm URL with Python's webbrowser, which runs $BROWSER
(this script, through doc-browser.sh, which detaches it so webbrowser.open returns at once). It follows the same
redirects and posts the same HTML forms as a browser (Kanidm /ui/oauth2 -> /ui/login: username, password, TOTP ->
consent) and finally GETs the http://127.0.0.1:<port>/?code=...&state=... redirect, which chp-site's one-shot loopback
listener is waiting for. Same form logic as oidc_login.py (Plan 2).
argv: URL. The credentials come from the 0600 JSON file named by $LAB_CRED ({"user", "password", "totp_secret",
"totp_algorithm"}); the file is deleted as soon as it is read. Nothing secret is printed; the log ($LAB_BROWSER_LOG)
holds paths and status codes only."""
import base64
import email.utils
import hashlib
import hmac
import html.parser
import http.client
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse

CA = "/etc/pki/ca-trust/source/anchors/chp-root.crt"
OFFSET = [0.0]
LOG = open(os.environ.get("LAB_BROWSER_LOG", os.devnull), "a")


def log(m):
    LOG.write(m + "\n"); LOG.flush()


def now():
    return time.time() + OFFSET[0]


def totp(secret, alg="sha256", step=30, digits=6):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", int(now()) // step), getattr(hashlib, alg)).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.forms = []; self.cur = None

    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "form":
            self.cur = {"action": a.get("action", ""), "fields": {}, "buttons": []}; self.forms.append(self.cur)
        elif tag in ("input", "button", "select", "textarea") and self.cur is not None and a.get("name"):
            if tag == "button" or a.get("type") == "submit":
                self.cur["buttons"].append((a["name"], a.get("value", "")))
            elif a.get("type") not in ("checkbox", "radio") or "checked" in a:
                self.cur["fields"][a["name"]] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


class Browser:
    def __init__(self):
        self.ctx = ssl.create_default_context(cafile=CA if os.path.exists(CA) else None); self.jar = {}

    def req(self, method, url, body=None, headers=None):
        u = urllib.parse.urlsplit(url)
        if u.scheme == "https":
            c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=self.ctx, timeout=30)
        else:
            c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=30)
        h = {"Host": u.netloc, "User-Agent": "Mozilla/5.0 (CHP plan3 scripted browser)", "Accept": "text/html,*/*"}
        if self.jar.get(u.hostname):
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar[u.hostname].items())
        h.update(headers or {})
        c.request(method, (u.path or "/") + ("?" + u.query if u.query else ""), body=body, headers=h)
        r = c.getresponse(); data = r.read()
        if r.getheader("date") and u.scheme == "https":
            OFFSET[0] = email.utils.parsedate_to_datetime(r.getheader("date")).timestamp() - time.time() + 0.5
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                n, _, val = v.split(";", 1)[0].partition("=")
                self.jar.setdefault(u.hostname, {})[n.strip()] = val.strip()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def go(self, method, url, body=None, headers=None):
        for _ in range(15):
            st, h, data = self.req(method, url, body, headers)
            u = urllib.parse.urlsplit(url)
            log(f"  {method} {u.scheme}://{u.netloc}{u.path} -> {st}")
            if st in (301, 302, 303, 307, 308) and "location" in h:
                url = urllib.parse.urljoin(url, h["location"])
                if st in (301, 302, 303):
                    method, body, headers = "GET", None, None
                continue
            return st, url, data
        raise RuntimeError("too many redirects")


def main():
    url = sys.argv[1]
    p = os.environ["LAB_CRED"]
    with open(p) as f:
        cred = json.load(f)
    os.unlink(p)
    if os.environ.get("LAB_BROWSER_MODE") == "ignore":    # B: the user never signs in (timeout test)
        log("ignoring the sign-in URL"); return 0
    b = Browser()
    st, url, data = b.go("GET", url)
    for step in range(8):
        u = urllib.parse.urlsplit(url)
        if u.hostname == "127.0.0.1":
            log(f"DONE loopback answered {st}: {data.decode('utf-8', 'replace').strip()[:80]}"); return 0
        fp = Forms(); fp.feed(data.decode("utf-8", "replace"))
        if not fp.forms:
            log(f"FAIL: no form at {u.path} (status {st})"); return 1
        f = fp.forms[0]; fields = dict(f["fields"])
        if "username" in fields:
            fields["username"] = cred["user"]
        if "password" in fields:
            fields["password"] = cred["password"]
        if "totp" in fields:
            time.sleep(31 - now() % 30) if step > 0 or "password" not in fields else None
            fields["totp"] = totp(cred["totp_secret"], cred.get("totp_algorithm", "sha256"))
        if f["buttons"] and f["buttons"][0][0] not in fields:
            fields[f["buttons"][0][0]] = f["buttons"][0][1]
        log(f"  form {f['action']} fields={sorted(fields)}")
        st, url, data = b.go("POST", urllib.parse.urljoin(url, f["action"]), urllib.parse.urlencode(fields),
                             {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"https://{u.netloc}"})
    log("FAIL: never reached the loopback redirect"); return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:                                   # noqa: BLE001 - lab helper: say why, never a secret
        log(f"FAIL: {type(e).__name__}: {e}"); sys.exit(1)
