"""proto/doc_auth.py (Task 2 SPIKE, throwaway; stdlib only, Python 3.9): how `chp-site doc` could sign in to NextCloud as
the user. RUNS ON THE WORKSTATION as the user (spike: `proto/on-dcli.sh doc_auth.py ...`). Two routes:

  oidc-login   Kanidm public client "chp-doc": authorization code + PKCE, redirect to a one-shot loopback listener
               (http://localhost:8400/callback, 127.0.0.1 only, closed after one request). Tokens (access ~15 min,
               refresh <= 8 h, set on the Kanidm client) go to $XDG_RUNTIME_DIR/chp-doc/session.json (tmpfs, 0600,
               gone at logout). NextCloud accepts the access token as a Bearer (user_oidc provider "kanidm-cli").
  flow2-login  NextCloud Login Flow v2: the browser signs in (through Kanidm) and grants; the CLI polls and receives an
               app password. --store runtime (tmpfs) or --store home (~/.config/chp-doc/app-password, 0600, on LUKS).
  whoami       OCS /cloud/user with whatever is stored (refreshing an expired access token)
  stored       what is stored, where, its mode, file system and lifetime (never the secret)
  logout       revoke at the server (Kanidm revoke / NextCloud DELETE apppassword) and delete the local copy

The browser step: a real user's Firefox opens the printed URL. SPIKE ONLY: --scripted-browser reads ONE JSON line
{"user","password","totp_secret"} from stdin and plays the browser (the same forms as lab/docs-spike/oidc_login.py)."""
import base64
import hashlib
import hmac
import html.parser
import http.client
import http.server
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse

D = "docs.lab.test"
FILES, IDM = f"https://files.{D}:8443", f"https://idm.{D}"
CLIENT, REDIRECT_PORT = "chp-doc", int(os.environ.get("CHP_DOC_PORT", "8400"))   # spike: try another port
REDIRECT = f"http://localhost:{REDIRECT_PORT}/callback"
CTX = ssl.create_default_context()          # the system trust store holds the site root (chp-root.crt)
RUN = os.path.join(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}", "chp-doc")
if os.environ.get("CHP_DOC_AS"):          # spike: several lab people signed in from one OS account
    RUN += "-" + os.environ["CHP_DOC_AS"]
HOME_STORE = os.path.expanduser("~/.config/chp-doc")
UA = "CHP doc commands (spike)"


# ---------------------------------------------------------------- HTTP
def req(method, url, body=None, headers=None, cookies=None):
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=CTX, timeout=30)
    else:
        c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=30)
    h = {"User-Agent": UA, "Accept": "*/*"}
    if cookies is not None and cookies.get(u.hostname):
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies[u.hostname].items())
    h.update(headers or {})
    c.request(method, (u.path or "/") + ("?" + u.query if u.query else ""), body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    if cookies is not None:
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                n, _, val = v.split(";", 1)[0].partition("=")
                cookies.setdefault(u.hostname, {})[n.strip()] = val.strip()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, data


def form_post(url, fields, headers=None, cookies=None):
    h = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    h.update(headers or {})
    return req("POST", url, urllib.parse.urlencode(fields), h, cookies)


def ocs_user(auth_header):
    st, _, data = req("GET", f"{FILES}/ocs/v2.php/cloud/user?format=json",
                      headers={"Authorization": auth_header, "OCS-APIRequest": "true", "Accept": "application/json"})
    if st != 200:
        return st, None
    d = json.loads(data)["ocs"]["data"]
    return st, {"id": d["id"], "groups": sorted(d.get("groups", [])), "backend": d.get("backend")}


# ---------------------------------------------------------------- storage (never prints a secret)
def _write(path, obj):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _paths():
    return [os.path.join(RUN, "session.json"), os.path.join(HOME_STORE, "app-password")]


def load(which=None):
    for p in _paths()[:1] if which == "runtime" else _paths()[1:] if which == "home" else _paths():
        if os.path.exists(p):
            return p, json.load(open(p))
    return None, None


def describe(p, s):
    st = os.stat(p)
    fs = ""
    for ln in open("/proc/self/mounts"):
        dev, mnt, typ = ln.split()[:3]
        if p.startswith(mnt.rstrip("/") + "/") and len(mnt) > len(fs.split(" ")[0] if fs else ""):
            fs = f"{mnt} {typ} ({dev})"
    out = {"path": p, "mode": oct(st.st_mode & 0o777), "owner_uid": st.st_uid, "filesystem": fs, "kind": s["kind"],
           "user": s.get("user"), "stored_at": time.strftime("%FT%TZ", time.gmtime(s["stored_at"]))}
    if s["kind"] == "oidc":
        out["access_token_expires"] = time.strftime("%FT%TZ", time.gmtime(s["expires_at"]))
        out["access_token_shape"] = f"{s['access_token'].count('.') + 1} dot-separated parts, {len(s['access_token'])} chars"
        out["refresh_token"] = "present" if s.get("refresh_token") else "absent"
        out["refresh_expires_by"] = (time.strftime("%FT%TZ", time.gmtime(s["stored_at"] + 28800)) +
                                     " (COMPUTED here from the Kanidm client setting 28800 s; not read from Kanidm, untested)")
    else:
        out["app_password"] = f"{len(s['app_password'])} chars; no expiry at the server (valid until revoked)"
    return out


# ---------------------------------------------------------------- SPIKE ONLY: the scripted browser
OFFSET = [0.0]


def totp(secret, alg="sha256"):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", int(time.time() + OFFSET[0]) // 30), getattr(hashlib, alg)).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** 6).zfill(6)


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.forms = []; self.cur = None
    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "form":
            self.cur = {"action": a.get("action", ""), "fields": {}, "buttons": []}; self.forms.append(self.cur)
        elif tag in ("input", "button") and self.cur is not None and a.get("name"):
            if tag == "button" or a.get("type") == "submit":
                self.cur["buttons"].append((a["name"], a.get("value", "")))
            elif a.get("type") not in ("checkbox", "radio") or "checked" in a:
                self.cur["fields"][a["name"]] = a.get("value", "")
    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


def browse(url, cred, jar, until, log):
    """Follow redirects and fill Kanidm's login + consent forms until a URL satisfying until(url) is reached."""
    method, body, headers = "GET", None, None
    for _ in range(40):
        if until(url):
            return url
        u = urllib.parse.urlsplit(url)
        st, h, data = req(method, url, body, headers, jar)
        if u.hostname == f"idm.{D}" and h.get("date"):
            import email.utils
            OFFSET[0] = email.utils.parsedate_to_datetime(h["date"]).timestamp() - time.time() + 0.5
        log(f"  browser {method} {u.scheme}://{u.netloc}{u.path} -> {st}")
        if st in (301, 302, 303, 307, 308):
            url = urllib.parse.urljoin(url, h["location"]); method, body, headers = "GET", None, None
            continue
        p = Forms(); p.feed(data.decode("utf-8", "replace"))
        if not p.forms:
            txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"(?s)<(script|style).*?</\1>", "", data.decode("utf-8", "replace"))))
            raise RuntimeError(f"browser: no form at {u.path}: {txt.strip()[:300]}")
        f = p.forms[0]; fields = dict(f["fields"])
        if "username" in fields:
            fields["username"] = cred["user"]
        if "password" in fields:
            fields["password"] = cred["password"]
        if "totp" in fields:
            time.sleep(31 - (time.time() + OFFSET[0]) % 30)       # a fresh window: Kanidm refuses a reused code
            fields["totp"] = totp(cred["totp_secret"], cred.get("totp_algorithm", "sha256"))
        if f["buttons"] and f["buttons"][0][0] not in fields:
            fields[f["buttons"][0][0]] = f["buttons"][0][1]
        log(f"  browser form {f['action'] or u.path} fields={sorted(fields)}")
        url = urllib.parse.urljoin(url, f["action"]); method = "POST"; body = urllib.parse.urlencode(fields)
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"{u.scheme}://{u.netloc}"}
    raise RuntimeError("browser: too many steps")


# ---------------------------------------------------------------- route 1: OIDC code + PKCE through Kanidm
def oidc_login(scripted, log):
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            got.update({k: v[0] for k, v in q.items()})
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(b"Signed in. You can close this tab and return to the terminal.\n")
        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", REDIRECT_PORT), H)   # loopback only; one request, then closed
    srv.timeout = 300
    t = threading.Thread(target=srv.handle_request, daemon=True); t.start()
    log(f"  listener: 127.0.0.1:{REDIRECT_PORT} (loopback only, one request, then closed)")
    q = urllib.parse.urlencode({"response_type": "code", "client_id": CLIENT, "redirect_uri": REDIRECT,
                                "scope": "openid profile groups", "state": state, "nonce": secrets.token_urlsafe(8),
                                "code_challenge": challenge, "code_challenge_method": "S256"})
    url = f"{IDM}/ui/oauth2?{q}"
    if scripted:
        cred = json.loads(sys.stdin.readline())
        last = browse(url, cred, {}, lambda x: x.startswith(REDIRECT), log)
        req("GET", last)                                   # the browser arriving at the loopback redirect
    else:
        print(f"Open this address in the browser and sign in:\n  {url}")
    t.join(300); srv.server_close()
    log(f"  listener closed; callback had: {sorted(got)}")
    if got.get("state") != state or "code" not in got:
        raise SystemExit("FAIL: no code (or a wrong state) on the callback")
    st, _, data = form_post(f"{IDM}/oauth2/token", {"grant_type": "authorization_code", "code": got["code"],
                                                     "redirect_uri": REDIRECT, "client_id": CLIENT, "code_verifier": verifier})
    if st != 200:
        raise SystemExit(f"FAIL: token endpoint {st}: {data[:200]!r}")
    tok = json.loads(data)
    log(f"  token response keys: {sorted(tok)}; expires_in={tok.get('expires_in')}; token_type={tok.get('token_type')}")
    idt = tok["id_token"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(idt[1] + "=" * (-len(idt[1]) % 4)))
    log(f"  id token: preferred_username={claims.get('preferred_username')} chp_groups={claims.get('chp_groups')} "
        f"aud={claims.get('aud')} auth_time={claims.get('auth_time')} exp-iat={claims['exp'] - claims['iat']}s")
    s = {"kind": "oidc", "user": claims.get("preferred_username"), "access_token": tok["access_token"],
         "refresh_token": tok.get("refresh_token"), "expires_at": time.time() + int(tok.get("expires_in", 300)),
         "stored_at": time.time(), "auth_time": claims.get("auth_time")}
    _write(os.path.join(RUN, "session.json"), s)
    return s


def oidc_refresh(p, s, log):
    st, _, data = form_post(f"{IDM}/oauth2/token", {"grant_type": "refresh_token", "refresh_token": s["refresh_token"],
                                                     "client_id": CLIENT})
    if st != 200:
        log(f"  refresh refused: {st} {data[:160]!r}")
        return None
    tok = json.loads(data)
    old_rt = s["refresh_token"]           # fix 6: compare old vs new BEFORE overwriting (the first version compared after)
    s.update(access_token=tok["access_token"], refresh_token=tok.get("refresh_token", old_rt),
             expires_at=time.time() + int(tok.get("expires_in", 300)))
    _write(p, s)
    log(f"  refreshed: new access token, expires_in={tok.get('expires_in')}; refresh token in the response: "
        f"{'refresh_token' in tok}; rotated (new != old): {tok.get('refresh_token') not in (None, old_rt)}")
    return s


# ---------------------------------------------------------------- route 2: NextCloud Login Flow v2
def flow2_login(scripted, store, log):
    st, _, data = req("POST", f"{FILES}/index.php/login/v2", headers={"Accept": "application/json"})
    if st != 200:
        raise SystemExit(f"FAIL: login/v2 {st}")
    d = json.loads(data)
    log(f"  login/v2 -> 200: a login URL + a poll token (poll endpoint {urllib.parse.urlsplit(d['poll']['endpoint']).path})")
    if scripted:
        cred = json.loads(sys.stdin.readline())
        jar = {}
        # the flow pages are JavaScript; the spike reads their initial state and does what the buttons do
        st, h, _ = req("GET", d["login"], cookies=jar)                                  # landing -> picker
        st, _, page = req("GET", urllib.parse.urljoin(d["login"], h["location"]), cookies=jar)
        auth = initial_state(page, "loginFlowAuth")
        log(f"  picker page: state {initial_state(page, 'loginFlowState')!r}, client {auth['client']!r}")
        grant_url = auth["loginRedirectUrl"]                                            # the "Log in" button
        # not signed in: the grant page sends the browser to /login; the spike takes the Kanidm button there
        start = f"{FILES}/index.php/apps/user_oidc/login/1?" + urllib.parse.urlencode({"redirectUrl": grant_url})
        browse(start, cred, jar, lambda x: "/login/v2/grant" in x, log)
        st, _, page = req("GET", grant_url, cookies=jar)
        rt = re.search(rb'data-requesttoken="([^"]+)"', page).group(1).decode()
        log(f"  grant page: HTTP {st}, state {initial_state(page, 'loginFlowState')!r}")
        st, h, _ = form_post(f"{FILES}/index.php/login/v2/grant",
                             {"stateToken": auth["stateToken"], "requesttoken": rt}, {"Accept": "text/html"}, jar)
        log(f"  POST /login/v2/grant (the Grant access button) -> {st}")
    else:
        print(f"Open this address in the browser, sign in and grant access:\n  {d['login']}")
    for _ in range(150):
        st, _, data = form_post(d["poll"]["endpoint"], {"token": d["poll"]["token"]})
        if st == 200:
            r = json.loads(data)
            break
        time.sleep(2)
    else:
        raise SystemExit("FAIL: never granted")
    log(f"  poll -> 200: loginName={r['loginName']}, appPassword=<{len(r['appPassword'])} chars, not shown>")
    s = {"kind": "app-password", "user": r["loginName"], "app_password": r["appPassword"], "stored_at": time.time()}
    _write(os.path.join(RUN, "session.json") if store == "runtime" else os.path.join(HOME_STORE, "app-password"), s)
    return s


def initial_state(page, key):
    m = re.search(rb'id="initial-state-core-' + key.encode() + rb'" value="([^"]+)"', page)
    return json.loads(base64.b64decode(m.group(1))) if m else None


# ---------------------------------------------------------------- commands
def auth_header(s):
    if s["kind"] == "oidc":
        return "Bearer " + s["access_token"]
    return "Basic " + base64.b64encode(f"{s['user']}:{s['app_password']}".encode()).decode()


def main(argv):
    cmd = argv[0] if argv else ""
    which = argv[argv.index("--store") + 1] if "--store" in argv else None
    scripted = "--scripted-browser" in argv
    log = print
    if cmd == "oidc-login":
        s = oidc_login(scripted, log)
        st, who = ocs_user(auth_header(s))
        print(f"WHOAMI (Bearer): HTTP {st} {who}")
    elif cmd == "flow2-login":
        s = flow2_login(scripted, which or "runtime", log)
        st, who = ocs_user(auth_header(s))
        print(f"WHOAMI (app password): HTTP {st} {who}")
    elif cmd == "whoami":
        p, s = load(which)
        if not s:
            raise SystemExit("not signed in")
        if s["kind"] == "oidc" and ("--force-refresh" in argv or time.time() > s["expires_at"] - 30):
            s = oidc_refresh(p, s, log) or s
        st, who = ocs_user(auth_header(s))
        print(f"WHOAMI ({s['kind']}): HTTP {st} {who}")
    elif cmd == "stored":
        for p in _paths():
            if os.path.exists(p):
                print(json.dumps(describe(p, json.load(open(p))), indent=1))
    elif cmd == "logout":
        p, s = load(which)
        if not s:
            raise SystemExit("not signed in")
        if s["kind"] == "oidc":
            for t in ("refresh_token", "access_token"):
                if s.get(t):
                    st, _, data = form_post(f"{IDM}/oauth2/token/revoke", {"token": s[t], "client_id": CLIENT})
                    print(f"  revoke {t}: HTTP {st}")
        else:
            st, _, _ = req("DELETE", f"{FILES}/ocs/v2.php/core/apppassword",
                           headers={"Authorization": auth_header(s), "OCS-APIRequest": "true"})
            print(f"  DELETE core/apppassword: HTTP {st}")
        old = auth_header(s)
        os.unlink(p)
        st, who = ocs_user(old)
        print(f"  the old credential afterwards: HTTP {st} {who}")
    else:
        print(__doc__); return 2
    return 0


if __name__ == "__main__" and not globals().get("_AS_LIB"):     # on-dcli.sh a.py+b.py loads this as a library
    sys.exit(main(sys.argv[1:]))
