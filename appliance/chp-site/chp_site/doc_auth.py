# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The workstation sign-in of `chp-site doc` (ISO 0.7.0 Plan 3 Task 6; spike route 1, proto/doc_auth.py).

The user signs in at Kanidm through the public client chp-doc: authorization code + PKCE (S256), redirected to a
one-shot listener on 127.0.0.1 at a port the system picks (port 0; Kanidm allows any port for http://127.0.0.1/).
The listener answers only GET / and keeps waiting until a callback with the right `state` arrives (anything else is
answered 400 and ignored), then closes. Scopes: openid profile groups.

Tokens: the access token (15 min) and the refresh token (Kanidm's client setting, 8 h) live ONLY in
$XDG_RUNTIME_DIR/chp-doc/session.json (0600 in a 0700 folder). The runtime dir must be an absolute, private (0700,
the user's own, not a symlink) tmpfs folder, and linger must be off for the user, so the tokens die with the user's
last session; anything else is refused. Nothing is written to the home. When the session ends at Kanidm is read
from Kanidm (token introspection of the refresh token), never computed from a constant; when Kanidm does not say,
it is unknown.

Before every request the access token is refreshed when under REFRESH_MARGIN (60 s) remain, so it cannot expire
between the command and the appender's userinfo call; after a "retry" answer it is refreshed whatever remains.

Transport: https only, pinned to the site CA (no system store), no redirects followed and no proxy (http.client
does neither), a timeout on every call. Stdlib only, Python 3.9."""
import base64
import contextlib
import fcntl
import hashlib
import http.client
import http.server
import json
import os
import secrets
import ssl
import stat
import time
import urllib.parse
import webbrowser
from pathlib import Path

from .sitefile import SiteError

CLIENT = "chp-doc"
SCOPES = "openid profile groups"
SITE_CA = "/etc/pki/ca-trust/source/anchors/chp-root.crt"
FILES_PORT = 8443
TIMEOUT = 30
REFRESH_MARGIN = 60
REFRESH_LIFETIME = 28800          # the chp-doc client's refresh token lifetime (documents.DOC_REFRESH): the ESTIMATE only
LOGIN_TIMEOUT = 300
HANDLER_TIMEOUT = 5               # one callback connection may take this long (a silent one cannot hold the listener)
MAX_BODY = 160 << 20              # the largest answer read (a 64 MiB document fetched by WebDAV fits)
UA = "chp-site doc"


class AuthError(SiteError):
    """Sign-in problem (plain message for the user)."""


class Unreachable(AuthError):
    """Kanidm or NextCloud could not be reached (the request may be sent again later)."""


class Env:
    """Everything the doc commands touch on the workstation, injectable for tests."""

    def __init__(self, *, domain, uid, user_name, home, runtime, transport=None, mounts="/proc/self/mounts",
                 sysfs="/sys", linger_dir="/var/lib/systemd/linger", clock=time.time, sleep=time.sleep,
                 browser=None, site=None, site_dir="/etc/chp", templates="/usr/share/chp-templates/doc",
                 x2t="/opt/onlyoffice/desktopeditors/converter/x2t", editor_running=None,
                 login_timeout=LOGIN_TIMEOUT, poll_timeout=None, poll_interval=1.0, run_user="/run/user"):
        self.domain, self.uid, self.user_name = domain, uid, user_name
        self.home, self.runtime = Path(home), runtime
        self.transport = transport or https_transport()
        self.mounts, self.sysfs, self.linger_dir = mounts, sysfs, linger_dir
        self.clock, self.sleep = clock, sleep
        self.browser = browser
        self.site, self.site_dir = site, site_dir
        self.templates, self.x2t = templates, x2t
        self.editor_running = editor_running
        self.login_timeout = login_timeout
        self.poll_timeout, self.poll_interval = poll_timeout, poll_interval
        self.run_user = run_user

    @property
    def idm(self):
        return f"https://idm.{self.domain}"

    @property
    def files(self):
        return f"https://files.{self.domain}:{FILES_PORT}"


# ---------- transport ----------

def _ssl_context(cafile):
    if not cafile or not os.path.isfile(cafile):
        raise AuthError(f"the site CA certificate {cafile} is missing (this workstation was not set up by CHP?)")
    ctx = ssl.create_default_context(cafile=cafile)       # the site CA only: with cafile, no system store is loaded
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def https_transport(cafile=SITE_CA, timeout=TIMEOUT):
    """(method, url, headers, body) -> (status, {lower-case header: value}, bytes). http.client follows no
    redirect and reads no proxy setting."""
    state = {}

    def call(method, url, headers=None, body=None):
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            raise AuthError(f"refused: {url} is not an https:// address")
        if "ctx" not in state:
            state["ctx"] = _ssl_context(cafile)
        c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=state["ctx"], timeout=timeout)
        h = {"User-Agent": UA, "Accept": "*/*"}
        h.update(headers or {})
        try:
            c.request(method, (u.path or "/") + ("?" + u.query if u.query else ""),
                      body=body.encode() if isinstance(body, str) else body, headers=h)
            r = c.getresponse()
            data = r.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise AuthError(f"refused: the answer from {u.hostname} is too large")
            return r.status, {k.lower(): v for k, v in r.getheaders()}, data
        except ssl.SSLCertVerificationError as e:
            raise AuthError(f"refused: {u.hostname}'s certificate does not verify against the site CA ({e})") from None
        except (OSError, http.client.HTTPException) as e:
            raise Unreachable(f"{u.hostname} could not be reached ({e})") from None
        finally:
            c.close()
    return call


def _form(fields):
    return urllib.parse.urlencode(fields)


def _call(env, method, url, headers=None, body=None):
    try:
        return env.transport(method, url, headers or {}, body)
    except AuthError:
        raise
    except (OSError, http.client.HTTPException) as e:
        raise Unreachable(f"{urllib.parse.urlsplit(url).hostname} could not be reached ({e})") from None


def _json(data):
    try:
        v = json.loads(data)
    except (ValueError, TypeError):
        return None
    return v


# ---------- the runtime dir ----------

def _unescape_mount(s):
    return s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def mount_of(path, mounts="/proc/self/mounts"):
    """(source, mount point, fs type) of the mount holding path (the longest mount point that contains it)."""
    p = os.path.realpath(path)
    best = None
    try:
        lines = Path(mounts).read_text().splitlines()
    except OSError:
        return None
    for ln in lines:
        f = ln.split()
        if len(f) < 3:
            continue
        src, mnt, typ = _unescape_mount(f[0]), _unescape_mount(f[1]), f[2]
        m = mnt.rstrip("/") or "/"
        if p == m or p.startswith(m.rstrip("/") + "/") or m == "/":
            if best is None or len(m) >= len(best[1]):
                best = (src, m, typ)
    return best


def runtime_dir(env):
    """$XDG_RUNTIME_DIR/chp-doc, made 0700; refused unless the runtime dir is /run/user/<uid> (logind's), a private
    tmpfs folder of this user, and linger is off (so the tokens die with the user's last session)."""
    r = env.runtime
    why = None
    if not r:
        why = "XDG_RUNTIME_DIR is not set (sign in on the desktop or through ssh, so systemd makes it)"
    elif not os.path.isabs(r):
        why = f"XDG_RUNTIME_DIR ({r}) is not an absolute path"
    elif os.path.normpath(r) != os.path.join(env.run_user, str(env.uid)):
        # final review B M7: systemd-logind's own runtime dir only (/run/user/<uid>), not any private tmpfs folder
        why = f"XDG_RUNTIME_DIR ({r}) is not {os.path.join(env.run_user, str(env.uid))}"
    else:
        try:
            st = os.lstat(r)
        except OSError:
            st = None
        if st is None or not stat.S_ISDIR(st.st_mode):
            why = f"XDG_RUNTIME_DIR ({r}) is not a folder (or is a symbolic link)"
        elif st.st_uid != env.uid or stat.S_IMODE(st.st_mode) != 0o700:
            why = f"XDG_RUNTIME_DIR ({r}) is not private to you (it must be yours, mode 0700)"
        else:
            m = mount_of(r, env.mounts)
            if m is None or m[2] != "tmpfs":
                why = f"XDG_RUNTIME_DIR ({r}) is not on tmpfs (the tokens must stay in memory)"
    if why:
        raise AuthError(f"refused: {why}; the sign-in tokens are kept only there")
    if env.user_name and os.path.exists(os.path.join(env.linger_dir, env.user_name)):
        raise AuthError(f"refused: linger is on for {env.user_name} (loginctl enable-linger), so the runtime dir and "
                        "the tokens would outlive your sessions; an administrator turns it off "
                        f"(loginctl disable-linger {env.user_name})")
    d = Path(r) / "chp-doc"
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != env.uid:
        raise AuthError(f"refused: {d} is not your folder")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(d, 0o700)
    return d


def write_private(path, obj):
    """JSON to path, 0600, atomically (a temporary file beside it, then a rename)."""
    tmp = f"{path}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def locked(env, name):
    """An exclusive flock on $XDG_RUNTIME_DIR/chp-doc/<name>.lock for the duration (session refresh, pending ids):
    two chp-site doc commands at once wait for each other instead of both using the rotating refresh token."""
    p = runtime_dir(env) / f"{name}.lock"
    fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)                                     # closing the descriptor releases the lock


def _session_path(env):
    return runtime_dir(env) / "session.json"


def load(env):
    p = _session_path(env)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd) as f:
        s = _json(f.read())
    return s if isinstance(s, dict) and s.get("access_token") else None


# ---------- sign-in ----------

def _claims(id_token):
    try:
        part = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (AttributeError, IndexError, ValueError):
        return {}


def _listen(env, state, say):
    """Serve http://127.0.0.1:<port>/ until the right state arrives (or the time runs out): (port, wait())."""
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        timeout = HANDLER_TIMEOUT                        # StreamRequestHandler: settimeout on the connection

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            ok = u.path == "/" and q.get("state") == state and not got
            if ok and ("code" in q or "error" in q):
                got.update(q)
                self.send_response(200)
                text = b"Signed in. You can close this tab and go back to the terminal.\n" if "code" in q else \
                    b"The sign-in did not complete. Go back to the terminal.\n"
            else:
                self.send_response(400)
                text = b"Not this sign-in. Go back to the terminal and try again.\n"
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(text)))
            self.end_headers()
            self.wfile.write(text)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)     # loopback only; the system picks the port

    def wait():
        deadline = time.monotonic() + env.login_timeout
        try:
            while not got:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                srv.timeout = min(left, 1.0)
                srv.handle_request()
        finally:
            srv.server_close()
        return got
    return srv.server_address[1], wait


def _store(env, s):
    write_private(_session_path(env), s)
    return s


def _introspect(env, s):
    """When the Kanidm session behind the refresh token ends (epoch seconds), as Kanidm says; None = Kanidm did not
    say (never computed here)."""
    try:
        st, _, data = _call(env, "POST", f"{env.idm}/oauth2/token/introspect",
                            {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                            _form({"token": s["refresh_token"], "token_type_hint": "refresh_token",
                                   "client_id": CLIENT}))
    except Unreachable:
        return s.get("session_expires_at")
    d = _json(data) if st == 200 else None
    if isinstance(d, dict) and d.get("active") is True and isinstance(d.get("exp"), (int, float)):
        return int(d["exp"])
    return None


def _token_response(env, data, nonce=None):
    tok = _json(data)
    if not isinstance(tok, dict) or not tok.get("access_token"):
        raise AuthError("refused: Kanidm's token answer is not usable")
    now = env.clock()
    out = {"access_token": tok["access_token"], "refresh_token": tok.get("refresh_token"),
           "expires_at": now + int(tok.get("expires_in") or 300)}
    if nonce is not None and not tok.get("id_token"):
        raise AuthError("refused: Kanidm's answer has no ID token, so this sign-in cannot be checked (nonce, user "
                        "name); ask the administrator to check the chp-doc client's openid scope")
    if tok.get("id_token"):
        c = _claims(tok["id_token"])
        if nonce is not None and c.get("nonce") != nonce:
            raise AuthError("refused: Kanidm's ID token does not carry this sign-in's nonce")
        out["user"] = c.get("preferred_username")
    return out


def nc_user(env, access_token):
    """NextCloud's name for this sign-in. An account with NO groups is refused (P3-D3): user_oidc made it from the
    chp-doc Bearer for a person who never signed in on the web (no groups, so no area is visible); one web sign-in
    maps the person's Kanidm groups. A NextCloud that does not list groups is not judged here."""
    st, _, data = _call(env, "GET", f"{env.files}/ocs/v2.php/cloud/user?format=json",
                        {"Authorization": "Bearer " + access_token, "OCS-APIRequest": "true",
                         "Accept": "application/json"})
    d = _json(data) if st == 200 else None
    try:
        who = d["ocs"]["data"]["id"]
        groups = d["ocs"]["data"].get("groups")
    except (TypeError, KeyError, AttributeError):
        raise AuthError(f"refused: NextCloud did not accept the sign-in (HTTP {st})") from None
    if isinstance(groups, list) and not groups:
        raise AuthError(f"refused: your NextCloud account {who} has no groups (a chp-doc sign-in made it before you ever "
                        "signed in on the web, or your groups were taken away): sign in once in the browser at "
                        f"{env.files}/ (NextCloud then takes your groups from Kanidm), then run chp-site doc login "
                        "again; if that does not help, ask the administrator")
    return who


def login(env, say=print):
    """Sign in at Kanidm (PKCE, loopback) and keep the tokens in the runtime dir. Returns the session."""
    runtime_dir(env)                                     # refused before anything is shown or sent
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(16)
    port, wait = _listen(env, state, say)
    redirect = f"http://127.0.0.1:{port}/"
    url = f"{env.idm}/ui/oauth2?" + urllib.parse.urlencode({
        "response_type": "code", "client_id": CLIENT, "redirect_uri": redirect, "scope": SCOPES, "state": state,
        "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
    say(f"Sign in at Kanidm in the browser (it should open by itself; if not, open this address):\n  {url}")
    (env.browser or _open_browser)(url)
    got = wait()
    if not got:
        raise AuthError(f"refused: no sign-in came back within {int(env.login_timeout)} s; run chp-site doc login "
                        "again")
    if "code" not in got:
        raise AuthError(f"refused: Kanidm did not sign you in ({got.get('error', 'no code')}); run chp-site doc "
                        "login again")
    st, _, data = _call(env, "POST", f"{env.idm}/oauth2/token",
                        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                        _form({"grant_type": "authorization_code", "code": got["code"], "redirect_uri": redirect,
                               "client_id": CLIENT, "code_verifier": verifier}))
    if st != 200:
        raise AuthError(f"refused: Kanidm refused the sign-in code (HTTP {st}); run chp-site doc login again")
    s = _token_response(env, data, nonce)
    who = nc_user(env, s["access_token"])
    if s.get("user") and who != s["user"]:
        raise AuthError(f"refused: NextCloud knows this sign-in as {who}, Kanidm as {s['user']}; the ledger would "
                        "refuse every request (ask the administrator)")
    s.update(user=s.get("user") or who, nc_user=who, stored_at=env.clock())
    s["session_expires_at"] = _introspect(env, s)
    # Kanidm 1.x answers the refresh token's introspection "active: false" (P3-D12, ruling): then the end is shown as
    # an ESTIMATE (now + the chp-doc refresh lifetime), labelled so, and never used to refuse anything
    s["session_estimate"] = None if s["session_expires_at"] else int(env.clock() + REFRESH_LIFETIME)
    _store(env, s)
    if s["session_expires_at"]:
        until = time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(s["session_expires_at"]))
    else:
        until = (time.strftime("about %Y-%m-%d %H:%M %Z", time.localtime(s["session_estimate"]))
                 + f" (an estimate: sign-in time + the {REFRESH_LIFETIME // 3600} h refresh lifetime; Kanidm did not "
                   "give the end)")
    say(f"signed in as {s['user']} (sign-in ends: {until})")
    return s


def _open_browser(url):
    try:
        webbrowser.open(url)
    except Exception:                                    # noqa: BLE001 - the address is printed anyway
        pass


def _ended(env):
    return AuthError("refused: your Kanidm sign-in has ended; run chp-site doc login")


def refresh(env, s):
    if not s.get("refresh_token"):
        raise _ended(env)
    st, _, data = _call(env, "POST", f"{env.idm}/oauth2/token",
                        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                        _form({"grant_type": "refresh_token", "refresh_token": s["refresh_token"],
                               "client_id": CLIENT}))
    if st in (400, 401, 403):
        raise _ended(env)
    if st != 200:
        raise Unreachable(f"Kanidm could not refresh the sign-in (HTTP {st})")
    new = _token_response(env, data)
    s = dict(s, access_token=new["access_token"], refresh_token=new.get("refresh_token") or s["refresh_token"],
             expires_at=new["expires_at"])
    s["session_expires_at"] = _introspect(env, s)
    return _store(env, s)


def fresh(env, force=False):
    """The session, its access token good for at least REFRESH_MARGIN more seconds (force: refreshed whatever remains,
    after a "retry" answer). Raises AuthError (sign in again) or Unreachable. The refresh holds the session lock and
    re-reads the session inside it: when another command refreshed meanwhile, its new token is used (Kanidm rotates
    the refresh token; using an old one twice may end the session)."""
    s0 = load(env)
    if s0 is None:
        raise AuthError("refused: not signed in; run chp-site doc login")
    if not force and s0.get("expires_at", 0) - env.clock() >= REFRESH_MARGIN:
        return s0
    with locked(env, "session"):
        s = load(env)
        if s is None:
            raise AuthError("refused: not signed in; run chp-site doc login")
        now = env.clock()
        renewed = s.get("access_token") != s0.get("access_token")
        if renewed and s.get("expires_at", 0) - now >= REFRESH_MARGIN:
            return s                                     # another command refreshed while this one waited
        end = s.get("session_expires_at")
        if end is not None and end - now < REFRESH_MARGIN:
            raise _ended(env)                            # Kanidm's own end of the session: a refresh cannot help
        return refresh(env, s)


def logout(env, say=print):
    """Revoke both tokens at Kanidm (best effort) and remove the local copy (always)."""
    p = _session_path(env)
    s = load(env)
    if s is None:
        say("not signed in")
        return
    try:
        for kind in ("refresh_token", "access_token"):
            if s.get(kind):
                try:
                    st, _, _ = _call(env, "POST", f"{env.idm}/oauth2/token/revoke",
                                      {"Content-Type": "application/x-www-form-urlencoded"},
                                      _form({"token": s[kind], "token_type_hint": kind, "client_id": CLIENT}))
                    if st != 200:
                        say(f"Kanidm did not confirm the revocation of the {kind.replace('_', ' ')} (HTTP {st})")
                except Exception as e:                   # noqa: BLE001 - the local copy goes anyway
                    say(f"Kanidm could not be reached to revoke the {kind.replace('_', ' ')} ({e})")
    finally:
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    say("signed out; the tokens are removed from this workstation")
