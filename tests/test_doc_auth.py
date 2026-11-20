"""Plan 3 Task 6: the workstation sign-in of `chp-site doc` (chp_site.doc_auth). A stub plays Kanidm and NextCloud
(the transport seam); the loopback listener is real (127.0.0.1, port 0). Made-up names and tokens only."""
import base64
import hashlib
import json
import os
import stat
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

from chp_site import doc_auth as A

D = "example.test"
IDM = f"https://idm.{D}"
FILES = f"https://files.{D}:8443"


def _jwt(claims):
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'ES256', 'typ': 'JWT'})}.{enc(claims)}.c2ln"


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class Stub:
    """Kanidm (token, introspect, revoke) and NextCloud (OCS user, WebDAV, chp_ledger) behind the transport seam."""

    def __init__(self, clock, user="alice"):
        self.clock, self.user = clock, user
        self.calls = []
        self.n = 0
        self.access_ttl = 900
        self.session_exp = clock() + 28800          # what Kanidm's introspection says (None: no exp in the answer)
        self.introspect_status = 200
        self.introspect_active = True                # Kanidm 1.x answers a refresh token's introspection active: false
        self.nc_groups = ["chp-users", "cui-users"]  # NextCloud's groups of the account (None: not in the answer)
        self.refresh_ok = True
        self.valid = set()
        self.exp = {}                                # access token -> when NextCloud stops taking it
        self.refresh_delay = 0.0                     # real seconds a refresh answer takes (after the rotation)
        self.id_token = True
        self.dav_garbage = False
        self.refreshes = 0
        self.revoked = []
        self.code = None
        self.challenge = None
        self.nonce = None
        self.nc_user = user
        # NextCloud's tree for this user: folders and files (path -> bytes), file ids
        self.folders = ["CUI", "CUI/Compliance", "Internal", "Internal/Compliance", "Internal/Compliance/Superseded"]
        self.files = {}
        self.ids = {}
        self.etags = {}
        self.next_id = 100
        for f in self.folders:
            self._id(f)
        # chp_ledger
        self.requests = []                           # (body, bearer)
        self.script = {}                             # request_id -> list of result states still to answer
        self.post_status = {}                        # request_id -> list of HTTP statuses for its next POSTs
        self.seq = 0
        self.answers = {}

    def _id(self, path):
        if path not in self.ids:
            self.next_id += 1
            self.ids[path] = self.next_id
            self.etags[path] = f'"e{self.next_id}"'
        return self.ids[path]

    def put(self, path, data):
        self.files[path] = data
        self._id(path)
        self.etags[path] = f'"e{self.ids[path]}-{hashlib.sha256(data).hexdigest()[:6]}"'

    def path_of(self, fid):
        return next(p for p, i in self.ids.items() if i == fid)

    # ---- the transport
    def __call__(self, method, url, headers=None, body=None):
        headers = headers or {}
        self.calls.append((method, url, dict(headers), body))
        u = urllib.parse.urlsplit(url)
        assert u.scheme == "https"
        if u.netloc == f"idm.{D}":
            return self._kanidm(method, u.path, urllib.parse.parse_qs((body or b"").decode() if isinstance(body, bytes)
                                                                       else body or ""))
        assert u.netloc == f"files.{D}:8443"
        tok = headers.get("Authorization", "")
        if not tok.startswith("Bearer ") or tok[7:] not in self.valid or self.clock() > self.exp.get(tok[7:], 0):
            return 401, {}, b'{"ocs":{"data":{"state":"refused","message":"refused: not signed in"}}}'
        if u.path == "/ocs/v2.php/cloud/user":
            data = {"id": self.nc_user}
            if self.nc_groups is not None:
                data["groups"] = list(self.nc_groups)
            return 200, {}, json.dumps({"ocs": {"data": data}}).encode()
        if u.path.startswith(f"/remote.php/dav/files/{self.nc_user}"):
            rel = urllib.parse.unquote(u.path[len(f"/remote.php/dav/files/{self.nc_user}"):]).strip("/")
            return self._dav(method, rel, headers)
        if u.path == "/ocs/v2.php/apps/chp_ledger/api/v1/request":
            return self._request(json.loads(body), tok[7:])
        if u.path.startswith("/ocs/v2.php/apps/chp_ledger/api/v1/result/"):
            return self._result(u.path.rsplit("/", 1)[1])
        return 404, {}, b""

    def _tokens(self):
        self.n += 1
        at, rt = f"at{self.n}", f"rt{self.n}"
        self.valid.add(at)
        self.exp[at] = self.clock() + self.access_ttl
        self.current_rt = rt
        out = {"access_token": at, "refresh_token": rt, "token_type": "Bearer", "expires_in": self.access_ttl}
        if self.id_token:
            out["id_token"] = _jwt({"preferred_username": self.user, "nonce": self.nonce, "aud": "chp-doc"})
        return out

    def _kanidm(self, method, path, form):
        f = {k: v[0] for k, v in form.items()}
        if path == "/oauth2/token" and f.get("grant_type") == "authorization_code":
            ch = base64.urlsafe_b64encode(hashlib.sha256(f["code_verifier"].encode()).digest()).rstrip(b"=").decode()
            if f.get("code") != self.code or ch != self.challenge or f.get("client_id") != "chp-doc":
                return 400, {}, b'{"error":"invalid_grant"}'
            return 200, {}, json.dumps(self._tokens()).encode()
        if path == "/oauth2/token" and f.get("grant_type") == "refresh_token":
            if not self.refresh_ok or f.get("refresh_token") != self.current_rt:
                return 400, {}, b'{"error":"invalid_grant"}'
            self.refreshes += 1
            out = json.dumps(self._tokens()).encode()     # rotated now: the old refresh token is spent
            if self.refresh_delay:
                import time
                time.sleep(self.refresh_delay)
            return 200, {}, out
        if path == "/oauth2/token/introspect":
            if self.introspect_status != 200:
                return self.introspect_status, {}, b""
            if not self.introspect_active:
                return 200, {}, b'{"active": false}'
            out = {"active": True}
            if self.session_exp is not None:
                out["exp"] = int(self.session_exp)
            return 200, {}, json.dumps(out).encode()
        if path == "/oauth2/token/revoke":
            self.revoked.append(f.get("token"))
            self.valid.discard(f.get("token"))
            return 200, {}, b""
        return 404, {}, b""

    def _dav(self, method, rel, headers):
        if method == "GET":
            if rel not in self.files:
                return 404, {}, b""
            return 200, {"etag": self.etags[rel]}, self.files[rel]
        assert method == "PROPFIND"
        if self.dav_garbage:
            return 207, {}, b"<html>not a listing"
        if rel not in self.files and rel not in self.folders:
            return 404, {}, b""
        items = [rel]
        if headers.get("Depth") == "1" and rel in self.folders:
            items += [p for p in self.folders + list(self.files) if p.rsplit("/", 1)[0] == rel and p != rel
                      and "/" in p]
        out = ['<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">']
        for p in items:
            coll = "<d:collection/>" if p in self.folders else ""
            size = len(self.files.get(p, b""))
            href = urllib.parse.quote(f"/remote.php/dav/files/{self.nc_user}/{p}" + ("/" if coll else ""))
            out.append(f"<d:response><d:href>{escape(href)}</d:href><d:propstat><d:prop>"
                       f"<d:getetag>{escape(self.etags[p])}</d:getetag><oc:fileid>{self.ids[p]}</oc:fileid>"
                       f"<oc:size>{size}</oc:size><d:resourcetype>{coll}</d:resourcetype></d:prop>"
                       "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")
        out.append("</d:multistatus>")
        return 207, {}, "".join(out).encode()

    def _request(self, b, bearer):
        self.requests.append((b, bearer))
        sts = self.post_status.get(b["request_id"])
        if sts:
            st = sts.pop(0)
            if st != 200:
                return st, {}, b'{"ocs":{"data":{"state":"refused","message":"refused: the request is not valid"}}}'
        self.answers.setdefault(b["request_id"], b)
        self.answers[b["request_id"]] = b
        return 200, {}, json.dumps({"ocs": {"data": {"request_id": b["request_id"], "state": "queued"}}}).encode()

    def _result(self, rid):
        b = self.answers.get(rid)
        if b is None:
            return 404, {}, b'{"ocs":{"data":{"state":"refused","message":"refused"}}}'
        todo = self.script.get(rid) or self.script.get("*")
        state = todo.pop(0) if todo else "done"
        if state == "queued":
            return 200, {}, json.dumps({"ocs": {"data": {"request_id": rid, "state": "queued"}}}).encode()
        if state == "retry":
            msg = "pending: Kanidm did not accept your sign-in token (it may have expired); nothing was recorded"
            return 200, {}, json.dumps({"ocs": {"data": {"request_id": rid, "state": "retry", "message": msg}}}).encode()
        if state.startswith("refused"):
            return 200, {}, json.dumps({"ocs": {"data": {"request_id": rid, "state": "refused",
                                                         "message": state}}}).encode()
        if rid not in getattr(self, "_done", {}):
            self.seq += 1
            e = {"seq": self.seq, "kind": b["kind"], "user": self.user, "request_id": rid, "file_id": None,
                 "sha256": b.get("sha256", ""), "cycle": 1}
            if b["kind"] == "checkout":
                p = self.path_of(int(b["file_id"]))
                e.update(file_id=int(b["file_id"]), path=p, sha256=hashlib.sha256(self.files[p]).hexdigest())
            else:
                e["path"] = self.path_of(int(b["file_id"])) + "/" + b.get("path", "")
            if b["kind"] == "publish":
                e["cr"] = f"CR-2027-{self.seq:04d}"
                msg = f"published {e['path']} as {e['cr']} (ledger entry {e['seq']})"
            else:
                msg = f"{b['kind']} recorded (ledger entry {e['seq']})"
            self._done = getattr(self, "_done", {})
            self._done[rid] = (msg, e)
        msg, e = self._done[rid]
        return 200, {}, json.dumps({"ocs": {"data": {"request_id": rid, "state": "done", "message": msg,
                                                     "entry": e}}}).encode()


def make_env(tmp_path, stub=None, clock=None, **kw):
    clock = clock or Clock()
    stub = stub or Stub(clock)
    home = tmp_path / "home"
    run = tmp_path / "run"
    home.mkdir(exist_ok=True)
    run.mkdir(mode=0o700, exist_ok=True)
    os.chmod(run, 0o700)
    os.chmod(home, 0o700)
    mounts = tmp_path / "mounts"
    rp = lambda p: os.path.realpath(p).replace(" ", "\\040")
    mounts.write_text(f"/dev/sda1 / xfs rw 0 0\ntmpfs {rp(run)} tmpfs rw,nosuid,nodev 0 0\n"
                      f"/dev/mapper/rl-home {rp(home)} xfs rw 0 0\n")
    sysfs = tmp_path / "sys"
    for dm, name, uuid, slaves in (("dm-1", "rl-home", "LVM-abc", ["dm-0"]),
                                   ("dm-0", "luks-1234", "CRYPT-LUKS2-1234-luks-1234", [])):
        b = sysfs / "block" / dm
        (b / "dm").mkdir(parents=True, exist_ok=True)
        (b / "dm" / "name").write_text(name + "\n")
        (b / "dm" / "uuid").write_text(uuid + "\n")
        (b / "slaves").mkdir(exist_ok=True)
        for s in slaves:
            (b / "slaves" / s).mkdir(exist_ok=True)
    args = dict(domain=D, uid=os.getuid(), user_name="alice", home=home, runtime=str(run), transport=stub,
                mounts=str(mounts), sysfs=str(sysfs), linger_dir=str(tmp_path / "linger"), clock=clock,
                sleep=clock.sleep)
    args.update(kw)
    env = A.Env(**args)
    env.stub = stub
    return env


def browser_for(stub, extra=()):
    """A browser that signs in at Kanidm and lands on the loopback redirect; `extra` callbacks arrive first."""
    seen = {}

    def go(url):
        q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
        seen.update(q)
        stub.challenge, stub.nonce = q["code_challenge"], q["nonce"]
        stub.code = "code-123"

        def hit():
            red = q["redirect_uri"]
            seen["answers"] = []
            for e in list(extra) + [{"code": stub.code, "state": q["state"]}]:
                try:
                    with urllib.request.urlopen(red + "?" + urllib.parse.urlencode(e), timeout=5) as r:
                        seen["answers"].append(r.status)
                except urllib.error.HTTPError as err:
                    seen["answers"].append(err.code)
        threading.Thread(target=hit, daemon=True).start()
    go.seen = seen
    return go


def login(env, extra=()):
    env.browser = browser_for(env.stub, extra)
    return A.login(env, say=lambda *a: None)


# ---------- sign-in ----------

def test_login_pkce_loopback_port0_state_checked(tmp_path):
    env = make_env(tmp_path)
    s = login(env, extra=[{"code": "evil", "state": "wrong"}, {"code": "evil"}, {"error": "x", "state": "nope"}])
    seen = env.browser.seen
    red = urllib.parse.urlsplit(seen["redirect_uri"])
    assert red.scheme == "http" and red.hostname == "127.0.0.1" and red.path == "/" and red.port not in (None, 0)
    assert seen["code_challenge_method"] == "S256" and seen["client_id"] == "chp-doc"
    assert seen["scope"] == "openid profile groups"
    assert seen["answers"] == [400, 400, 400, 200]          # wrong state ignored: the listener kept waiting
    assert s["user"] == "alice" and s["access_token"] == "at1"
    token_call = [c for c in env.stub.calls if c[1] == f"{IDM}/oauth2/token"][0]
    assert "code=code-123" in token_call[3] and "code_verifier=" in token_call[3]
    with pytest.raises(OSError):                            # the listener is closed after the sign-in
        urllib.request.urlopen(seen["redirect_uri"], timeout=2)


def test_login_times_out_without_the_right_state(tmp_path):
    clock = Clock()
    env = make_env(tmp_path, clock=clock)
    env.login_timeout = 1.0
    env.browser = lambda url: None                          # nobody comes back
    with pytest.raises(A.AuthError, match="no sign-in"):
        A.login(env, say=lambda *a: None)


def test_tokens_in_runtime_dir_only(tmp_path):
    env = make_env(tmp_path)
    login(env)
    f = Path(env.runtime) / "chp-doc" / "session.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    assert json.loads(f.read_text())["refresh_token"] == "rt1"
    for p in (tmp_path / "home").rglob("*"):                # nothing in the home (on disk) holds a token
        if p.is_file():
            assert b"at1" not in p.read_bytes() and b"rt1" not in p.read_bytes()


@pytest.mark.parametrize("bad", ["unset", "relative", "not-tmpfs", "mode", "symlink", "linger"])
def test_runtime_dir_refused(tmp_path, bad):
    env = make_env(tmp_path)
    if bad == "unset":
        env.runtime = None
    elif bad == "relative":
        env.runtime = "run"
    elif bad == "not-tmpfs":
        Path(env.mounts).write_text(f"/dev/sda1 / xfs rw 0 0\n")
    elif bad == "mode":
        os.chmod(env.runtime, 0o755)
    elif bad == "symlink":
        os.symlink(env.runtime, tmp_path / "run-link")
        env.runtime = str(tmp_path / "run-link")
    elif bad == "linger":
        (tmp_path / "linger").mkdir()
        (tmp_path / "linger" / "alice").write_text("")
    with pytest.raises(A.AuthError) as e:
        login(env)
    assert "XDG_RUNTIME_DIR" in str(e.value) or "linger" in str(e.value)
    assert not list(Path(tmp_path / "run").rglob("session.json"))


def test_refresh_before_send(tmp_path):
    clock = Clock()
    env = make_env(tmp_path, clock=clock)
    login(env)
    clock.t += 900 - 59                                     # under 60 s left: refreshed before it is sent
    s = A.fresh(env)
    assert s["access_token"] == "at2" and s["refresh_token"] == "rt2"
    clock.t += 900 - 61                                     # 61 s left: used as it is
    assert A.fresh(env)["access_token"] == "at2"
    assert A.fresh(env, force=True)["access_token"] == "at3"   # after a "retry" answer: always a fresh one
    stored = json.loads((Path(env.runtime) / "chp-doc" / "session.json").read_text())
    assert stored["access_token"] == "at3" and stored["refresh_token"] == "rt3"


def test_refresh_refused_means_sign_in_again(tmp_path):
    clock = Clock()
    env = make_env(tmp_path, clock=clock)
    login(env)
    env.stub.refresh_ok = False
    clock.t += 900
    with pytest.raises(A.AuthError, match="chp-site doc login"):
        A.fresh(env)


def test_refresh_near_8h_limit_reads_expiry_from_kanidm(tmp_path):
    clock = Clock()
    env = make_env(tmp_path, clock=clock)
    env.stub.session_exp = clock() + 3600                   # Kanidm says: the session ends in 1 h (not 8 h)
    s = login(env)
    assert s["session_expires_at"] == int(clock() + 3600)
    assert [c for c in env.stub.calls if c[1] == f"{IDM}/oauth2/token/introspect"]
    clock.t += 3600 - 30                                    # 30 s before Kanidm's end: no refresh, sign in again
    n = len(env.stub.calls)
    with pytest.raises(A.AuthError, match="chp-site doc login"):
        A.fresh(env)
    assert len(env.stub.calls) == n                         # nothing was sent
    # a refresh re-reads the expiry (Kanidm may move it); no expiry in Kanidm's answer = unknown, never a constant
    (tmp_path / "b").mkdir()
    env2 = make_env(tmp_path / "b", clock=Clock())
    env2.stub.session_exp = None
    s2 = login(env2)
    assert s2["session_expires_at"] is None
    env2.clock.t += 7 * 3600 + 3540
    env2.stub.session_exp = env2.clock() + 120
    s3 = A.fresh(env2)
    assert s3["access_token"] == "at2" and s3["session_expires_at"] == int(env2.clock() + 120)


def test_login_refuses_a_nextcloud_user_that_is_not_the_kanidm_name(tmp_path):
    env = make_env(tmp_path)
    env.stub.nc_user = "bob"
    with pytest.raises(A.AuthError, match="bob"):
        login(env)
    assert not (Path(env.runtime) / "chp-doc" / "session.json").exists()


def test_logout_removes_tokens(tmp_path):
    env = make_env(tmp_path)
    login(env)
    A.logout(env, say=lambda *a: None)
    assert not (Path(env.runtime) / "chp-doc" / "session.json").exists()
    assert set(env.stub.revoked) == {"at1", "rt1"}
    with pytest.raises(A.AuthError, match="not signed in"):
        A.fresh(env)
    # Kanidm unreachable at logout: the local copy goes anyway
    login(env)

    def down(*a, **k):
        raise OSError("unreachable")
    env.transport = down
    A.logout(env, say=lambda *a: None)
    assert not (Path(env.runtime) / "chp-doc" / "session.json").exists()


def test_https_transport_is_pinned_and_never_redirects(tmp_path):
    with pytest.raises(A.AuthError, match="https"):
        A.https_transport(cafile=str(tmp_path / "none.crt"))("GET", "http://files.example.test/", {}, None)
    with pytest.raises(A.AuthError, match="site CA"):
        A._ssl_context(str(tmp_path / "none.crt"))
    import ssl
    ca = Path(__file__).parent / "fixtures" / "kanidm-lab-root.crt"
    ctx = A._ssl_context(str(ca))
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert len(ctx.get_ca_certs()) == 1                     # the site CA only, no system store


# ---------- fix round 1 ----------

def test_login_silent_connection_does_not_hold_the_listener(tmp_path):
    import socket
    import time
    env = make_env(tmp_path)
    env.login_timeout = 1.0
    held = []

    def silent(url):
        red = urllib.parse.urlsplit(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))["redirect_uri"])
        held.append(socket.create_connection((red.hostname, red.port)))   # connects, never sends a request
    env.browser = silent
    t0 = time.monotonic()
    with pytest.raises(A.AuthError, match="no sign-in"):
        A.login(env, say=lambda *a: None)
    assert time.monotonic() - t0 < 1.0 + A.HANDLER_TIMEOUT + 2
    held[0].close()


def test_login_refuses_without_id_token(tmp_path):
    env = make_env(tmp_path)
    env.stub.id_token = False
    with pytest.raises(A.AuthError, match="no ID token"):
        login(env)
    assert not (Path(env.runtime) / "chp-doc" / "session.json").exists()


def test_refresh_is_locked_between_commands(tmp_path):
    """Two commands refreshing at once: the second waits and uses the first one's new token instead of sending the
    spent (rotated) refresh token, which Kanidm refuses."""
    import time
    env = make_env(tmp_path)
    login(env)
    env.stub.refresh_delay = 0.3
    out, errs = [], []

    def one():
        try:
            out.append(A.fresh(env, force=True)["access_token"])
        except Exception as e:                              # noqa: BLE001
            errs.append(e)
    t1 = threading.Thread(target=one)
    t1.start()
    time.sleep(0.1)
    t2 = threading.Thread(target=one)
    t2.start()
    t1.join(5)
    t2.join(5)
    assert not errs and out == ["at2", "at2"] and env.stub.refreshes == 1


# ---------- Task 13a ----------

def test_13a_d12_inactive_introspection_shows_an_estimate_never_used_to_refuse(tmp_path):
    """P3-D12 (logs/119, 173): Kanidm 1.x answers the refresh token's introspection "active: false". The sign-in end is
    then shown as an ESTIMATE (sign-in time + the chp-doc client's 8 h refresh lifetime), labelled so; it is never
    used to refuse (only Kanidm's own answer is)."""
    from chp_site import documents
    assert A.REFRESH_LIFETIME == documents.DOC_REFRESH
    clock = Clock()
    env = make_env(tmp_path, clock=clock)
    env.stub.introspect_active = False
    said = []
    env.browser = browser_for(env.stub)
    t0 = clock()
    s = A.login(env, say=said.append)
    assert s["session_expires_at"] is None and s["session_estimate"] == int(t0 + 28800)
    line = said[-1]
    assert "estimate" in line and "Kanidm did not say" not in line and "8 h" in line, line
    clock.t += 28800 + 600                               # past the estimate: still a refresh, never a local refusal
    s2 = A.fresh(env)
    assert s2["access_token"] != s["access_token"] and s2["session_estimate"] == int(t0 + 28800)
    # Kanidm's own answer, when it gives one, is shown as it is (no estimate)
    (tmp_path / "b").mkdir()
    env2 = make_env(tmp_path / "b", clock=Clock())
    said2 = []
    env2.browser = browser_for(env2.stub)
    s3 = A.login(env2, say=said2.append)
    assert s3["session_expires_at"] and "estimate" not in said2[-1]


def test_13a_d3_login_refuses_a_nextcloud_account_without_groups(tmp_path):
    """P3-D3 (logs/119-122): the chp-doc Bearer made a NextCloud account with no groups for a person who never signed
    in on the web. The sign-in says what to do (sign in once in the browser), and keeps no session."""
    env = make_env(tmp_path)
    env.stub.nc_groups = []
    with pytest.raises(A.AuthError) as e:
        login(env)
    m = str(e.value)
    assert "no groups" in m and "browser" in m and f"{FILES}/" in m and "doc login" in m
    assert A.load(env) is None
    env.stub.nc_groups = None                            # a NextCloud that does not list groups: not judged here
    assert login(env)["user"] == "alice"
