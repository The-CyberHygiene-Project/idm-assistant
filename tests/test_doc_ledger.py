"""The root appender, server-side publish and the hash-chained document ledger (ISO 0.7.0 Plan 3 Task 4): the spike's
proof table (lab/docs-spike/SPIKE-NEXTCLOUD.md §Ledger) and the M2 hardening list as unit tests. NextCloud (the store),
Kanidm (userinfo) and the marking checker (Task 5) are fakes here; the real ones are proved on the lab (Task 11)."""
import base64
import hashlib
import http.server
import json
import os
import re
import ssl
import threading
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_site import doc_ledger as L
from chp_site.sitefile import SiteError

TOP = Path(__file__).resolve().parents[1]
UNITS = TOP / "appliance/rpm/chp-documents/units"
NOW = 1795000000.0                       # 2026-11-18T...Z


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ---------- fakes ----------

class FakeStore:
    """NextCloud as the appender sees it: nodes by file id; CUI-area writes are tagged by folder like chp_foldertag."""
    def __init__(self):
        self.nodes = {}
        self.next_id = 5000
        self.tagging = True
        self.read_hook = None
        self.move_error = None
        self.calls = []
        for fid, parent, name in ((10, 0, "CUI"), (100, 10, "Compliance"), (99, 10, "Work"), (30, 0, "Archive"),
                                  (300, 30, "Superseded"), (20, 0, "Internal"), (200, 20, "Compliance"),
                                  (210, 200, "Superseded")):
            self.nodes[fid] = {"type": "folder", "parent": parent, "name": name, "data": None, "tags": set(), "etag": "e"}

    def add(self, parent, name, data, fid=None):
        fid = fid or self._id()
        self.nodes[fid] = {"type": "file", "parent": parent, "name": name, "data": data, "etag": f"e{fid}",
                           "tags": self._tags_for(parent)}
        return fid

    def _id(self):
        self.next_id += 1
        return self.next_id

    def _chain(self, fid):
        out, cur = [], self.nodes[fid]["parent"]
        while cur:
            out.append(cur)
            cur = self.nodes[cur]["parent"]
        return tuple(out)

    def _tags_for(self, parent):
        chain = self._chain(parent) if parent else ()
        top = chain[-1] if chain else parent
        return {"CUI"} if self.tagging and top in (10, 30) else set()

    def _path(self, fid):
        names = [self.nodes[fid]["name"]] + [self.nodes[a]["name"] for a in self._chain(fid)]
        return "/".join(reversed(names))

    def info(self, fid):
        n = self.nodes.get(fid)
        if n is None:
            return None
        return L.Node(fid, n["type"], n["name"], self._path(fid), self._chain(fid), n["etag"])

    def children(self, folder):
        return [self.info(i) for i, n in sorted(self.nodes.items()) if n["parent"] == folder]

    def read(self, fid):
        self.calls.append(("read", fid))
        if self.read_hook:
            self.read_hook(self, fid)
        return self.nodes[fid]["data"]

    def put(self, folder, name, data):
        self.calls.append(("put", folder, name))
        if any(n["parent"] == folder and n["name"] == name for n in self.nodes.values()):
            raise L.StoreError(f"{name} exists")
        return self.info(self.add(folder, name, data))

    def move(self, fid, folder):
        self.calls.append(("move", fid, folder))
        if self.move_error:
            raise self.move_error
        n = self.nodes[fid]
        n["parent"] = folder
        n["tags"] |= self._tags_for(folder)
        n["etag"] += "m"
        return self.info(fid)

    def delete(self, fid):
        self.calls.append(("delete", fid))
        del self.nodes[fid]

    def tags(self, fid):
        return set(self.nodes[fid]["tags"])

    def names(self, folder):
        return sorted(n["name"] for n in self.nodes.values() if n["parent"] == folder)


NAME = re.compile(r"(?P<prefix>(?:CUI_|FCI_)?)(?P<title>.+?)_v(?P<version>\d+\.\d+)(?P<draft>-DRAFT)?(?:\.\w+)?")


class FakeMarking:
    """marking (Task 5) as the appender calls it: parse_name(name) and check(path, cui, values) -> Report."""
    def __init__(self):
        self.checked = []

    @staticmethod
    def parse_name(name):
        m = NAME.fullmatch(name)
        if not m:
            raise ValueError(f"{name}: not <prefix><title>_vX.Y")
        return SimpleNamespace(prefix=m["prefix"], title=m["title"], version=m["version"], draft=bool(m["draft"]))

    def check(self, path, cui, values):
        data = Path(path).read_bytes()
        self.checked.append((Path(path).name, cui, data, values))
        problems = []
        name = Path(path).name
        if cui and not name.startswith(("CUI_", "FCI_")):
            problems.append(f"name rule: {name} needs the CUI_ or FCI_ prefix in the CUI area")
        if cui and b"CUI//BANNER" not in data:
            problems.append("banner missing on the first or last page")
        return SimpleNamespace(ok=not problems, problems=problems, name=None)


def userinfo_for(state):
    def ui(url, token):
        state["calls"].append((url, token))
        if state.get("down"):
            raise L.KanidmUnavailable("connection refused")
        if state.get("expired") or not token.startswith("tok-"):
            raise L.TokenRejected("HTTP 401")
        who = token[4:]
        return {"preferred_username": state.get("as", who), "sub": f"sub-{who}", "sid": f"sid-{who}", "aud": "chp-doc"}
    return ui


class Env:
    def __init__(self, tmp, isso="dana", approvers=("bob", "carol")):
        self.base = tmp / "chp-docs"
        for d in ("spool", "out"):
            (self.base / d).mkdir(parents=True)
        self.store = FakeStore()
        self.marking = FakeMarking()
        self.kanidm = {"calls": []}
        self.journal = []
        self.now = [NOW]
        self.site = {"DOC_ISSO_ACCOUNT": isso, "DOC_APPROVER_ACCOUNTS": list(approvers)}
        self.conf = {"CUI_COMPLIANCE_ID": "100", "INTERNAL_COMPLIANCE_ID": "200", "CUI_SUPERSEDED_ID": "300",
                     "INTERNAL_SUPERSEDED_ID": "210", "DOC_OIDC_CLIENT": "chp-doc",
                     "KANIDM_USERINFO_URL": "https://idm.example.test/oauth2/openid/chp-doc/userinfo"}
        self.ctx = L.Ctx(base=self.base, site=self.site, conf=self.conf, store=self.store,
                         userinfo=userinfo_for(self.kanidm), marking=self.marking, mark_values=lambda: "VALUES",
                         journal=self.journal.append, now=lambda: self.now[0], chown=lambda p: None)
        self.n = 0
        self.v10 = b"CUI//BANNER SSP version 1.0 CUI//BANNER"
        self.doc = self.store.add(100, "CUI_SSP_v1.0.docx", self.v10)
        self.store.add(100, "CUI_SSP_v1.0.pdf", b"%PDF CUI//BANNER 1.0")
        self.idoc = self.store.add(200, "Policy_v1.0.md", b"policy 1.0")

    def spool(self, body, rid=None):
        self.n += 1
        rid = rid or f"{self.n:032x}"
        p = self.base / "spool" / f"{rid}.json"
        p.write_bytes(body if isinstance(body, bytes) else json.dumps(body).encode())
        return p

    def req(self, kind, user, fid, *, name=None, sha256="", auth="bearer", token=None, content=None, pdf=None,
            reason="", notes="", rid=None, extra=None):
        target = "folder" if name is not None else "file"
        body = {"request_id": None, "kind": kind, "file_id": fid, "target": target, "name": name,
                "path": f"/{user}/files/x", "area_id": 100, "sha256": sha256, "reason": reason, "notes": notes,
                "content": base64.b64encode(content).decode() if content is not None else None,
                "pdf_content": base64.b64encode(pdf).decode() if pdf is not None else None,
                "user": user, "auth": auth, "auth_header": "bearer" if auth == "bearer" else "none",
                "nc_app_token": auth == "app-password",
                "bearer_token": (token or f"tok-{user}") if auth == "bearer" else None,
                "received_at": "2026-11-18T10:00:00Z", "remote_addr": "10.0.0.5"}
        body.update(extra or {})
        self.n += 1
        rid = rid or f"{self.n:032x}"
        body["request_id"] = rid
        p = self.base / "spool" / f"{rid}.json"
        p.write_text(json.dumps(body))
        return L.process_one(p, self.ctx)

    def out(self, rid):
        return json.loads((self.base / "out" / f"{rid}.json").read_text())

    def ledger(self):
        f = self.base / "ledger" / "ledger.jsonl"
        return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []

    def quarantine(self):
        q = self.base / "quarantine"
        return sorted(q.iterdir()) if q.exists() else []

    # the happy path pieces
    def checkout(self, user, fid=None, **kw):
        return self.req("checkout", user, fid or self.doc, **kw)

    def approve(self, user, data, name="CUI_SSP_v1.1.docx", folder=100, **kw):
        return self.req("approve", user, folder, name=name, sha256=sha(data), **kw)

    def publish(self, user, data, name="CUI_SSP_v1.1.docx", folder=100, pdf=b"%PDF CUI//BANNER 1.1", **kw):
        return self.req("publish", user, folder, name=name, sha256=sha(data), content=data, pdf=pdf, **kw)


V11 = b"CUI//BANNER SSP version 1.1 CUI//BANNER"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def ok(r):
    assert r.state == "done", r.message
    return r.entry


def refused(r, *words):
    assert r.state == "refused", r
    for w in words:
        assert w.lower() in r.message.lower(), r.message
    return r.message


# ---------- author and approval rules ----------

def test_author_cannot_approve(tmp_path):
    e = Env(tmp_path, approvers=("alice", "bob"))
    ok(e.checkout("alice"))
    m = refused(e.approve("alice", V11), "author")
    assert "alice" in m
    assert [x["kind"] for x in e.ledger()] == ["checkout"]


def test_reader_checkout_makes_author(env):
    ok(env.checkout("alice"))
    ok(env.checkout("bob"))                     # bob checks it out only to read it
    m = refused(env.approve("bob", V11), "checked it out", "author")
    assert "bob" in m and "approver must be someone else" in m
    ok(env.approve("carol", V11))               # someone who never checked it out may


def test_approval_must_follow_last_checkout(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    ok(env.checkout("alice"))                   # a later checkout voids the earlier approval
    refused(env.publish("alice", V11), "no valid approval", "after the cycle's last checkout")
    ok(env.approve("bob", V11))
    ok(env.publish("alice", V11))


def test_approval_is_for_exact_sha256(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    other = V11 + b" one more line"
    refused(env.publish("alice", other), "no valid approval", "sha256")
    # the content must be the file the request names
    r = env.req("publish", "alice", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), content=other, pdf=b"%PDF CUI//BANNER")
    refused(r, "sha256")
    assert [x["kind"] for x in env.ledger()] == ["checkout", "approve"]


def test_publisher_must_be_author(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    refused(env.publish("carol", V11), "not an author", "alice")
    assert env.store.names(100) == ["CUI_SSP_v1.0.docx", "CUI_SSP_v1.0.pdf"]


def test_override_only_one_person_site(tmp_path):
    e = Env(tmp_path / "a", isso="dana", approvers=("bob",))
    ok(e.checkout("dana"))
    refused(e.req("override", "dana", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="no one else"),
            "not a one-person site", "bob")
    solo = Env(tmp_path / "b", isso="dana", approvers=())
    ok(solo.checkout("dana"))
    o = ok(solo.req("override", "dana", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="one-person site"))
    assert o["kind"] == "override" and o["reason"] == "one-person site" and o["kanidm_sub"] == "sub-dana"
    assert any(j.get("event") == "ledger" and j.get("kind") == "override" for j in solo.journal)
    ok(solo.publish("dana", V11))


def test_override_needs_reason(tmp_path):
    e = Env(tmp_path, isso="dana", approvers=())
    ok(e.checkout("dana"))
    refused(e.req("override", "dana", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="   "), "reason")


def test_non_isso_override_refused(tmp_path):
    e = Env(tmp_path, isso="dana", approvers=())
    ok(e.checkout("alice"))
    refused(e.req("override", "alice", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="x"), "only the isso")


def test_approve_refused_when_no_approvers_configured(tmp_path):
    e = Env(tmp_path, isso="", approvers=())
    ok(e.checkout("alice"))
    refused(e.approve("bob", V11), "DOC_ISSO_ACCOUNT", "DOC_APPROVER_ACCOUNTS")
    refused(e.req("override", "bob", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="x"), "DOC_ISSO_ACCOUNT")
    # read at approve time, not at enable: an account removed from site.conf no longer approves
    e2 = Env(tmp_path / "b", approvers=("bob",))
    ok(e2.checkout("alice"))
    e2.site["DOC_APPROVER_ACCOUNTS"] = ["carol"]
    refused(e2.approve("bob", V11), "not an approver")


# ---------- Bearer checks ----------

def test_approve_needs_verified_bearer(env):
    ok(env.checkout("alice"))
    refused(env.approve("bob", V11, auth="session"), "kanidm", "bearer")
    env.kanidm["as"] = "mallory"                # a cookie session carrying someone else's Bearer
    m = refused(env.approve("bob", V11), "belongs to")
    assert "mallory" in m and "bob" in m
    env.kanidm.pop("as")
    env.conf["DOC_OIDC_CLIENT"] = "chp-doc"
    e = ok(env.approve("bob", V11))
    assert e["auth"] == "bearer" and e["kanidm_sub"] == "sub-bob" and e["session_id"] == "sid-bob"
    assert env.kanidm["calls"][-1] == (env.conf["KANIDM_USERINFO_URL"], "tok-bob")
    assert [x["kind"] for x in env.ledger()] == ["checkout", "approve"]


def test_bearer_for_another_client_refused(env):
    ok(env.checkout("alice"))
    base = env.ctx.userinfo
    env.ctx.userinfo = lambda u, t: {**base(u, t), "aud": "nextcloud", "azp": "nextcloud"}
    refused(env.approve("bob", V11), "chp-doc")


def test_app_password_refused_for_approve(env):
    ok(env.checkout("alice"))
    refused(env.approve("bob", V11, auth="app-password"), "app password")
    refused(env.req("override", "dana", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="x",
                    auth="app-password"), "app password")
    assert not env.quarantine()


def test_kanidm_outage_retries(env):
    ok(env.checkout("alice"))
    env.kanidm["down"] = True
    rid = "ab" * 16
    r = env.approve("bob", V11, rid=rid)
    assert r.state == "retry" and "run" in r.message and "again" in r.message
    assert env.out(rid) == {"request_id": rid, "user": "bob", "state": "retry", "message": r.message}
    assert not list((env.base / "spool").iterdir()) and not env.quarantine()
    assert [x["kind"] for x in env.ledger()] == ["checkout"]
    env.kanidm["down"] = False                  # the client re-sends, same request id, fresh token
    e = ok(env.approve("bob", V11, rid=rid))
    assert env.out(rid)["state"] == "done" and env.out(rid)["entry"]["seq"] == e["seq"]


def test_expired_token_mid_request(env):
    ok(env.checkout("alice"))
    env.kanidm["expired"] = True                # the 15-minute token ran out between approve and userinfo
    rid = "cd" * 16
    r = env.approve("bob", V11, rid=rid)
    assert r.state == "retry" and "pending" in r.message.lower() and "sign" in r.message.lower()
    assert not env.quarantine() and len(env.ledger()) == 1
    env.kanidm["expired"] = False
    ok(env.approve("bob", V11, rid=rid))


def test_userinfo_pinned_to_site_ca_no_redirects(monkeypatch):
    seen = {}

    def ctx_factory(*a, **kw):
        seen.update(kw)
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(L.ssl, "create_default_context", ctx_factory)
    op = L._opener(L.SITE_CA)
    assert seen == {"cafile": L.SITE_CA}        # the site CA only: no system store, no other file
    assert any(isinstance(h, L._NoRedirect) for h in op.handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in op.handlers)
    https = [h for h in op.handlers if isinstance(h, urllib.request.HTTPSHandler)]
    assert https and https[0]._context.verify_mode == ssl.CERT_REQUIRED and https[0]._context.check_hostname
    # https only, host from documents.conf
    with pytest.raises(L.KanidmRefused, match="https"):
        L.kanidm_userinfo("http://idm.example.test/oauth2/openid/chp-doc/userinfo", "t")
    # a redirect is never followed (the target is never asked) and is a refusal, not an outage
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/ui":
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/ui"
        with pytest.raises(L.KanidmRefused, match="redirect"):
            L._userinfo_call(url, "tok", L._opener(L.SITE_CA), 5)
        assert hits == ["/ui"]
    finally:
        srv.shutdown()


# ---------- publish ----------

def test_publish_happy_path_entry_shape(env):
    co = ok(env.checkout("alice"))
    assert co["sha256"] == sha(env.v10) and co["file_id"] == env.doc and co["cycle"] == 1
    assert co["path"] == "CUI/Compliance/CUI_SSP_v1.0.docx"
    ok(env.approve("bob", V11, notes="read it"))
    p = ok(env.publish("alice", V11))
    assert p["kind"] == "publish" and p["sha256"] == sha(V11) and p["cycle"] == 1 and p["supersedes"] == env.doc
    assert p["path"] == "CUI/Compliance/CUI_SSP_v1.1.docx"
    assert env.store.read(p["file_id"]) == V11
    led = env.ledger()
    assert [x["seq"] for x in led] == [1, 2, 3] and all(x["doc"] == led[0]["doc"] for x in led)
    # the next cycle starts after the publish: a checkout of the new version is cycle 2
    assert ok(env.checkout("bob", p["file_id"]))["cycle"] == 2


def test_publish_race_refused(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    reads = []

    def edit_after_check(store, fid):          # a second publish / an admin edit lands after the freshness check
        if fid == env.doc:
            reads.append(fid)
            if len(reads) == 2:
                store.nodes[fid]["data"] = b"CUI//BANNER admin edit"
                store.nodes[fid]["etag"] = "changed"
    env.store.read_hook = edit_after_check
    refused(env.publish("alice", V11), "changed")
    assert not [c for c in env.store.calls if c[0] in ("put", "move")]
    assert env.store.names(100) == ["CUI_SSP_v1.0.docx", "CUI_SSP_v1.0.pdf"]
    assert [x["kind"] for x in env.ledger()] == ["checkout", "approve"]


def test_publish_stale_checkout_refused(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    env.store.nodes[env.doc]["data"] = b"CUI//BANNER changed on the server"
    refused(env.publish("alice", V11), "changed since", "checkout")
    assert not [c for c in env.store.calls if c[0] == "put"]


def test_publish_unapproved_hash_refused(env):
    ok(env.checkout("alice"))
    refused(env.publish("alice", V11), "no valid approval")


def test_publish_draft_refused(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11, name="CUI_SSP_v1.1-DRAFT.docx"))
    refused(env.publish("alice", V11, name="CUI_SSP_v1.1-DRAFT.docx"), "-DRAFT")
    assert not [c for c in env.store.calls if c[0] == "put"]


def test_publish_name_rule_refused(env):
    ok(env.req("new", "alice", 100, name="SSP2_v0.1-DRAFT.docx"))
    data = b"CUI//BANNER new doc CUI//BANNER"
    ok(env.approve("bob", data, name="SSP2_v0.1.docx"))
    refused(env.publish("alice", data, name="SSP2_v0.1.docx"), "name rule")
    assert not [c for c in env.store.calls if c[0] == "put"]
    # a name the parser cannot read is a plain refusal, never a stack trace
    refused(env.req("new", "alice", 100, name="no version here.docx"), "name")


def test_publish_marks_rechecked_on_server(env):
    ok(env.checkout("alice"))
    unmarked = b"SSP version 1.1 with the banner removed"
    ok(env.approve("bob", unmarked))
    refused(env.publish("alice", unmarked), "banner")
    name, cui, data, values = env.marking.checked[0]
    assert name == "CUI_SSP_v1.1.docx" and cui is True and data == unmarked and values == "VALUES"
    assert not [c for c in env.store.calls if c[0] == "put"]
    assert not list((env.base / "work").iterdir())              # the CUI bytes never stay on the disk


def test_publish_supersedes_to_archive(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    ok(env.publish("alice", V11))
    assert env.store.names(100) == ["CUI_SSP_v1.1.docx", "CUI_SSP_v1.1.pdf"]
    assert env.store.names(300) == ["CUI_SSP_v1.0.docx", "CUI_SSP_v1.0.pdf"]      # CUI: Archive/Superseded
    assert env.store.nodes[env.doc]["parent"] == 300
    # non-CUI: Internal/Compliance/Superseded, no banner needed
    ok(env.checkout("alice", env.idoc))
    p11 = b"policy 1.1"
    ok(env.approve("bob", p11, name="Policy_v1.1.md", folder=200))
    e = ok(env.publish("alice", p11, name="Policy_v1.1.md", folder=200, pdf=b"%PDF policy"))
    assert env.store.names(210) == ["Policy_v1.0.md"] and "Policy_v1.1.md" in env.store.names(200)
    assert env.marking.checked[-1][1] is False and e["supersedes"] == env.idoc


def test_publish_move_degraded_is_reported_and_undone(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    env.store.move_error = L.Degraded("SQLSTATE: function md5 is not available")
    m = refused(env.publish("alice", V11), "DEGRADED", "Superseded")
    assert "md5" in m.lower()
    assert env.store.names(100) == ["CUI_SSP_v1.0.docx", "CUI_SSP_v1.0.pdf"]  # the new file was removed again
    assert [x["kind"] for x in env.ledger()] == ["checkout", "approve"]


def test_publish_sets_tag_and_confirms(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    env.store.tagging = False                   # chp_foldertag did not tag the new file
    refused(env.publish("alice", V11), "tag")
    assert env.store.names(100) == ["CUI_SSP_v1.0.docx", "CUI_SSP_v1.0.pdf"]   # undone: old back, new gone
    assert env.store.names(300) == []
    env.store.tagging = True
    p = ok(env.publish("alice", V11))
    assert "CUI" in env.store.tags(p["file_id"])


def test_publish_writes_reader_pdf_and_hash(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    refused(env.publish("alice", V11, pdf=b"%PDF without marks"), "pdf", "banner")
    assert env.store.names(100) == ["CUI_SSP_v1.0.docx", "CUI_SSP_v1.0.pdf"]
    pdf = b"%PDF CUI//BANNER 1.1 reader copy"
    p = ok(env.publish("alice", V11, pdf=pdf))
    assert p["pdf_sha256"] == sha(pdf)
    pid = next(i for i, n in env.store.nodes.items() if n["name"] == "CUI_SSP_v1.1.pdf")
    assert env.store.nodes[pid]["parent"] == 100 and env.store.read(pid) == pdf


def test_publish_never_overwrites_in_place(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11, name="CUI_SSP_v1.0.docx"))
    refused(env.publish("alice", V11, name="CUI_SSP_v1.0.docx"), "new version")


def test_cr_numbering(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    p1 = ok(env.publish("alice", V11))
    assert p1["cr"] == "CR-2026-0001"
    v12 = b"CUI//BANNER 1.2"
    ok(env.checkout("alice", p1["file_id"]))
    ok(env.approve("bob", v12, name="CUI_SSP_v1.2.docx"))
    assert ok(env.publish("alice", v12, name="CUI_SSP_v1.2.docx"))["cr"] == "CR-2026-0002"
    env.now[0] = 1800000000.0                   # 2027
    ok(env.checkout("alice", env.store.info(next(i for i, n in env.store.nodes.items()
                                                 if n["name"] == "CUI_SSP_v1.2.docx")).file_id))
    v13 = b"CUI//BANNER 1.3"
    ok(env.approve("bob", v13, name="CUI_SSP_v1.3.docx"))
    assert ok(env.publish("alice", v13, name="CUI_SSP_v1.3.docx"))["cr"] == "CR-2027-0001"
    assert all("cr" not in x for x in env.ledger() if x["kind"] != "publish")


def test_new_document_cycle(env):
    e = ok(env.req("new", "alice", 100, name="CUI_Plan_v0.1-DRAFT.docx"))
    assert e["file_id"] is None and e["path"] == "CUI/Compliance/CUI_Plan_v0.1-DRAFT.docx" and e["sha256"] == ""
    refused(env.req("new", "carol", 100, name="CUI_Plan_v0.1-DRAFT.docx"), "already")
    refused(env.req("new", "carol", 100, name="CUI_SSP_v0.1-DRAFT.docx"), "already", "checkout")
    data = b"CUI//BANNER plan"
    ok(env.approve("bob", data, name="CUI_Plan_v0.1.docx"))
    p = ok(env.publish("alice", data, name="CUI_Plan_v0.1.docx"))
    assert "supersedes" not in p and p["cr"] == "CR-2026-0001"


def test_area_rechecked_by_the_appender(env):
    w = env.store.add(99, "CUI_Notes_v1.0.docx", b"x")                 # CUI/Work: not a Compliance area
    refused(env.checkout("alice", w), "controlled document")
    old = env.store.add(300, "CUI_Old_v1.0.docx", b"x")                # Archive/Superseded
    refused(env.checkout("alice", old), "controlled document")
    sup = env.store.add(210, "Old_v1.0.md", b"x")                      # Internal/Compliance/Superseded
    refused(env.checkout("alice", sup), "controlled document")
    refused(env.req("new", "alice", 210, name="X_v0.1-DRAFT.md"), "controlled document")
    refused(env.checkout("alice", 424242), "controlled document")
    assert env.ledger() == []


# ---------- spool and quarantine ----------

def test_quarantine_record_has_no_bearer(env):
    rid = "ef" * 16
    p = env.spool({"request_id": rid, "kind": "delete-everything", "user": "alice", "auth": "bearer",
                   "bearer_token": "SECRET-TOKEN", "content": base64.b64encode(b"CUI//SECRET BYTES").decode(),
                   "file_id": 1, "target": "file"}, rid=rid)
    r = L.process_one(p, env.ctx)
    assert r.state == "refused"
    [q] = env.quarantine()
    raw = q.read_text()
    assert "SECRET-TOKEN" not in raw and "bearer_token" not in raw
    assert base64.b64encode(b"CUI//SECRET BYTES").decode() not in raw
    rec = json.loads(raw)
    assert rec["request"]["content"] == {"bytes": 17, "sha256": sha(b"CUI//SECRET BYTES")}
    assert oct(q.stat().st_mode & 0o777) == "0o600" and oct(q.parent.stat().st_mode & 0o777) == "0o700"
    assert not p.exists() and env.out(rid)["state"] == "refused" and env.out(rid)["user"] == "alice"
    assert any(j.get("event") == "quarantine" for j in env.journal)
    assert "SECRET-TOKEN" not in json.dumps(env.journal)


def test_unparsable_recorded_by_size_and_sha(env):
    raw = b'{"request_id": "x", "bearer_token": "SECRET-TOKEN", broken'
    p = env.spool(raw)
    L.process_one(p, env.ctx)
    [q] = env.quarantine()
    rec = json.loads(q.read_text())
    assert rec["request"] == {"unparsed": True, "bytes": len(raw), "sha256": sha(raw)}
    assert "SECRET" not in q.read_text() and not p.exists()


def test_non_dict_json_quarantined(env):
    for body in (b"[1, 2, 3]", b'"just a string"', b"null"):
        p = env.spool(body)
        r = L.process_one(p, env.ctx)
        assert r.state == "refused" and not p.exists()
    assert len(env.quarantine()) == 3


def test_quarantine_names_never_collide(env):
    rid = "aa" * 16
    for _ in range(3):                          # the same id, the same second
        L.process_one(env.spool(b"[]", rid=rid), env.ctx)
    qs = env.quarantine()
    assert len(qs) == 3 and len({q.name for q in qs}) == 3


def test_spool_always_deleted(env):
    env.spool(b"garbage")
    env.spool({"request_id": "bad"})
    ok_rid = "01" * 16
    env.spool({"request_id": ok_rid, "kind": "checkout", "file_id": env.doc, "target": "file", "name": None,
               "sha256": "", "reason": "", "notes": "", "content": None, "pdf_content": None, "user": "alice",
               "auth": "bearer", "bearer_token": "tok-alice", "received_at": "x"}, rid=ok_rid)
    boom_rid = "02" * 16
    env.spool({"request_id": boom_rid, "kind": "checkout", "file_id": env.idoc, "target": "file", "name": None,
               "sha256": "", "reason": "", "notes": "", "content": None, "pdf_content": None, "user": "alice",
               "auth": "bearer", "bearer_token": "tok-alice", "received_at": "x"}, rid=boom_rid)
    real = env.store.read

    def boom(fid):
        if fid == env.idoc:
            raise RuntimeError("unexpected")
        return real(fid)
    env.store.read = boom
    (env.base / "spool" / ".0123.tmp").write_text("in progress")      # the app's half-written file is not ours
    rs = L.process(env.ctx)
    assert len(rs) == 4
    assert [p.name for p in (env.base / "spool").iterdir()] == [".0123.tmp"]
    assert env.out(ok_rid)["state"] == "done" and env.out(boom_rid)["state"] == "refused"


def test_only_request_names_processed(env):
    for name in ("AB" * 16 + ".json", "ab" * 16 + ".json\n", "ab" * 15 + ".json", "x.json"):
        p = env.base / "spool" / name
        p.write_text("{}")
        r = L.process_one(p, env.ctx)
        assert r.state == "refused" and p.exists()           # never read, never deleted, never quarantined
    assert not env.quarantine()


def test_spool_symlink_never_followed(env, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text('{"x": 1}')
    p = env.base / "spool" / ("bc" * 16 + ".json")
    p.symlink_to(secret)
    L.process_one(p, env.ctx)
    assert secret.exists() and not os.path.lexists(p)
    assert '"x"' not in env.quarantine()[0].read_text()


def test_unlink_failure_does_not_crash(env, monkeypatch):
    def nope(p):
        raise PermissionError("immutable")
    monkeypatch.setattr(L, "_unlink_raw", nope)
    rid = "03" * 16
    r = env.checkout("alice", rid=rid)
    assert r.state == "done" and env.out(rid)["state"] == "done"
    assert any(j.get("event") == "spool-unlink-failed" for j in env.journal)
    L.process(env.ctx)                          # still there: processed again, idempotent, no crash
    assert len(env.ledger()) == 1


def test_never_refused_after_append(env, monkeypatch):
    ok(env.checkout("alice"))
    rid = "04" * 16
    real = L._write_result
    calls = []

    def flaky(ctx, rid_, user, state, message, entry=None):
        calls.append(state)
        if len(calls) == 1:
            raise OSError("out/ is full")
        return real(ctx, rid_, user, state, message, entry)
    monkeypatch.setattr(L, "_write_result", flaky)
    r = env.approve("bob", V11, rid=rid)
    assert r.state == "done"                    # appended; the result could not be written: still not "refused"
    assert not (env.base / "out" / f"{rid}.json").exists() and not env.quarantine()
    env.kanidm["expired"] = True                # the re-send comes later, its token now expired
    r2 = env.approve("bob", V11, rid=rid)
    assert r2.state == "done" and r2.entry["seq"] == r.entry["seq"]
    assert env.out(rid)["state"] == "done" and len(env.ledger()) == 2
    # the same request id from someone else never reads or overwrites the owner's result
    r3 = env.approve("carol", V11, rid=rid)
    assert r3.state == "refused" and env.out(rid)["user"] == "bob" and len(env.ledger()) == 2


def test_results_carry_owner_and_mode(env):
    rid = "05" * 16
    env.checkout("alice", rid=rid)
    res = env.base / "out" / f"{rid}.json"
    assert env.out(rid)["user"] == "alice" and oct(res.stat().st_mode & 0o777) == "0o640"
    assert "bearer" not in res.read_text().lower() or "tok-" not in res.read_text()


def test_purge_quarantine_requires_root(env, monkeypatch):
    L.process_one(env.spool(b"[]"), env.ctx)
    monkeypatch.setattr(L.os, "geteuid", lambda: 1000)
    with pytest.raises(SiteError, match="root"):
        L.purge_quarantine(env.ctx)
    assert len(env.quarantine()) == 1
    monkeypatch.setattr(L.os, "geteuid", lambda: 0)
    assert L.purge_quarantine(env.ctx) == 1 and env.quarantine() == []
    assert any(j.get("event") == "quarantine-purged" for j in env.journal)


# ---------- journal (ruling F4) ----------

def test_journal_line_per_entry_without_secrets(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    ok(env.publish("alice", V11))
    led = [j for j in env.journal if j.get("event") == "ledger"]
    assert [j["kind"] for j in led] == ["checkout", "approve", "publish"]
    assert {k: v for k, v in led[2].items() if k != "event"} == env.ledger()[2]
    text = json.dumps(env.journal)
    assert "tok-" not in text and base64.b64encode(V11).decode() not in text


def test_journal_default_uses_the_ledger_identifier(monkeypatch):
    got = []
    monkeypatch.setattr(L.subprocess, "run", lambda argv, **kw: got.append(argv))
    L.journal({"event": "ledger", "kind": "approve"})
    argv = got[0]
    assert argv[0] == "logger" and argv[argv.index("-t") + 1] == "chp-docs-ledger"     # SYSLOG_IDENTIFIER
    assert int(argv[argv.index("--size") + 1]) >= 8192      # logger's 1 KiB default would cut a long entry
    assert argv[-2] == "--" and json.loads(argv[-1]) == {"event": "ledger", "kind": "approve"}


# ---------- ledger integrity ----------

def _three(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))
    ok(env.publish("alice", V11))
    return env.base / "ledger" / "ledger.jsonl", env.base / "ledger" / "ledger.head"


def test_chain_and_head_verify(env):
    led, head = _three(env)
    out = []
    assert L.verify(led, head, None, say=out.append) == 0 and "3 entries" in out[-1]
    assert oct(led.stat().st_mode & 0o777) == "0o600" and oct(led.parent.stat().st_mode & 0o777) == "0o700"
    assert head.read_text().split()[0] == "3"
    lines = led.read_text().splitlines()
    lines[1] = lines[1].replace('"bob"', '"eve"')     # an approver's name changed in place
    led.write_text("\n".join(lines) + "\n")
    out = []
    assert L.verify(led, head, None, say=out.append) == 1 and any("entry 3" in x for x in out)


def test_truncation_caught_by_head(env):
    led, head = _three(env)
    led.write_text("\n".join(led.read_text().splitlines()[:2]) + "\n")
    out = []
    assert L.verify(led, head, None, say=out.append) == 1 and any("shorter than its recorded head" in x for x in out)
    led.unlink()                                # deleted outright: still caught
    assert L.verify(led, head, None, say=out.append) == 1


def test_broken_ledger_refuses_new_entries(env):
    led, head = _three(env)
    led.write_text(led.read_text().replace('"bob"', '"eve"'))
    r = env.checkout("carol")
    refused(r, "ledger")
    assert any(j.get("event") == "ledger-broken" for j in env.journal)


def test_export_to_stick_and_verify_heads(env, tmp_path):
    led, head = _three(env)
    stick = tmp_path / "stick"
    res = L.export(stick, env.ctx)
    d = stick / "docs-ledger"
    assert (d / "ledger.jsonl").read_bytes() == led.read_bytes()
    assert (d / "verify.txt").read_text().startswith("OK")
    heads = (d / "heads.txt").read_text()
    assert heads.split()[0] == "3" and res["head"][0] == 3
    assert L.verify(led, head, heads, say=lambda s: None) == 0
    # root on the server rewrites the ledger AND its head witness consistently: only the stick's heads catch it
    lines = led.read_text().splitlines()
    first = json.loads(lines[0])
    first["user"] = "eve"
    new = [json.dumps(first, sort_keys=True, separators=(",", ":"))]
    for ln in lines[1:]:
        x = json.loads(ln)
        x["prev"] = L.entry_hash(new[-1])
        new.append(json.dumps(x, sort_keys=True, separators=(",", ":")))
    led.write_text("\n".join(new) + "\n")
    head.write_text(f"3 {L.entry_hash(new[-1])}\n")
    out = []
    assert L.verify(led, head, None, say=out.append) == 0          # the server alone cannot tell
    assert L.verify(led, head, heads, say=out.append) == 1 and any("rewritten" in x for x in out)
    bad = []
    assert L.verify(led, head, "nonsense\n", say=bad.append) == 1


# ---------- units and cli ----------

def test_units_oneshot_finite_limits_onfailure_on_both():
    path = (UNITS / "chp-docs-ledger.path").read_text()
    svc = (UNITS / "chp-docs-ledger.service").read_text()
    alert = (UNITS / "chp-docs-ledger-alert.service").read_text()
    assert "OnFailure=chp-docs-ledger-alert.service" in path and "OnFailure=chp-docs-ledger-alert.service" in svc
    assert "PathExistsGlob=/var/lib/chp-docs/spool/*.json" in path and "Unit=chp-docs-ledger.service" in path
    for text, key in ((path, "TriggerLimit"), (svc, "StartLimit")):
        burst = re.search(rf"^{key}BurstSec?=(\d+)$|^{key}Burst=(\d+)$", text, re.M)
        interval = re.search(rf"^{key}IntervalSec=(\d+)$", text, re.M)
        assert burst and interval and int(interval.group(1)) > 0 and int([g for g in burst.groups() if g][0]) > 0
    assert "Type=oneshot" in svc and "ExecStart=/usr/bin/chp-site doc-ledger process" in svc
    assert "StartLimitIntervalSec=0" not in svc + path
    assert "Type=oneshot" in alert and "-t chp-docs-ledger" in alert and "auth.crit" in alert
    assert "OnFailure" not in alert             # the alert never alerts on itself in a loop


def test_spec_ships_units_and_ledger_dirs():
    spec = (TOP / "appliance/rpm/chp-documents/chp-documents.spec").read_text()
    build = (TOP / "appliance/rpm/chp-documents/build-rpm.sh").read_text()
    files = spec.split("%files", 1)[1]
    for u in ("chp-docs-ledger.path", "chp-docs-ledger.service", "chp-docs-ledger-alert.service"):
        assert re.search(rf"^Source\d+:\s+{re.escape(u)}$", spec, re.M), u
        assert f"%{{_unitdir}}/{u}\n" in files
        assert f'"$here"/units/{u}' in build
    assert "%dir %attr(0700,root,root) %{_localstatedir}/lib/chp-docs/ledger\n" in files
    assert "%dir %attr(0700,root,root) %{_localstatedir}/lib/chp-docs/quarantine\n" in files
    assert "%dir %attr(0700,root,root) %{_localstatedir}/lib/chp-docs/work\n" in files
    post = spec.split("%post", 1)[1].split("%preun", 1)[0]
    assert "chp-docs-ledger.path" in post
    assert "semanage fcontext -a -t var_lib_t '%{_localstatedir}/lib/chp-docs/(ledger|quarantine|work)(/.*)?'" in post


def test_cli_doc_ledger_subcommands(env, monkeypatch, tmp_path, capsys):
    from chp_site import cli
    monkeypatch.setattr(L.Ctx, "system", classmethod(lambda cls: env.ctx))
    env.spool(b"[]")
    assert cli.main(["doc-ledger", "process"]) == 0
    _three(env)
    assert cli.main(["doc-ledger", "verify"]) == 0
    assert cli.main(["doc-ledger", "export", "--stick", str(tmp_path / "stick")]) == 0
    assert cli.main(["doc-ledger", "verify", "--stick", str(tmp_path / "stick")]) == 0
    monkeypatch.setattr(L.os, "geteuid", lambda: 1000)
    assert cli.main(["doc-ledger", "purge-quarantine"]) == 2
    assert "root" in capsys.readouterr().err


# ---------- the app side of the retry contract (chp_ledger) ----------

def test_app_accepts_a_resend_after_retry():
    php = (TOP / "appliance/rpm/nextcloud-chp/chp_ledger/lib/Controller/LedgerController.php").read_text()
    acc = php[php.index("function accept("):]
    i = acc.index("$prior = $this->spool->result($id);")
    assert "($prior['state'] ?? null) !== 'retry'" in acc[i:i + 700]
    res = php[php.index("function result("):php.index("function accept(")]
    assert res.index("$this->spool->queued($request_id)") < res.index("$this->spool->result($request_id)")


def test_enable_starts_the_ledger_path_unit():
    from chp_site import documents as D
    assert "chp-docs-ledger.path" in D.UNITS


def test_occ_store_writes_as_the_publish_account_via_stdin(tmp_path):
    rows = {100: {"fileid": 100, "parent": 10, "name": "Compliance", "path": "files/Compliance", "etag": "e1",
                  "mimetype": "httpd/unix-directory", "folder_id": 1, "mount_point": "CUI"},
            5001: {"fileid": 5001, "parent": 100, "name": "CUI_X_v1.0.docx", "path": "files/Compliance/CUI_X_v1.0.docx",
                   "etag": "e2", "mimetype": "application/octet-stream", "folder_id": 1, "mount_point": "CUI"}}

    def sql(q):
        if q.startswith("WITH RECURSIVE"):
            return [{"fileid": 100, "d": 1}, {"fileid": 10, "d": 2}] if "= 5001 " in q else [{"fileid": 10, "d": 1}]
        if "AND name = 'CUI_X_v1.0.docx'" in q:
            return [{"fileid": 5001}]
        if "oc_systemtag" in q:
            return [{"name": "CUI"}]
        m = re.search(r"f\.fileid = (\d+)$", q)
        return [rows[int(m.group(1))]] if m and int(m.group(1)) in rows else []
    calls = []

    def run(argv, input=None, capture_output=None, timeout=None):
        calls.append((argv, input))
        err = b"SQLSTATE[42883]: function md5(unknown) is not available in FIPS mode" if "files:move" in argv else b""
        return SimpleNamespace(returncode=1 if err else 0, stdout=b"", stderr=err)
    (tmp_path / "1/files/Compliance").mkdir(parents=True)
    (tmp_path / "1/files/Compliance/CUI_X_v1.0.docx").write_bytes(b"bytes")
    with pytest.raises(L.StoreError, match="DOC_PUBLISH_USER"):
        L.OccStore({}, run=run, sql=sql, data=tmp_path).put(100, "CUI_X_v1.0.docx", b"x")
    s = L.OccStore({"DOC_PUBLISH_USER": "chp-publisher"}, run=run, sql=sql, data=tmp_path)
    n = s.put(100, "CUI_X_v1.0.docx", b"the bytes")
    assert calls[-1] == (L.OccStore.OCC + ["files:put", "-", "/chp-publisher/files/CUI/Compliance/CUI_X_v1.0.docx"],
                         b"the bytes")
    assert n == L.Node(5001, "file", "CUI_X_v1.0.docx", "CUI/Compliance/CUI_X_v1.0.docx", (100, 10), "e2")
    assert s.read(5001) == b"bytes" and s.tags(5001) == {"CUI"}
    assert s.info(100).type == "folder" and s.info(100).path == "CUI/Compliance"
    with pytest.raises(L.Degraded):
        s.move(5001, 100)


# ---------- the appender's NextCloud account chp-publisher (pre-review ruling 1) ----------

def _dconf(e):
    return dict(ln.split("=", 1) for ln in (e.root / "etc/chp/documents.conf").read_text().splitlines()
                if "=" in ln and not ln.startswith("#"))


def test_publish_account_created_idempotent(tmp_path, capsys):
    from chp_site import documents as D
    from tests import test_chp_site_documents as T
    e = T.Env(tmp_path)
    done = e.enable()
    add = [(c, env) for c, env in zip(e.nc.calls, e.nc.envs) if c[0] == "user:add" and c[-1] == D.PUBLISH_USER]
    assert len(add) == 1
    argv, env = add[0]
    assert D.PUBLISH_USER == "chp-publisher" and "--password-from-env" in argv
    gi = [argv[i + 1] for i, x in enumerate(argv) if x == "--group"]
    assert sorted(gi) == ["chp-users", "cui-users"]               # nothing else: never admin
    pw = env["OC_PASS"]
    assert len(pw) >= 24
    assert not any(pw in " ".join(c) for c in e.nc.calls + e.run.calls)        # random, discarded, never printed
    assert pw not in "\n".join(done) and pw not in capsys.readouterr().out
    assert not (e.root / "etc/chp").joinpath("documents.conf").read_text().count(pw)
    assert _dconf(e)["DOC_PUBLISH_USER"] == "chp-publisher"
    assert ["user:disable", D.PUBLISH_USER] not in e.nc.calls      # enabled: occ acts as it (lab: disabled user?)
    n = len(e.nc.calls)
    e.enable()                                                     # a second run makes no second account
    assert not [c for c in e.nc.calls[n:] if c[0] == "user:add" and c[-1] == D.PUBLISH_USER]
    assert ["group:adduser", "cui-users", D.PUBLISH_USER] in e.nc.calls[n:]   # membership put back if removed
    assert _dconf(e)["DOC_PUBLISH_USER"] == "chp-publisher"


def test_publish_account_rights_limited_to_four_areas(tmp_path):
    from chp_site import documents as D
    from tests import test_chp_site_documents as T
    e = T.Env(tmp_path)
    e.enable()
    fid = {f["name"]: i for i, f in e.nc.folders.items()}
    want = sorted([str(fid[t]), "/" + rel] for _, t, rel in D.AREAS)
    got = []
    for i, f in e.nc.folders.items():
        for r in f["rules"]:
            if "--user" in r:
                assert r[:3] == ["--user", D.PUBLISH_USER, "--"], r
                assert r[4:] == ["+read", "+write", "+create", "+delete", "-share"], r     # never share
                got.append([str(i), r[3]])
    assert sorted(got) == want                                     # exactly the four areas, nothing else
    assert D.PUBLISH_MASK == 31 and D.PUBLISH_PERMS == 15
    assert not any(D.PUBLISH_USER in c for f in e.nc.folders.values() for g in f["groups"] for c in [g])


def test_nightly_check_allows_only_the_publish_account(tmp_path):
    from chp_site import documents as D
    from tests import test_chp_site_documents as T
    db = T.DB()
    comp = db.file("CUI", "files/Compliance", directory=True)
    sup = db.file("Archive", "files/Superseded", directory=True)
    db.c.execute("INSERT INTO oc_group_user VALUES ('cui-users', ?)", (D.PUBLISH_USER,))
    db.c.execute("INSERT INTO oc_group_folders_acl VALUES (300, ?, 'user', ?, 31, 15)", (comp, D.PUBLISH_USER))
    db.c.execute("INSERT INTO oc_group_folders_acl VALUES (301, ?, 'user', ?, 31, 15)", (sup, D.PUBLISH_USER))
    _, res, _ = T.do_check(tmp_path, db=db)
    assert res["alerts"] == [], res["alerts"]
    # the same rights anywhere else, wider rights (share), or the same rule for anyone else: flagged
    for i, (sql, args, key) in enumerate((
            ("INSERT INTO oc_group_folders_acl VALUES (302, ?, 'user', ?, 31, 15)", (db.roots["CUI"], D.PUBLISH_USER),
             "acl-other:%d" % T.IDS["CUI"]),
            ("UPDATE oc_group_folders_acl SET permissions = 31 WHERE acl_id = 300", (), "acl-other:%d" % T.IDS["CUI"]),
            ("INSERT INTO oc_group_folders_acl VALUES (303, ?, 'user', 'mallory', 31, 15)", (sup,),
             "acl-other:%d" % T.IDS["Archive"]),
            ("INSERT INTO oc_group_user VALUES ('cui-users', 'chp-publisher2')", (), "cui-member:chp-publisher2"))):
        db.c.execute("SAVEPOINT s")                # each case alone, on the clean state above
        db.c.execute(sql, args)
        _, res, _ = T.do_check(tmp_path / str(i), db=db)
        assert keys_of(res) == {key}, res["alerts"]
        db.c.execute("ROLLBACK TO s")
        db.c.execute("RELEASE s")


def keys_of(res):
    return {a["key"] for a in res["alerts"]}


# ---------- the ledger in the nightly backup (pre-review ruling 2) ----------

def test_nightly_backup_copies_the_ledger_only(tmp_path, monkeypatch):
    from tests import test_chp_documents_static as S
    docs = tmp_path / "chp-docs"
    for d in ("ledger", "spool", "out", "work", "quarantine"):
        (docs / d).mkdir(parents=True)
    monkeypatch.setenv("CHP_DOCS_LEDGER", str(docs / "ledger"))
    rc, out, calls = S._backup(tmp_path, 10**9, ["20260101T000000Z"])
    assert rc == 0, out
    rs = [ln for ln in calls.splitlines() if ln.startswith("rsync")]
    led = [ln for ln in rs if str(docs / "ledger") in ln]
    assert len(led) == 1 and led[0].split()[-2] == f"{docs}/ledger/" and led[0].split()[-1].endswith("/chp-docs-ledger/")
    for d in ("spool", "out", "work", "quarantine"):
        assert str(docs / d) not in calls                      # never the Bearer tokens, results, work files or quarantine
    script = (TOP / "appliance/rpm/chp-documents/chp-nextcloud-backup").read_text()
    assert "LEDGER=${CHP_DOCS_LEDGER:-/var/lib/chp-docs/ledger}" in script
    assert "/var/lib/chp-docs/spool" not in script and "/var/lib/chp-docs\"" not in script
    # restore never overwrites a live ledger
    assert 'if [ -s "$LEDGER/ledger.jsonl" ]; then log "restore: kept the existing document ledger' in script


def test_occ_store_undo_delete_is_forced_and_skips_the_trash():
    calls = []
    row = {"fileid": 7, "parent": 100, "name": "x.docx", "path": "files/Compliance/x.docx", "etag": "e",
           "mimetype": "text/plain", "folder_id": 1, "mount_point": "CUI"}
    sql = lambda q: [] if q.startswith("WITH RECURSIVE") else [row]
    s = L.OccStore({"DOC_PUBLISH_USER": "chp-publisher"}, sql=sql,
                   run=lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
    s.delete(7)
    assert calls[-1][-4:] == ["files:delete", "--force", "--skip-trash", "/chp-publisher/files/CUI/Compliance/x.docx"]


# ---------- fix round 1 ----------

def test_every_kind_needs_verified_bearer(env):
    """Identity comes only from Kanidm's chp-doc userinfo: a browser session or an app password (Login Flow v2 tokens
    read as app passwords) is refused for every kind, plainly, never quarantined."""
    ok(env.checkout("alice"))                                  # (with a Bearer)
    n = len(env.ledger())
    cases = [("checkout", env.doc, {}), ("new", 100, {"name": "CUI_X_v0.1-DRAFT.docx"}),
             ("approve", 100, {"name": "CUI_SSP_v1.1.docx", "sha256": sha(V11)}),
             ("override", 100, {"name": "CUI_SSP_v1.1.docx", "sha256": sha(V11), "reason": "x"}),
             ("publish", 100, {"name": "CUI_SSP_v1.1.docx", "sha256": sha(V11), "content": V11, "pdf": b"%PDF"})]
    for kind, fid, kw in cases:
        for auth, words in (("session", "browser session"), ("app-password", "app password")):
            m = refused(env.req(kind, "alice", fid, auth=auth, **kw), "Kanidm-verified Bearer", words)
            assert kind in m
    assert len(env.ledger()) == n and not env.quarantine()
    assert not [c for c in env.store.calls if c[0] in ("put", "move")]
    env.kanidm["as"] = "mallory"                               # a Bearer for someone else: refused for checkout too
    refused(env.checkout("alice"), "belongs to")


def _ready_to_publish(env):
    ok(env.checkout("alice"))
    ok(env.approve("bob", V11))


def test_ledger_line_failure_undoes_the_publish(env, monkeypatch):
    _ready_to_publish(env)
    real = L._write_line

    def half(fd, data):                                        # ENOSPC after half the line reached the file
        os.write(fd, data[:len(data) // 2])
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(L, "_write_line", half)
    m = refused(env.publish("alice", V11), "ledger could not be written", "nothing was published")
    assert env.store.names(100) == ["CUI_SSP_v1.0.docx", "CUI_SSP_v1.0.pdf"] and env.store.names(300) == []
    assert not [n for n in env.store.nodes.values() if n["name"].startswith("CUI_SSP_v1.1")]
    led, head = env.base / "ledger" / "ledger.jsonl", env.base / "ledger" / "ledger.head"
    assert L.verify(led, head, None, say=lambda s: None) == 0  # the partial line was cut back off
    assert len(env.ledger()) == 2 and "UNDO INCOMPLETE" not in m
    ev = [j["event"] for j in env.journal]
    assert ev.index("publish-started") < ev.index("publish-undone")
    monkeypatch.setattr(L, "_write_line", real)
    assert ok(env.publish("alice", V11))["cr"] == "CR-2026-0001"


def test_head_failure_after_the_line_is_still_done(env, monkeypatch):
    _ready_to_publish(env)

    def nohead(self, e, line):
        raise OSError(5, "I/O error")
    monkeypatch.setattr(L._Ledger, "_write_head", nohead)
    rid = "0a" * 16
    r = env.publish("alice", V11, rid=rid)
    assert r.state == "done" and env.out(rid)["state"] == "done" and not env.quarantine()
    assert any(j.get("event") == "head-write-failed" for j in env.journal)
    monkeypatch.undo()
    led, head = env.base / "ledger" / "ledger.jsonl", env.base / "ledger" / "ledger.head"
    assert L.verify(led, head, None, say=lambda s: None) == 0  # a lagging head is not a problem
    ok(env.checkout("carol", r.entry["file_id"]))              # the next append rewrites it
    assert head.read_text().split()[0] == "4"


def test_journal_failure_after_append_is_still_done(env):
    _ready_to_publish(env)
    base = env.ctx.journal

    def broken(rec):
        if rec.get("event") == "ledger":
            raise OSError("journald gone")
        base(rec)
    env.ctx.journal = broken
    assert env.publish("alice", V11).state == "done"


def test_publish_started_journalled_before_the_first_write(env):
    _ready_to_publish(env)
    seen = []
    put = env.store.put

    def watch(folder, name, data):
        seen.append([j.get("event") for j in env.journal])
        return put(folder, name, data)
    env.store.put = watch
    ok(env.publish("alice", V11))
    assert "publish-started" in seen[0]
    st = next(j for j in env.journal if j.get("event") == "publish-started")
    assert st["name"] == "CUI_SSP_v1.1.docx" and st["supersedes"] == env.doc and "content" not in st


def test_process_stops_starting_requests_after_its_budget(env):
    for i in range(3):
        env.spool({"request_id": None}, rid=f"{i + 1:032x}")
    ticks = iter([0, 0, 700, 700, 700])
    rs = L.process(env.ctx, budget=600, clock=lambda: next(ticks))
    assert len(rs) == 2 and len(list((env.base / "spool").iterdir())) == 1
    assert any(j.get("event") == "budget-reached" for j in env.journal)
    svc = (UNITS / "chp-docs-ledger.service").read_text()
    m = re.search(r"^TimeoutStartSec=(\d+)min$", svc, re.M)
    assert m and int(m.group(1)) * 60 > L.BUDGET + 8 * L.OCC_TIMEOUT + 60


def test_cr_year_is_the_entry_year(env):
    _ready_to_publish(env)
    calls = []

    def clock():                                               # 2026-12-31T23:59:59Z, then the new year
        calls.append(1)
        return 1798761599.0 if len(calls) == 1 else 1798761600.0
    env.ctx.now = clock
    p = ok(env.publish("alice", V11))
    assert p["ts"].startswith("2026-12-31") and p["cr"] == "CR-2026-0001"


class _Opener:
    def __init__(self, exc=None, body=None):
        self.exc, self.body = exc, body

    def open(self, req, timeout=None):
        if self.exc is not None:
            raise self.exc
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


def test_userinfo_call_maps_real_failures():
    import http.client
    import socket
    url = "https://idm.example.test/oauth2/openid/chp-doc/userinfo"
    cases = [
        (urllib.error.HTTPError(url, 401, "Unauthorized", {}, None), L.TokenRejected),
        (urllib.error.HTTPError(url, 503, "Unavailable", {}, None), L.KanidmUnavailable),
        (urllib.error.URLError(ConnectionRefusedError(111, "refused")), L.KanidmUnavailable),
        (socket.timeout("timed out"), L.KanidmUnavailable),
        (urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed")), L.KanidmRefused),
        (http.client.BadStatusLine("garbage"), L.KanidmUnavailable),
        (http.client.RemoteDisconnected("closed"), L.KanidmUnavailable),
    ]
    for exc, want in cases:
        with pytest.raises(want):
            L._userinfo_call(url, "t", _Opener(exc), 5)
    with pytest.raises(L.KanidmUnavailable):                   # cut off while reading the body
        L._userinfo_call(url, "t", _Opener(body=http.client.IncompleteRead(b"{")), 5)
    with pytest.raises(L.KanidmRefused):
        L._userinfo_call(url, "t", _Opener(body=b"not json"), 5)
    assert L._userinfo_call(url, "t", _Opener(body=b'{"sub": "x"}'), 5) == {"sub": "x"}


def test_broken_http_answer_is_a_retry_not_a_quarantine(env):
    import http.client
    ok(env.checkout("alice"))
    env.ctx.userinfo = lambda url, tok: L._userinfo_call(url, tok, _Opener(body=http.client.IncompleteRead(b"")), 5)
    r = env.approve("bob", V11)
    assert r.state == "retry" and not env.quarantine()


def test_override_only_when_no_approver_other_than_the_author(tmp_path):
    e = Env(tmp_path / "a", isso="dana", approvers=())
    ok(e.checkout("alice"))                                    # alice is the author; the ISSO could approve it
    m = refused(e.req("override", "dana", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="x"),
                "not a one-person site")
    assert "dana" in m
    ok(e.approve("dana", V11))                                 # ... as an ordinary approval
    both = Env(tmp_path / "b", isso="dana", approvers=("bob",))
    ok(both.checkout("dana"))
    ok(both.checkout("bob"))                                   # every approver account is an author of this change
    ok(both.req("override", "dana", 100, name="CUI_SSP_v1.1.docx", sha256=sha(V11), reason="both of us wrote it"))


def test_publish_account_password_reset_every_run(tmp_path):
    from chp_site import documents as D
    from tests import test_chp_site_documents as T
    e = T.Env(tmp_path)
    e.enable()
    n = len(e.nc.calls)
    e.enable()
    rs = [(c, env) for c, env in zip(e.nc.calls[n:], e.nc.envs[n:]) if c[0] == "user:resetpassword"]
    assert len(rs) == 1 and rs[0][0] == ["user:resetpassword", "--password-from-env", D.PUBLISH_USER]
    pw = rs[0][1]["OC_PASS"]
    first = next(env for c, env in zip(e.nc.calls, e.nc.envs) if c[0] == "user:add" and c[-1] == D.PUBLISH_USER)
    assert len(pw) >= 24 and pw != first["OC_PASS"]
    assert not any(pw in " ".join(c) for c in e.nc.calls + e.run.calls)
