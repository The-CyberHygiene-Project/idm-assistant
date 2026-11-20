# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site doc login|logout|checkout|new|check|mark|approve|override|publish|close (ISO 0.7.0 design §4-5, Plan 3
Task 6): the workstation half of the controlled-document workflow. Run as yourself (never root) on a CHP workstation.

Where things are:
  - the working folder ~/Documents/CHP-Working/ (mode 0700, yours, on the workstation's LUKS2 disk; refused
    otherwise). The working copies are CUI; beside them, .chp-doc/ holds one record per document (which version was
    checked out, its NextCloud file id and the sha256 the SERVER recorded at checkout; never a token);
  - the sign-in tokens only in $XDG_RUNTIME_DIR/chp-doc/ (doc_auth), with the requests still pending.
Every request goes to the NextCloud app chp_ledger (POST .../api/v1/request, then GET .../result/<id>) with the
Kanidm chp-doc access token as the Bearer; the server's root appender checks it at Kanidm and decides. Nothing here
is trusted by the server: the local checks only spare a round trip.

Requests and "retry": each request has a random 32-hex request id, kept in the runtime dir until the ledger answers
done or refused. On "retry" (Kanidm unreachable at the server, or the token expired there) the same request id is
sent again with a fresh token (the appender is idempotent by request id); an HTTP 409 or 500 on a re-sent id means
"poll the result". When the retries run out, or the ledger has not answered in time, the command says "pending"
(exit 3): running the same command again re-sends the SAME request, never a second one.

Documents: the name rule is marking.parse_name's (<CUI_|FCI_><title>_vX.Y[-DRAFT].<ext>). A document lives in
CUI/Compliance (a CUI_ or FCI_ name) or Internal/Compliance (no prefix), or a folder directly inside one; the area
ids come from the server (WebDAV), never from here. approve, override and publish name the document by its area
folder and its file name (the appender keys a document by folder + prefix + title + extension, so the version in
the name can change). Marks (from the name: CUI_ the CUI banner and block, FCI_ the FCI banner only, owner decision
2026-11-20): check, approve and publish run marking.check here first (the server runs it again);
mark inserts them into a -DRAFT file, dry run unless --apply. publish never renames: the author renames the approved
file away from -DRAFT (unchanged, so its sha256 still matches the approval); publish refuses a -DRAFT name.

Reader PDF: made with ONLYOFFICE's x2t (unsupported CLI; it needs ONLYOFFICE's first GUI run, which builds
AllFonts.js) from the approved file, then checked with marking.check before it is sent. A PDF document is its own
reader copy.

Close (spike G2): `doc close <file>` removes the working copy, its record, ONLYOFFICE's auto-recovery copies of it
(data/recover/DE__*/) and its recents.xml entries; refused while ONLYOFFICE runs. remove_editor_copies() is the
function the periodic sweep (Task 8) calls with its own rule."""
import base64
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

from . import doc_auth as auth
from .sitefile import SiteError

RETRIES = 3
POLL_TIMEOUT = 300                # a publish makes several NextCloud writes on the server
WORK = ("Documents", "CHP-Working")
AREAS = {True: "CUI/Compliance", False: "Internal/Compliance"}
SKIP_FOLDERS = ("Superseded",)    # Internal/Compliance/Superseded sits inside Internal/Compliance
OO = Path(".local/share/onlyoffice/desktopeditors")
RECOVER = OO / "data" / "recover"
RECENTS = (OO / "data" / "recents.xml", OO / "recents.xml")
ALLFONTS = OO / "data" / "fonts" / "AllFonts.js"
EDITOR_PROCESSES = ("DesktopEditors", "editors_helper")
PDF_FORMAT = 513                  # x2t: AVS_OFFICESTUDIO_FILE_CROSSPLATFORM_PDF
X2T_TIMEOUT = 180
MAX_CONTENT = 64 << 20            # chp_ledger: content and pdf_content together, decoded
TEMPLATES_PKG = "chp-templates 1.4.0"
LEDGER = "/ocs/v2.php/apps/chp_ledger/api/v1"
NS = {"d": "DAV:", "oc": "http://owncloud.org/ns"}
PROPFIND = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>'
            '<d:getetag/><oc:fileid/><oc:size/><d:resourcetype/></d:prop></d:propfind>')


class DocError(SiteError):
    """A plain refusal before anything was sent (chp-site prints it; exit 2)."""


# ---------- the environment ----------

def processes(proc="/proc"):
    """{uid: {comm, ...}} of the running processes (from /proc). doc close and the Task 8 sweep both read it."""
    tab = {}
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return tab
    for p in pids:
        try:
            uid = os.stat(os.path.join(proc, p)).st_uid
            with open(os.path.join(proc, p, "comm")) as f:
                tab.setdefault(uid, set()).add(f.read().strip())
        except OSError:
            continue
    return tab


def _editor_running(env):
    """An ONLYOFFICE process of this user is running (from /proc)."""
    return bool(processes().get(env.uid, set()) & set(EDITOR_PROCESSES))


def system_env():
    if os.getuid() == 0:
        raise DocError("refused: run chp-site doc as yourself, not as root (it signs in as you)")
    from .sitefile import parse_site, read_file
    try:
        site = parse_site(read_file(Path("/etc/chp/site.conf"), "site.conf"))
    except Exception as e:                                # noqa: BLE001 - a plain message, never a traceback
        raise DocError(f"cannot read the site settings (/etc/chp/site.conf): {e}") from None
    if not site.get("DOMAIN"):
        raise DocError("cannot read the site settings (/etc/chp/site.conf): DOMAIN is not set")
    pw = pwd.getpwuid(os.getuid())
    return auth.Env(domain=site["DOMAIN"], uid=os.getuid(), user_name=pw.pw_name, home=pw.pw_dir,
                    runtime=os.environ.get("XDG_RUNTIME_DIR"), site=site, editor_running=_editor_running)


def _site(env):
    if env.site is None:
        from .sitefile import parse_site, read_file
        p = Path(env.site_dir) / "site.conf"
        try:
            env.site = parse_site(read_file(p, "site.conf"))
        except Exception as e:                            # noqa: BLE001
            raise DocError(f"cannot read the site settings ({p}): {e}") from None
    return env.site


def _values(env):
    from . import marking
    try:
        return marking.MarkValues.from_site(_site(env))
    except DocError:
        raise
    except Exception as e:                                # noqa: BLE001 - MarkValues.from_site raises on a bad site
        raise DocError(f"cannot read the marking values from site.conf: {e}") from None


def _parse(name):
    from . import marking
    try:
        return marking.parse_name(name)
    except marking.NameRuleError as e:
        raise DocError(f"refused: {e}") from None


# ---------- the working folder ----------

def _dm(src, sysfs):
    if src.startswith("/dev/mapper/"):
        want = src[len("/dev/mapper/"):]
        try:
            for d in os.listdir(Path(sysfs) / "block"):
                try:
                    if (Path(sysfs) / "block" / d / "dm" / "name").read_text().strip() == want:
                        return d
                except OSError:
                    continue
        except OSError:
            return None
        return None
    b = os.path.basename(src)
    return b if src.startswith("/dev/dm-") else None


def _luks2(dm, sysfs, depth=0):
    if dm is None or depth > 16:
        return False
    base = Path(sysfs) / "block" / dm
    try:
        if (base / "dm" / "uuid").read_text().strip().startswith("CRYPT-LUKS2"):
            return True
        slaves = os.listdir(base / "slaves")
    except OSError:
        return False
    return any(_luks2(s, sysfs, depth + 1) for s in slaves if s.startswith("dm-"))


def on_luks2(path, env):
    m = auth.mount_of(path, env.mounts)
    return m is not None and _luks2(_dm(m[0], env.sysfs), env.sysfs)


def working_folder(env, create=True):
    """~/Documents/CHP-Working: made 0700 when missing; refused unless it is your own 0700 folder (not a symbolic
    link) on a LUKS2-encrypted disk. create=False: None when it does not exist (nothing is made)."""
    w = env.home.joinpath(*WORK)
    if not os.path.lexists(w):
        if not create:
            return None
        if not os.path.lexists(w.parent):
            os.mkdir(w.parent, 0o700)
        os.mkdir(w, 0o700)
        os.chmod(w, 0o700)
    st = os.lstat(w)
    if not stat.S_ISDIR(st.st_mode):
        raise DocError(f"refused: {w} is not a folder (or is a symbolic link)")
    if st.st_uid != env.uid or stat.S_IMODE(st.st_mode) != 0o700:
        raise DocError(f"refused: the working folder {w} must be yours with mode 0700 (it holds CUI); "
                       f"fix it with: chmod 0700 {w}")
    if not on_luks2(w, env):
        raise DocError(f"refused: the working folder {w} is not on a LUKS2-encrypted disk (CUI working copies may "
                       "only be kept there)")
    return w


def _private_dir(p):
    try:
        os.mkdir(p, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(p)
    if not stat.S_ISDIR(st.st_mode):
        raise DocError(f"refused: {p} is not a folder")
    return Path(p)


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _series_key(name):
    """A document's key: its series (prefix + title, NFC, case-folded) + its extension; None when the name breaks
    the rule."""
    from . import marking
    try:
        p = marking.parse_name(name)
    except marking.NameRuleError:
        return None
    return f"{marking._series_key(p.series)}.{p.ext.lower()}"


class Records:
    """<working folder>/.chp-doc/<key>.json: one record per document (series + extension), so renaming the version
    (or dropping -DRAFT) keeps it."""

    def __init__(self, work):
        self.dir = Path(work) / ".chp-doc"

    def _file(self, name):
        k = _series_key(name)
        return None if k is None else self.dir / (hashlib.sha256(k.encode()).hexdigest()[:32] + ".json")

    def get(self, name):
        f = self._file(name)
        if f is None or not f.is_file():
            return None
        try:
            r = json.loads(f.read_text())
        except ValueError:
            return None
        return r if isinstance(r, dict) else None

    def put(self, name, rec):
        _private_dir(self.dir)
        auth.write_private(self._file(name), rec)

    def drop(self, name):
        f = self._file(name)
        if f is not None:
            try:
                os.unlink(f)
            except FileNotFoundError:
                pass


class _Pending:
    """Requests sent and not yet answered done/refused: {key: request id}, in the runtime dir. Every
    read-modify-write holds the runtime dir's pending lock (two commands at once never lose an id)."""

    def __init__(self, env):
        self.env = env
        self.path = auth.runtime_dir(env) / "pending.json"

    def _all(self):
        try:
            d = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return d if isinstance(d, dict) else {}

    def get(self, key):
        with auth.locked(self.env, "pending"):
            v = self._all().get(key)
        return v if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{32}", v) else None

    def put(self, key, rid):
        with auth.locked(self.env, "pending"):
            d = self._all()
            d[key] = rid
            auth.write_private(self.path, d)

    def drop(self, key):
        with auth.locked(self.env, "pending"):
            d = self._all()
            if d.pop(key, None) is not None:
                auth.write_private(self.path, d)


# ---------- NextCloud ----------

def _bearer(s):
    return {"Authorization": "Bearer " + s["access_token"]}


def _dav_url(env, s, path):
    return (f"{env.files}/remote.php/dav/files/{urllib.parse.quote(s['nc_user'], safe='')}/"
            + urllib.parse.quote(path.strip("/")))


def propfind(env, s, path, depth="0"):
    """[{path, name, fileid, etag, size, folder}] (the first is path itself); None when it does not exist."""
    st, _, data = auth._call(env, "PROPFIND", _dav_url(env, s, path),
                             dict(_bearer(s), Depth=depth, **{"Content-Type": "application/xml"}), PROPFIND)
    if st == 404:
        return None
    if st == 401:
        raise auth.AuthError("refused: NextCloud did not accept your sign-in; run chp-site doc login")
    if st != 207:
        raise DocError(f"refused: NextCloud answered HTTP {st} for {path}")
    try:
        return _multistatus(env, s, data)
    except (ET.ParseError, ValueError, TypeError):
        raise DocError(f"refused: NextCloud's answer for {path} could not be read (not a WebDAV listing)") from None


def _multistatus(env, s, data):
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError("a DTD in a WebDAV answer")
    root = ET.fromstring(data)
    prefix = urllib.parse.unquote(urllib.parse.urlsplit(_dav_url(env, s, "")).path)
    out = []
    for r in root.findall("d:response", NS):
        href = urllib.parse.unquote(r.findtext("d:href", "", NS))
        rel = href[len(prefix):] if href.startswith(prefix) else href
        rel = rel.strip("/")
        fid = r.findtext(".//oc:fileid", None, NS)
        out.append({"path": rel, "name": rel.rsplit("/", 1)[-1], "fileid": int(fid) if fid and fid.isdigit() else None,
                    "etag": r.findtext(".//d:getetag", "", NS),
                    "size": int(r.findtext(".//oc:size", "0", NS) or 0),
                    "folder": r.find(".//d:resourcetype/d:collection", NS) is not None})
    return out


def fetch(env, s, path):
    st, _, data = auth._call(env, "GET", _dav_url(env, s, path), _bearer(s))
    if st != 200:
        raise DocError(f"refused: NextCloud answered HTTP {st} when reading {path}")
    return data


def _current(listing, key):
    """The current version in a folder listing of the document with this key (None when it has none)."""
    for it in listing[1:]:
        if not it["folder"] and _series_key(it["name"]) == key:
            return it
    return None


def _versions(listing):
    """{series: 'X.Y'} of the files in a folder listing (for the citation check)."""
    from . import marking
    out = {}
    for it in listing[1:]:
        if it["folder"]:
            continue
        try:
            p = marking.parse_name(it["name"])
        except marking.NameRuleError:
            continue
        if p.series not in out or p.version_tuple > tuple(int(x) for x in out[p.series].split(".")):
            out[p.series] = p.version
    return out


def area(env, s, cui):
    items = propfind(env, s, AREAS[cui])
    if not items or items[0]["fileid"] is None:
        raise DocError(f"refused: the area {AREAS[cui]} is not visible to you in NextCloud (are the documents "
                       "enabled on the server, and are you in the right groups?)")
    return items[0]


def locate(env, s, name, cui):
    """(the folder that holds the document, or the area when it is new; its current version or None)."""
    key = _series_key(name)
    top = propfind(env, s, AREAS[cui], "1")
    if not top:
        area(env, s, cui)
    hit = _current(top, key)
    if hit:
        return top[0], hit, top
    for sub in top[1:]:
        if sub["folder"] and sub["name"] not in SKIP_FOLDERS:
            lst = propfind(env, s, sub["path"], "1") or []
            hit = _current(lst, key) if lst else None
            if hit:
                return lst[0], hit, lst
    return top[0], None, top


def _ocs(data):
    try:
        d = json.loads(data)["ocs"]["data"]
    except (ValueError, TypeError, KeyError):
        return {}
    return d if isinstance(d, dict) else {}


def _poll(env, rid):
    deadline = env.clock() + (env.poll_timeout or POLL_TIMEOUT)
    forced = False
    while True:
        s = auth.fresh(env)
        st, _, data = auth._call(env, "GET", f"{env.files}{LEDGER}/result/{rid}?format=json",
                                 dict(_bearer(s), **{"OCS-APIRequest": "true", "Accept": "application/json"}))
        d = _ocs(data)
        if st == 200 and d.get("state") in ("done", "refused", "retry"):
            return d["state"], d
        if st == 401 and not forced:
            auth.fresh(env, force=True)
            forced = True
            continue
        if st not in (200, 404):                     # 404: not visible yet
            return "error", {"message": d.get("message") or f"the ledger answered HTTP {st}"}
        if env.clock() >= deadline:
            return "timeout", d
        env.sleep(env.poll_interval)


SIGN_IN_AGAIN = "sign in again (chp-site doc login), then run the same command again"
LASTING = (400, 403, 413)          # chp_ledger's answers to the request itself (shape, visibility, size): the same
                                   # body always gets them again, so a kept id is not left pending forever (Task 11a)
PROXY = (502, 503, 504)            # a proxy in front of NextCloud: the POST may have reached it


def _result_once(env, rid):
    """One look at the ledger's result for rid: ("final", (state, answer)) for done / refused; ("absent", None) only
    when the app answers 404 (it holds nothing for rid: neither waiting in the spool nor a result); else ("held", why):
    queued, retry, 401, 5xx or anything else, the server may still hold it (fix round 1, I3). Raises
    auth.Unreachable / auth.AuthError."""
    s = auth.fresh(env)
    st, _, data = auth._call(env, "GET", f"{env.files}{LEDGER}/result/{rid}?format=json",
                             dict(_bearer(s), **{"OCS-APIRequest": "true", "Accept": "application/json"}))
    d = _ocs(data)
    if st == 200 and d.get("state") in ("done", "refused"):
        return "final", (d["state"], d)
    if st == 404:
        return "absent", None
    what = d.get("state") if st == 200 else f"HTTP {st}"
    return "held", f"the server may still hold this request (its result is {what or 'unknown'})"


def _plain(e):
    m = str(e)
    return m[len("refused: "):] if m.startswith("refused: ") else m


def send(env, kind, fields, say=print):
    """Send one request to the ledger and wait for its answer: (state, answer), state = done | refused | pending.

    Once the server may hold the request id (it was kept from an earlier run, or a POST of it has been made), nothing
    here answers "refused" on its own: a sign-in that ends, NextCloud or Kanidm unreachable, or an HTTP answer other
    than 200 to the POST is "pending" and the id is kept, so the next run asks about the same request. The ledger's
    own result (done / refused) ends it, and so does a LASTING refusal of the request itself (400, 403, 413: the same
    body is refused every time): after one look at its result, the id is dropped only when the server holds nothing for
    it (404; a done/refused result is answered instead; queued, retry or a failed look stays pending) (Task 11a). 401, 409, 429 and 5xx stay pending. On the FIRST POST of a new id any non-200 answer is a
    refusal (nothing was spooled), except a proxy's 502/503/504: the request may have got through, so pending."""
    key_src = {"kind": kind, **{k: v for k, v in fields.items() if k not in ("content", "pdf_content")}}
    key = hashlib.sha256(json.dumps(key_src, sort_keys=True).encode()).hexdigest()
    pend = _Pending(env)
    rid = pend.get(key)
    kept = rid is not None                                # from an earlier run: the server may hold it
    known = kept                                          # the server may hold this id
    if rid is None:
        rid = secrets.token_hex(16)
        pend.put(key, rid)
    body = json.dumps({"kind": kind, **fields, "request_id": rid})

    def pending(why):
        return "pending", {"message": f"pending: {why}. Nothing more happens now; run the same command again in a "
                                      "minute (it sends this same request again, never a second one)"}
    force, unauthorised = False, False
    why = "the ledger has not answered yet"
    for attempt in range(RETRIES):
        try:
            s = auth.fresh(env, force=force)
        except auth.Unreachable as e:
            return pending(str(e))
        except auth.AuthError as e:
            if not known:
                pend.drop(key)                            # nothing was sent: a plain refusal
                raise
            return pending(f"{_plain(e)}; {SIGN_IN_AGAIN}")
        try:
            known = True                                  # a POST is going out: the server may get it
            st, _, data = auth._call(env, "POST", f"{env.files}{LEDGER}/request?format=json",
                                     dict(_bearer(s), **{"OCS-APIRequest": "true", "Accept": "application/json",
                                                         "Content-Type": "application/json"}), body)
        except auth.Unreachable as e:
            return pending(str(e))
        d = _ocs(data)
        if st == 401:
            if unauthorised:
                return pending(f"NextCloud did not accept your sign-in; {SIGN_IN_AGAIN}")
            unauthorised, force = True, True
            continue
        if st != 200:
            first = not kept and attempt == 0
            if first and st in PROXY:
                return pending(f"the server answered HTTP {st} (a proxy in front of NextCloud); the request may have "
                               "reached it")
            if first:
                pend.drop(key)                            # the first POST of a new id, answered: never spooled
                return "refused", {"message": d.get("message") or f"refused: the ledger answered HTTP {st}"}
            if st in LASTING:
                try:                                      # an earlier send of this id may have been processed
                    how, got = _result_once(env, rid)
                except auth.Unreachable as e:
                    return pending(str(e))
                except auth.AuthError as e:
                    return pending(f"{_plain(e)}; {SIGN_IN_AGAIN}")
                if how == "held":
                    return pending(got)
                pend.drop(key)
                if how == "final":
                    return got
                return "refused", {"message": (d.get("message") or f"refused: the ledger answered HTTP {st}")
                                   + " (this request is refused every time it is sent: it is dropped; fix the cause "
                                     "and run the command again)"}
            if st not in (409, 500):
                return pending(d.get("message") or f"the server answered HTTP {st}")
            # 409 / 500 on a re-sent id: poll its result
        try:
            state, d = _poll(env, rid)
        except auth.Unreachable as e:
            return pending(str(e))
        except auth.AuthError as e:
            return pending(f"{_plain(e)}; {SIGN_IN_AGAIN}")
        if state in ("done", "refused"):
            pend.drop(key)
            return state, d
        if state == "retry":
            why = d.get("message") or "the server asked for the request again"
            say(f"  {why}; sending it again with a fresh sign-in token")
            force = True
            continue
        if state == "error":
            why = d.get("message") or why
        break
    return pending(why)


def _answer(state, d, say):
    msg = d.get("message") or state
    say(msg)
    return {"done": 0, "refused": 1, "pending": 3}.get(state, 1)


# ---------- the commands ----------

def _file(path):
    f = Path(path)
    if not f.is_file():
        raise DocError(f"refused: {path} is not a file")
    return f


def _cui_of(name, rec):
    if rec is not None and "cui" in rec:
        return bool(rec["cui"])
    return name.startswith(("CUI_", "FCI_"))


def _record(env, name):
    w = working_folder(env, create=False)
    return Records(w).get(name) if w is not None else None


def _next_draft(p):
    x, y = (int(v) for v in p.version.split("."))
    if y >= 9999:
        raise DocError(f"refused: {p.series}_v{p.version}: no next minor version; rename the working copy by hand")
    return f"{p.series}_v{x}.{y + 1}-DRAFT.{p.ext}"


def cmd_checkout(env, a, say):
    arg = a.document.strip()
    name = arg.rsplit("/", 1)[-1]
    p = _parse(name)
    w = working_folder(env)
    s = auth.fresh(env)
    if "/" in arg:
        items = propfind(env, s, arg)
        if not items or items[0]["folder"]:
            raise DocError(f"refused: {arg} was not found in NextCloud (or is a folder)")
        it = items[0]
        up = propfind(env, s, arg.rsplit("/", 1)[0])
        if not up:
            raise DocError(f"refused: the folder of {arg} is not visible to you in NextCloud")
        parent = up[0]
    else:
        parent, it, _ = locate(env, s, name, bool(p.prefix))
        if it is None or it["name"] != name:
            hint = f" (the current version is {it['name']})" if it else ""
            raise DocError(f"refused: {name} was not found in {AREAS[bool(p.prefix)]}{hint}")
    cui = it["path"].startswith(AREAS[True] + "/")
    if not cui and not it["path"].startswith(AREAS[False] + "/"):
        raise DocError(f"refused: {it['path']} is not a controlled document (CUI/Compliance or Internal/Compliance)")
    local = _next_draft(p)
    if os.path.lexists(w / local):
        raise DocError(f"refused: {w / local} already exists; publish it or close it first (chp-site doc close)")
    state, d = send(env, "checkout", {"file_id": it["fileid"]}, say)
    if state != "done":
        return _answer(state, d, say)
    e = d.get("entry") or {}
    s = auth.fresh(env)                                   # the poll may have taken minutes: not the token from before
    data = fetch(env, s, it["path"])
    if not e.get("sha256") or hashlib.sha256(data).hexdigest() != e["sha256"]:
        say(f"refused: {name} changed between the server's checkout record and the download (an administrator's edit "
            "or a publish); nothing was kept here; check it out again")
        return 1
    _write_new(w / local, data)
    Records(w).put(local, {"name": it["name"], "path": it["path"], "file_id": it["fileid"],
                           "folder_id": parent["fileid"], "folder_path": parent["path"], "cui": cui,
                           "sha256": e["sha256"], "etag": it["etag"], "seq": e.get("seq"), "user": s["user"],
                           "request_id": d.get("request_id"), "local": local})
    say(d.get("message", "checkout recorded"))
    say(f"working copy: {w / local}\n"
        "Open it in ONLYOFFICE (the first time, start ONLYOFFICE once from the desktop: publish needs its first run)."
        f"\nThe next version is a minor one (v{local.split('_v')[-1].split('-')[0]}); rename it for a major change.")
    return 0


TEMPLATE_PLACEHOLDERS = {"CUI_CONTROLLED_BY": "controlled_by", "CUI_CATEGORY": "category", "CUI_POC": "poc"}
_PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def fill_template(data, ext, values):
    """A marked template (chp-templates 1.4.0 doc/cui/) with its {{CUI_CONTROLLED_BY}}, {{CUI_CATEGORY}} and {{CUI_POC}}
    placeholders filled from the site's marking values (the values as marking.check compares them). docx/xlsx: in the
    XML text of every part, XML-escaped, in a package rebuilt with the same order, dates and compression (the same
    template and values always give the same bytes); md: as text. One substitution pass over the template, so a value
    that itself holds "{{...}}" stays literal. A placeholder in the template that chp-site does not fill is refused
    (DocError) before anything is filled. The templates hold the placeholders only in body text, footer paragraphs
    and cells, never inside an Excel header/footer code string."""
    from . import marking
    vals = {k: marking._norm(getattr(values, attr, "") or "") for k, attr in TEMPLATE_PLACEHOLDERS.items()}

    def fill(text, xml):
        unknown = sorted({m.group(1) for m in _PLACEHOLDER.finditer(text)} - set(vals))
        if unknown:
            raise DocError("refused: the template holds a placeholder that chp-site does not fill ("
                           + ", ".join("{{%s}}" % u for u in unknown) + f"); install the template from {TEMPLATES_PKG}")
        return _PLACEHOLDER.sub(lambda m: escape(vals[m.group(1)], {'"': "&quot;"}) if xml else vals[m.group(1)],
                                text)

    if ext == "md":
        try:
            return fill(data.decode("utf-8"), False).encode("utf-8")
        except UnicodeDecodeError:
            raise DocError("refused: the template is not UTF-8 text") from None
    try:
        z = marking._Zip(data)
    except marking._Bad as e:
        raise DocError(f"refused: the template {e}") from None
    out = {}
    for name in z.data:
        b = z.data[name]
        if b"{{" in b:
            try:
                out[name] = fill(b.decode("utf-8"), True).encode("utf-8")
            except UnicodeDecodeError:
                raise DocError(f"refused: the template's part {name} is not UTF-8") from None
    return marking._rezip(z, out, []) if out else data


def cmd_new(env, a, say):
    """--cui: CUI_<title> from doc/cui (filled from the CUI marking site keys, CUI marks); --fci: FCI_<title> from
    doc/fci (the FCI banner only, no site keys; owner decision 2026-11-20); both go to CUI/Compliance (the name rule's
    CUI_/FCI_ prefixes share the CUI area). --non-cui: no prefix, doc/noncui, Internal/Compliance."""
    from . import marking
    fci = bool(getattr(a, "fci", False))
    cui = bool(a.cui) or fci                              # the target area: FCI_ documents live in CUI/Compliance
    ext = a.type
    prefix = "FCI_" if fci else ("CUI_" if cui else "")
    name = f"{prefix}{a.title}_v0.1-DRAFT.{ext}"
    _parse(name)
    tpl = Path(env.templates) / ("fci" if fci else "cui" if cui else "noncui") / f"Template.{ext}"
    if not tpl.is_file():
        raise DocError(f"refused: the template {tpl} is not installed (it comes with {TEMPLATES_PKG})")
    values = _values(env) if cui and not fci else marking.MarkValues()
    if cui and not fci:
        _, missing = values.block()
        if missing:
            raise DocError("refused: the site keys " + ", ".join(missing) + " are not set, so a CUI document cannot "
                           "be marked (set them on the site stick and apply it)")
    w = working_folder(env)
    dst = w / name
    if os.path.lexists(dst):
        raise DocError(f"refused: {dst} already exists")
    tmp = Path(tempfile.mkdtemp(dir=_private_dir(Records(w).dir), prefix="new-"))
    try:
        f = tmp / name
        _write_new(f, fill_template(tpl.read_bytes(), ext, values) if cui and not fci else tpl.read_bytes())
        if cui:
            try:
                marking.insert(f, values, dry_run=False)
            except (marking.MarkingError, marking.NameRuleError) as e:
                raise DocError(f"refused: the template could not be marked: {e}") from None
        rep = marking.check(f, cui, values)
        if not rep.ok:
            raise DocError("refused: the new document does not pass the marking check: " + "; ".join(rep.problems))
        s = auth.fresh(env)
        ar = area(env, s, cui)
        state, d = send(env, "new", {"file_id": ar["fileid"], "path": name}, say)
        if state != "done":
            return _answer(state, d, say)
        os.rename(f, dst)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    Records(w).put(name, {"name": None, "path": f"{ar['path']}/{name}", "file_id": None, "folder_id": ar["fileid"],
                          "folder_path": ar["path"], "cui": cui, "sha256": None, "user": s["user"],
                          "seq": (d.get("entry") or {}).get("seq"), "request_id": d.get("request_id"), "local": name})
    say(d.get("message", "new recorded"))
    say(f"new document: {dst}\nOpen it in ONLYOFFICE (the first time, start ONLYOFFICE once from the desktop: publish "
        "needs its first run).")
    return 0


def _freshness(env, s, rec, key):
    """(fresh?, the folder listing) against this document's checkout record."""
    lst = propfind(env, s, rec["folder_path"], "1") if rec.get("folder_path") else None
    if rec.get("file_id") is None:
        return True, lst
    cur = _current(lst or [], key) if lst else None
    if cur is None or cur["fileid"] != rec["file_id"]:
        return False, lst
    if cur["etag"] == rec.get("etag"):                    # ETag is only a pre-check: equal means unchanged
        return True, lst
    return hashlib.sha256(fetch(env, s, cur["path"])).hexdigest() == rec["sha256"], lst


def _stale(rec):
    return (f"the canonical copy {rec['name']} changed since your checkout (or is no longer the current version); "
            "check it out again (chp-site doc checkout)")


def cmd_check(env, a, say):
    from . import marking
    f = _file(a.file)
    rec = _record(env, f.name)
    cui = _cui_of(f.name, rec)
    values = _values(env) if cui else marking.MarkValues()
    key = _series_key(f.name)
    current, fresh, note = None, True, None
    try:
        s = auth.fresh(env)
    except auth.AuthError as e:
        s, note = None, f"freshness and citations not checked: {e}"
    if s is not None and key is not None:
        try:
            if rec is not None:
                fresh, lst = _freshness(env, s, rec, key)
            else:
                _, _, lst = locate(env, s, f.name, cui)
            current = _versions(lst) if lst else None
        except (auth.AuthError, DocError) as e:
            note = f"freshness and citations not checked: {e}"
    rep = marking.check(f, cui, values, current)
    marks = ("FCI banner" if f.name.startswith("FCI_") else "CUI marks") if cui else "no banner"
    say(f"{f.name}: {'CUI' if cui else 'non-CUI'} area ({marks})")
    for p in rep.problems:
        say(f"  PROBLEM: {p}")
    for w_ in rep.warnings:
        say(f"  WARNING: {w_}")
    if rep.name is not None and rep.name.draft:
        say(f"  -DRAFT: still a draft; after the approval rename it, unchanged, to "
            f"{f.name.replace('-DRAFT', '', 1)} and publish that")
    if rec is not None and s is not None and note is None:
        say("  freshness: fresh (the canonical copy is the one you checked out)" if fresh else f"  PROBLEM: {_stale(rec)}")
    elif rec is None and note is None:
        say("  freshness: no checkout of this document in your working folder (nothing to compare)")
    if note:
        say(f"  {note}")
    ok = rep.ok and fresh
    say("OK" if ok else "NOT READY")
    return 0 if ok else 1


def cmd_mark(env, a, say):
    from . import marking
    f = _file(a.file)
    values = _values(env)
    try:
        changes = marking.insert(f, values, dry_run=not a.apply)
    except (marking.MarkingError, marking.NameRuleError) as e:
        say(str(e))
        return 1
    if not changes:
        say(f"{f.name}: nothing to add (the marks are there)")
        return 0
    say(("dry run (nothing changed; run again with --apply): " if not a.apply else "marked: ") + f.name)
    for c in changes:
        say(f"  {c}")
    return 0


def _ready(env, f, rec, say):
    """The local marking check before approve / override / publish; (cui, values) or None (refused, reported)."""
    from . import marking
    cui = _cui_of(f.name, rec)
    values = _values(env) if cui else marking.MarkValues()
    rep = marking.check(f, cui, values)
    if not rep.ok:
        say(f"refused: {f.name} does not pass the marking check (nothing was sent):")
        for p in rep.problems:
            say(f"  {p}")
        return None
    return cui, values


def _folder_of(env, s, f, rec, cui):
    if rec is not None and rec.get("folder_id"):
        return rec["folder_id"]
    folder, _, _ = locate(env, s, f.name, cui)
    return folder["fileid"]


def _sign(env, a, say, kind):
    f = _file(a.file)
    _parse(f.name)
    rec = _record(env, f.name)
    r = _ready(env, f, rec, say)
    if r is None:
        return 1
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    s = auth.fresh(env)
    fields = {"file_id": _folder_of(env, s, f, rec, r[0]), "path": f.name, "sha256": sha}
    if kind == "approve" and a.notes:
        fields["notes"] = a.notes
    if kind == "override":
        if not (a.reason or "").strip():
            raise DocError("refused: an override needs a reason (--reason)")
        fields["reason"] = a.reason
    state, d = send(env, kind, fields, say)
    return _answer(state, d, say)


def cmd_approve(env, a, say):
    return _sign(env, a, say, "approve")


def cmd_override(env, a, say):
    return _sign(env, a, say, "override")


def _x2t_params(src, dst, fonts):
    return ('<?xml version="1.0" encoding="utf-8"?>\n<TaskQueueDataConvert>\n'
            f"<m_sFileFrom>{escape(str(src))}</m_sFileFrom>\n<m_sFileTo>{escape(str(dst))}</m_sFileTo>\n"
            f"<m_nFormatTo>{PDF_FORMAT}</m_nFormatTo>\n<m_sAllFontsPath>{escape(str(fonts))}</m_sAllFontsPath>\n"
            f"<m_sFontDir>{escape(str(fonts.parent))}</m_sFontDir>\n<m_bIsNoBase64>false</m_bIsNoBase64>\n"
            "</TaskQueueDataConvert>\n")


def _x2t_env(env, scratch):
    """x2t's environment: only what it needs, its temporary files in the private folder the caller removes (they are
    CUI), never /tmp."""
    keep = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "LC_CTYPE") if k in os.environ}
    return dict(keep, HOME=str(env.home), TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch))


def reader_pdf(env, f, tmp):
    """The reader PDF of f, made by x2t in tmp (a private folder the caller removes): its path."""
    fonts = env.home / ALLFONTS
    if not fonts.is_file():
        raise DocError("refused: ONLYOFFICE has not had its first run yet (it builds its font list then, and the "
                       "reader PDF needs it): start ONLYOFFICE once from the desktop, close it, then run publish again")
    if not os.access(env.x2t, os.X_OK):
        raise DocError(f"refused: ONLYOFFICE's converter {env.x2t} is not installed (chp-onlyoffice)")
    stem = f.name.rsplit(".", 1)[0]
    src = tmp / (stem + (".txt" if f.suffix.lower() == ".md" else f.suffix))   # x2t reads Markdown as plain text
    shutil.copyfile(f, src)
    out = tmp / "out" / (stem + ".pdf")
    out.parent.mkdir(mode=0o700)
    params = tmp / "params.xml"
    params.write_text(_x2t_params(src, out, fonts))
    scratch = tmp / "scratch"
    scratch.mkdir(mode=0o700)
    try:
        r = subprocess.run([env.x2t, str(params)], cwd=str(tmp), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=X2T_TIMEOUT, env=_x2t_env(env, scratch))
    except subprocess.TimeoutExpired:
        raise DocError(f"refused: ONLYOFFICE's converter did not finish in {X2T_TIMEOUT} s; nothing was sent") from None
    except OSError as e:
        raise DocError(f"refused: ONLYOFFICE's converter could not run ({e}); nothing was sent") from None
    if r.returncode != 0 or not out.is_file() or out.read_bytes()[:5] != b"%PDF-":
        tail = r.stdout.decode("utf-8", "replace").strip().splitlines()[-1:] if r.stdout else []
        raise DocError(f"refused: ONLYOFFICE's converter made no PDF (exit {r.returncode}"
                       + (f": {tail[0][:200]}" if tail else "") + "); nothing was sent. If ONLYOFFICE was never "
                       "opened on this workstation, open it once first")
    return out


def cmd_publish(env, a, say):
    from . import marking
    f = _file(a.file)
    p = _parse(f.name)
    if p.draft:
        raise DocError(f"refused: {f.name} is still -DRAFT. publish never renames: rename the approved file yourself, "
                       f"unchanged (mv {f.name} {f.name.replace('-DRAFT', '', 1)}), then publish that")
    rec = _record(env, f.name)
    r = _ready(env, f, rec, say)
    if r is None:
        return 1
    cui, values = r
    data = f.read_bytes()
    s = auth.fresh(env)
    key = _series_key(f.name)
    if rec is not None and rec.get("file_id") is not None:
        fresh, _ = _freshness(env, s, rec, key)
        if not fresh:
            say(f"refused: {_stale(rec)}; nothing was sent")
            return 1
    w = working_folder(env)
    tmp = Path(tempfile.mkdtemp(dir=_private_dir(Records(w).dir), prefix="pdf-"))
    try:
        if p.ext.lower() == "pdf":
            pdf = data
        else:
            out = reader_pdf(env, f, tmp)
            rep = marking.check(out, cui, values)
            if not rep.ok:
                say(f"refused: the reader PDF made from {f.name} does not pass the marking check (nothing was sent):")
                for x in rep.problems:
                    say(f"  {x}")
                return 1
            pdf = out.read_bytes()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if len(data) + len(pdf) > MAX_CONTENT:
        raise DocError(f"refused: {f.name} and its reader PDF together are larger than 64 MiB (the publish limit)")
    s = auth.fresh(env)                                   # x2t may have taken minutes: not the token from before
    fields = {"file_id": _folder_of(env, s, f, rec, cui), "path": f.name, "sha256": hashlib.sha256(data).hexdigest(),
              "content": base64.b64encode(data).decode(), "pdf_content": base64.b64encode(pdf).decode()}
    state, d = send(env, "publish", fields, say)
    rc = _answer(state, d, say)
    if state == "done":
        say(f"When you are done with it: chp-site doc close {f}")
    return rc


# ---------- close (G2) ----------

def _real_dirs(home, rel, say):
    """True when every folder from home down to home/rel exists as a real folder (no symbolic link on the way); a
    link is reported and the place skipped (rmtree would follow it out of the user's ONLYOFFICE data)."""
    p = Path(home)
    for part in Path(rel).parts:
        p = p / part
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            say(f"skipped {Path(home) / rel}: {p} is a symbolic link or not a folder (check it by hand)")
            return False
    return True


def _recover_dirs(home, say=print):
    base = Path(home) / RECOVER
    if not _real_dirs(home, RECOVER, say):
        return []
    try:
        return [base / d for d in sorted(os.listdir(base)) if d.startswith("DE__") and (base / d).is_dir()
                and not (base / d).is_symlink()]
    except OSError:
        return []


def _recover_names(d):
    names = []
    for e in os.listdir(d):
        if (d / e).is_file() and e not in ("Editor.bin", "asc_name.info", "user_name.log"):
            names.append(str(d / e))
    try:
        info = (d / "asc_name.info").read_text(errors="replace").strip()
        if info:
            names.append(info)
    except OSError:
        pass
    return names


def remove_editor_copies(home, match, keep_dir=None, say=print, on_removed=None):
    """Remove ONLYOFFICE's auto-recovery copies (data/recover/DE__*/) and recents.xml entries of the files for which
    match(path) is true; a recover dir is matched on the files in it (and its asc_name.info). Returns what was
    removed. The Task 8 sweep calls this with its own rule (age, no live editor) and on_removed(item), called as
    each removal is DONE, so a failure part-way still leaves a record of what was already removed."""
    removed = []

    def done(item):
        removed.append(item)
        if on_removed:
            on_removed(item)
    for d in _recover_dirs(home, say):
        if d == keep_dir:
            continue
        if any(match(n) for n in _recover_names(d)):
            shutil.rmtree(d)
            done(str(d))
    for rel in RECENTS:
        p = Path(home) / rel
        if not _real_dirs(home, rel.parent, say) or not p.is_file() or p.is_symlink():
            continue
        raw = p.read_bytes()
        bom = raw.startswith(b"\xef\xbb\xbf")
        text = raw[3:] if bom else raw
        if b"<!DOCTYPE" in text or b"<!ENTITY" in text:
            continue
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            continue
        gone = [e for e in list(root) if e.get("path") and match(e.get("path"))]
        if not gone:
            continue
        for e in gone:
            root.remove(e)
        new = (b"\xef\xbb\xbf" if bom else b"") + b'<?xml version="1.0" encoding="utf-8"?>' + \
            ET.tostring(root, encoding="unicode").encode()
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".recents-", suffix=".tmp")
        with os.fdopen(fd, "wb") as fh:
            fh.write(new)
        os.chmod(tmp, stat.S_IMODE(os.stat(p).st_mode))
        os.replace(tmp, p)
        for e in gone:                                    # recorded once the file without them is in place
            done(f"{p}: {e.get('path')}")
    return removed


def cmd_close(env, a, say):
    w = working_folder(env)
    f = Path(a.file)
    if (env.editor_running or _editor_running)(env):
        raise DocError("refused: ONLYOFFICE is running; save and close the document, quit ONLYOFFICE, then run close "
                       "again (its recovery copies of open documents are still in use)")
    key = _series_key(f.name)

    def match(path):
        n = Path(path).name
        return n == f.name or (key is not None and _series_key(n) == key)
    removed = remove_editor_copies(env.home, match, say=say)
    inside = f.exists() and Path(os.path.realpath(f)).parent == Path(os.path.realpath(w))
    if inside:
        os.unlink(f)
        removed.append(str(f))
    elif f.exists():
        say(f"{f} is not in the working folder {w}: left as it is (remove it yourself if it is a copy)")
    if Records(w).get(f.name) is not None:
        Records(w).drop(f.name)
        removed.append(f"the checkout record of {f.name}")
    for r in removed:
        say(f"removed {r}")
    say(f"closed {f.name}" if removed else f"{f.name}: nothing to remove")
    return 0


# ---------- the command line ----------

def cmd_login(env, a, say):
    auth.login(env, say=say)
    return 0


def cmd_logout(env, a, say):
    auth.logout(env, say=say)
    return 0


COMMANDS = {"login": cmd_login, "logout": cmd_logout, "checkout": cmd_checkout, "new": cmd_new, "check": cmd_check,
            "mark": cmd_mark, "approve": cmd_approve, "override": cmd_override, "publish": cmd_publish,
            "close": cmd_close}


def add_parser(sub):
    dp = sub.add_parser("doc", help="(workstation; as yourself) controlled documents: sign in, check out, create, "
                                    "check, mark, approve, override, publish, close")
    ds = dp.add_subparsers(dest="doc_cmd", required=True)
    ds.add_parser("login", help="sign in at Kanidm (browser; the tokens stay in memory, in XDG_RUNTIME_DIR)")
    ds.add_parser("logout", help="revoke the sign-in and remove the tokens")
    c = ds.add_parser("checkout", help="fetch the current version to ~/Documents/CHP-Working as the next -DRAFT")
    c.add_argument("document", help="its name (CUI_SSP_v1.2.docx) or its NextCloud path")
    n = ds.add_parser("new", help="start a new document from the marked template")
    n.add_argument("title")
    g = n.add_mutually_exclusive_group(required=True)
    g.add_argument("--cui", action="store_true", help="for CUI/Compliance (CUI_ name, CUI marks)")
    g.add_argument("--fci", action="store_true", help="for CUI/Compliance (FCI_ name, the FCI banner; no CUI marks)")
    g.add_argument("--non-cui", action="store_true", help="for Internal/Compliance (no prefix, no CUI marks)")
    n.add_argument("--type", choices=("docx", "xlsx", "md"), default="docx")
    k = ds.add_parser("check", help="report what is missing (name rule, marks, -DRAFT, freshness); changes nothing")
    k.add_argument("file")
    m = ds.add_parser("mark", help="insert the missing CUI marks into a -DRAFT file (dry run unless --apply)")
    m.add_argument("file")
    m.add_argument("--apply", action="store_true")
    ap = ds.add_parser("approve", help="(approver) record your approval of this exact file")
    ap.add_argument("file")
    ap.add_argument("--notes")
    o = ds.add_parser("override", help="(ISSO, one-person site) approve your own change, with a reason")
    o.add_argument("file")
    o.add_argument("--reason", required=True)
    pb = ds.add_parser("publish", help="publish the approved file (renamed by you without -DRAFT) and its reader PDF")
    pb.add_argument("file")
    cl = ds.add_parser("close", help="remove the working copy and ONLYOFFICE's recovery copies and recents entries")
    cl.add_argument("file")
    return dp


def run(a, env=None, say=print):
    env = env or system_env()
    try:
        return COMMANDS[a.doc_cmd](env, a, say)
    except OSError as e:                                  # a file of yours, a folder: a plain message, no traceback
        where = f": {e.filename}" if getattr(e, "filename", None) else ""
        raise DocError(f"refused: {e.strerror or e}{where}") from None
