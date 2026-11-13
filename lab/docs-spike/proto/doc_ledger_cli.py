"""proto/doc_ledger_cli.py (Task 2 SPIKE, throwaway; stdlib, Python 3.9; RUNS ON THE WORKSTATION as
`doc_auth.py+doc_ledger_cli.py`, signed in by route 1; CHP_DOC_AS=<person> picks whose session): the workstation half
of the two ledger routes.
  l1 ACTION PATH [--sha HEX] [--notes T] [--reason T] [--claim USER]
        POST /ocs/v2.php/apps/chp_ledger/api/v1/request over NextCloud's HTTPS, then poll /result/<id>.
        --claim adds user=USER to the request (a forgery attempt; the app must ignore it).
  l2 ACTION PATH [--sha HEX] [--notes T] [--claim USER]
        PUT a request file Approvals/<random>.json (the server job reads it later; nothing comes back).
  l2-try-overwrite NAME | l2-try-delete NAME | l2-list
ACTION: checkout | approve | override | publish. --sha defaults to the sha256 of the canonical file now."""
import hashlib as _h
import uuid as _u
import xml.etree.ElementTree as _ET


def _s():
    p, s = load("runtime")
    if not s:
        raise SystemExit("not signed in")
    if time.time() > s["expires_at"] - 30:
        s = oidc_refresh(p, s, print) or s
    return s


def _dav(s, path):
    return f"{FILES}/remote.php/dav/files/{s['user']}/" + urllib.parse.quote(path)


def _fileid_sha(s, path):
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/>'
            '</d:prop></d:propfind>')
    st, _, data = req("PROPFIND", _dav(s, path), body, {"Authorization": auth_header(s), "Depth": "0"})
    if st != 207:
        return None, None, st
    fid = int(_ET.fromstring(data).find(".//{http://owncloud.org/ns}fileid").text)
    st, _, data = req("GET", _dav(s, path), headers={"Authorization": auth_header(s)})
    return fid, _h.sha256(data).hexdigest(), st


def _opt(a, k, d=""):
    return a[a.index(k) + 1] if k in a else d


def l1(a):
    s = _s(); action, path = a[1], a[2]
    fid, sha, st = _fileid_sha(s, path)
    if fid is None:
        fid, sha = int(_opt(a, "--fileid", "119")), "0" * 64
        print(f"  (this user cannot see {path}: HTTP {st}; sending the known file id {fid} anyway)")
    f = {"action": action, "fileid": str(fid), "sha256": _opt(a, "--sha", sha), "notes": _opt(a, "--notes"),
         "reason": _opt(a, "--reason")}
    if "--claim" in a:
        f["user"] = _opt(a, "--claim")
    hdr = {"Authorization": auth_header(s), "OCS-APIRequest": "true", "Accept": "application/json"}
    st, _, data = form_post(f"{FILES}/ocs/v2.php/apps/chp_ledger/api/v1/request?format=json", f, hdr)
    d = json.loads(data)["ocs"]["data"] if data[:1] == b"{" else data[:120]
    print(f"L1 {action} as {s['user']}{' claiming ' + f['user'] if 'user' in f else ''}: POST -> {st} {d}")
    if st != 200:
        return 1
    t0 = time.time()
    while time.time() - t0 < 30:
        st, _, data = req("GET", f"{FILES}/ocs/v2.php/apps/chp_ledger/api/v1/result/{d['id']}?format=json", headers=hdr)
        if st == 200:
            r = json.loads(data)["ocs"]["data"]
            print(f"  result after {time.time() - t0:.1f}s: ok={r['ok']} seq={r['seq']} reason={r['reason']!r}")
            return 0 if r["ok"] else 1
        time.sleep(0.3)
    print("  no result in 30 s"); return 1


def l2(a):
    s = _s(); action, path = a[1], a[2]
    fid, sha, st = _fileid_sha(s, path)
    body = {"action": action, "fileid": fid, "path": path, "sha256": _opt(a, "--sha", sha or ""),
            "notes": _opt(a, "--notes"), "reason": _opt(a, "--reason"), "user": _opt(a, "--claim", s["user"])}
    name = _u.uuid4().hex + ".json"
    st, _, _ = req("PUT", _dav(s, "Approvals/" + name), json.dumps(body), {"Authorization": auth_header(s)})
    print(f"L2 {action} as {s['user']} (file says user={body['user']!r}): PUT Approvals/{name} -> {st}")
    return name


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["l1"]:
        sys.exit(l1(a))
    elif a[:1] == ["l2"]:
        l2(a)
    elif a[:1] in (["l2-try-overwrite"], ["l2-try-delete"]):
        s = _s()
        m = "PUT" if a[0] == "l2-try-overwrite" else "DELETE"
        st = req(m, _dav(s, "Approvals/" + a[1]), b'{"action":"approve"}' if m == "PUT" else None,
                 {"Authorization": auth_header(s)})[0]
        print(f"{a[0]} as {s['user']}: {m} Approvals/{a[1]} -> {st}")
    elif a[:1] == ["l2-list"]:
        s = _s()
        st, _, data = req("PROPFIND", _dav(s, "Approvals"), None, {"Authorization": auth_header(s), "Depth": "1"})
        names = [urllib.parse.unquote(e.text).rsplit("/", 1)[-1] for e in _ET.fromstring(data).iter("{DAV:}href")][1:] if st == 207 else []
        print(f"l2-list as {s['user']}: HTTP {st}; {len(names)} request file(s) visible")
    else:
        print(__doc__)
