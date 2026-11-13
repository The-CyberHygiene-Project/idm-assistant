"""proto/doc_fresh.py (Task 2 SPIKE, throwaway; stdlib, Python 3.9; RUNS ON THE WORKSTATION as `doc_auth.py+doc_fresh.py`,
signed in by route 1): the freshness rule of `chp-site doc checkout` / `publish`.
  checkout PATH                 fetch the canonical copy to ~/chp-docs-work/, record {fileid, etag, sha256} beside it
  publish NAME [--decide etag-only|full] [--dry-run]
                                full (default): refuse unless the canonical's fileid, ETag AND sha256 still match the
                                checkout record; then PUT with If-Match: <etag> so a change in between gives 412.
                                etag-only: the same decision on the ETag alone (to show what it misses)."""
import hashlib as _h

WORK = os.path.expanduser("~/chp-docs-work")


def _session():
    p, s = load("runtime")
    if not s:
        raise SystemExit("not signed in (doc_auth.py oidc-login)")
    if time.time() > s["expires_at"] - 30:
        s = oidc_refresh(p, s, print) or s
    return s


def _dav(s, path):
    return f"{FILES}/remote.php/dav/files/{s['user']}/" + urllib.parse.quote(path)


def _props(s, path):
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:getetag/>'
            '<oc:fileid/><oc:size/></d:prop></d:propfind>')
    st, _, data = req("PROPFIND", _dav(s, path), body, {"Authorization": auth_header(s), "Depth": "0",
                                                         "Content-Type": "application/xml"})
    if st != 207:
        raise SystemExit(f"PROPFIND {path}: HTTP {st}")
    import xml.etree.ElementTree as ET
    r = ET.fromstring(data)
    g = lambda q: r.find(".//" + q, {"d": "DAV:", "oc": "http://owncloud.org/ns"}).text
    return {"etag": g("d:getetag"), "fileid": g("oc:fileid"), "size": int(g("oc:size"))}


def _get(s, path):
    st, h, data = req("GET", _dav(s, path), headers={"Authorization": auth_header(s)})
    if st != 200:
        raise SystemExit(f"GET {path}: HTTP {st}")
    return h.get("etag"), data


def checkout(path):
    s = _session()
    m = _props(s, path)
    etag, data = _get(s, path)
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    name = os.path.basename(path)
    with open(os.path.join(WORK, name), "wb") as f:
        f.write(data)
    rec = {"path": path, "fileid": m["fileid"], "etag": m["etag"], "sha256": _h.sha256(data).hexdigest(),
           "user": s["user"], "time": time.strftime("%FT%TZ", time.gmtime())}
    _write(os.path.join(WORK, f".{name}.checkout.json"), rec)
    print(f"CHECKOUT {path} as {s['user']}: fileid {rec['fileid']} etag {rec['etag']} sha256 {rec['sha256'][:16]}... "
          f"(GET's own ETag header {etag})")


def publish(name, decide, dry):
    s = _session()
    rec = json.load(open(os.path.join(WORK, f".{name}.checkout.json")))
    cur = _props(s, rec["path"])
    _, data = _get(s, rec["path"])
    now_sha = _h.sha256(data).hexdigest()
    same = {"fileid": cur["fileid"] == rec["fileid"], "etag": cur["etag"] == rec["etag"], "sha256": now_sha == rec["sha256"]}
    print(f"  canonical now: etag {cur['etag']} sha256 {now_sha[:16]}...; matches checkout: {same}")
    ok = same["fileid"] and same["etag"] if decide == "etag-only" else all(same.values())
    if not ok:
        print(f"PUBLISH REFUSED ({decide}): the canonical copy changed since checkout"); return 1
    if dry:
        print(f"PUBLISH WOULD PROCEED ({decide}): the copy looks fresh"); return 0
    body = open(os.path.join(WORK, name), "rb").read()
    st, h, _ = req("PUT", _dav(s, rec["path"]), body, {"Authorization": auth_header(s), "If-Match": rec["etag"]})
    print(f"PUBLISH PUT with If-Match {rec['etag']}: HTTP {st}; new etag {h.get('etag')}")
    return 0 if st in (200, 201, 204) else 1


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["checkout"]:
        checkout(a[1])
    elif a[:1] == ["publish"]:
        sys.exit(publish(a[1], a[a.index("--decide") + 1] if "--decide" in a else "full", "--dry-run" in a))
    elif a[:1] == ["edit"]:      # the author's edit in ONLYOFFICE, simulated
        p = os.path.join(WORK, a[1]); open(p, "ab").write(b"\nauthor edit " + time.strftime("%T").encode() + b"\n")
        print(f"edited {p}")
    else:
        print(__doc__)
