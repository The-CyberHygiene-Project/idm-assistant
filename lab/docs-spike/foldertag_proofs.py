"""foldertag_proofs.py (RUNS ON THE MAC, python3 -I, over the spike.sh tunnel): ISO 0.7.0 Plan 2 Task 3 lab test of
chp_foldertag 1.0 (owner decision 3: copy/move out of CUI, FCI, Archive refused, except CUI <-> Archive). Same
WebDAV endpoints the browser uses, as lab01 (cui-users + chp-users), app password ~/idm-lab-secrets/docs-lab01-app.txt
(never printed). argv: ROOT_CA FILES_PORT STAGE
  main        renames / subfolder moves inside CUI, CUI <-> Archive (files and folders, move and copy), refusals
              (403, nothing created) to FCI / Operations / home, into-containment moves, trash restore and version
              restore across folders; every surviving file must carry the CUI tag
  failclosed  run while app config "contain" is invalid JSON: CUI -> Archive refused, rename inside CUI allowed
Lab folder ids: 1 CUI, 2 FCI, 3 Archive, 4 Operations; tag 1 = CUI (rules {"1":"1","2":"2"}; Archive has NO rule, so
a CUI file in Archive is tagged only because its tag travels with it)."""
import base64
import http.client
import os
import socket
import ssl
import sys
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

FILES = "files.docs.lab.test"
CA, PORT, STAGE = sys.argv[1], int(sys.argv[2]), sys.argv[3]
CTX = ssl.create_default_context(cafile=CA)
U = "lab01"
OC, NC, D = "{http://owncloud.org/ns}", "{http://nextcloud.org/ns}", "{DAV:}"
SECRET = open(os.path.expanduser(f"~/idm-lab-secrets/docs-{U}-app.txt")).read().strip()
fails = 0


def req(method, path, body=None, headers=None):
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=CTX, timeout=60)
    c.sock = CTX.wrap_socket(socket.create_connection(("127.0.0.1", PORT), 60), server_hostname=FILES)
    h = {"Host": f"{FILES}:8443", "Authorization": "Basic " + base64.b64encode(f"{U}:{SECRET}".encode()).decode(),
         "OCS-APIRequest": "true", "User-Agent": "CHP foldertag 1.0 lab test"}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    return r.status, r.read()


def dav(p):
    return f"/remote.php/dav/files/{U}/" + urllib.parse.quote(p)


def dest(path, overwrite="F"):
    h = {"Destination": f"https://{FILES}:8443" + path}
    if overwrite:
        h["Overwrite"] = overwrite
    return h


def check(name, ok, detail=""):
    global fails
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
    fails += 0 if ok else 1


def put(p, data):
    return req("PUT", dav(p), data)[0]


def mkcol(p):
    return req("MKCOL", dav(p))[0]


def exists(p):
    return req("PROPFIND", dav(p), None, {"Depth": "0"})[0] == 207


def fileid(p):
    body = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>'
    st, data = req("PROPFIND", dav(p), body, {"Depth": "0", "Content-Type": "application/xml"})
    e = ET.fromstring(data).find(f".//{OC}fileid") if st == 207 else None
    return e.text if e is not None else None


def tags(p):
    fid = fileid(p)
    if fid is None:
        return None
    body = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:display-name/></d:prop></d:propfind>'
    st, data = req("PROPFIND", f"/remote.php/dav/systemtags-relations/files/{fid}", body, {"Depth": "1", "Content-Type": "application/xml"})
    return sorted(e.text for e in ET.fromstring(data).iter(f"{OC}display-name") if e.text) if st == 207 else None


def mv(verb, src, dst):
    return req(verb, dav(src), headers=dest(dav(dst)))[0]


known = 0
GUARD = (403, 500)   # folder guard refusal: 403, or 500 "Failed to rename" for a rename inside the same parent


def allowed(verb, src, dst, files=("",), guarded=False):
    """verb src -> dst must succeed and every file at/below dst (rel paths in files) must carry CUI. guarded=True: the
    move hits the folder guard while the database refuses MD5 (FIPS PostgreSQL; NextCloud moves a folder's children,
    or a team-folder file's versions folder, with SQL MD5()) and must instead be refused with nothing changed and the
    source still tagged. Allowed and tagged, or refused, never untagged. Returns where the item now is."""
    global known
    st = mv(verb, src, dst)
    if guarded and st != 201:
        tg = {f: tags(src + ("/" + f if f else "")) for f in files}
        ok = st in GUARD and not exists(dst) and all(t is not None and "CUI" in t for t in tg.values())
        check(f"{verb} {src} -> {dst} refused by the folder guard (database MD5 unavailable), source whole and tagged", ok,
              f"HTTP {st}; target exists {exists(dst)}; source tags {tg}")
        known += 1 if ok else 0
        return src
    tg = {f: tags(dst + ("/" + f if f else "")) for f in files}
    check(f"{verb} {src} -> {dst} allowed and tagged", st in (201, 204) and all(t is not None and "CUI" in t for t in tg.values()),
          f"HTTP {st}; tags {tg}")
    return dst


def refused(verb, src, dst):
    st = mv(verb, src, dst)
    there = exists(dst)
    check(f"{verb} {src} -> {dst} refused, nothing created", st == 403 and not there and exists(src),
          f"HTTP {st}; target exists {there}")


def trash_items():
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:nc="http://nextcloud.org/ns"><d:prop>'
            '<nc:trashbin-original-location/><nc:trashbin-filename/></d:prop></d:propfind>')
    st, data = req("PROPFIND", f"/remote.php/dav/trashbin/{U}/trash/", body, {"Depth": "1", "Content-Type": "application/xml"})
    out = {}
    for r in ET.fromstring(data).iter(f"{D}response") if st == 207 else []:
        loc = r.find(f".//{NC}trashbin-original-location")
        if loc is not None and loc.text:
            out[loc.text] = r.find(f"{D}href").text
    return out


def restore(original):
    items = trash_items()
    href = items.get(original) or items.get(original + "/")
    if href is None:
        return None
    return req("MOVE", href, headers=dest(f"/remote.php/dav/trashbin/{U}/restore/" + href.rstrip("/").split("/")[-1], None))[0]


def versions(p):
    st, data = req("PROPFIND", f"/remote.php/dav/versions/{U}/versions/{fileid(p)}", None, {"Depth": "1"})
    hrefs = [e.text for e in ET.fromstring(data).iter(f"{D}href")] if st == 207 else []
    return sorted(h for h in hrefs if not h.rstrip("/").endswith(f"/versions/{fileid(p)}"))


n = uuid.uuid4().hex[:6]
if STAGE == "main":
    print(f"run {n}: lab01; contain [1,2,3], contain_allow [[1,3],[3,1]], rules CUI->tag CUI, FCI->tag FCI")
    # 1. rename and subfolder moves inside CUI
    put(f"CUI/ren-{n}.txt", b"rename test\n")
    ren = allowed("MOVE", f"CUI/ren-{n}.txt", f"CUI/ren-{n}-renamed.txt")
    mkcol(f"CUI/sub-{n}"); mkcol(f"CUI/sub-{n}/deep"); put(f"CUI/sub-{n}/in-sub.txt", b"in sub\n")
    put(f"CUI/mv-{n}.txt", b"subfolder move\n")
    allowed("MOVE", f"CUI/mv-{n}.txt", f"CUI/sub-{n}/deep/mv.txt")
    FS = ("in-sub.txt", "deep/mv.txt")
    sub = allowed("MOVE", f"CUI/sub-{n}", f"CUI/sub-{n}-renamed", files=FS, guarded=True)
    allowed("MOVE", f"CUI/sub-{n}", f"CUI/sub2-{n}/moved-sub", files=FS, guarded=True) if mkcol(f"CUI/sub2-{n}") == 201 else None
    cpy = allowed("COPY", sub, f"CUI/sub-{n}-copy", files=FS)
    # control, no rules involved: a folder rename in Operations hits the same guard
    mkcol(f"Operations/ctl-{n}"); put(f"Operations/ctl-{n}/f.txt", b"control\n")
    st = mv("MOVE", f"Operations/ctl-{n}", f"Operations/ctl-{n}-renamed")
    check("CONTROL folder rename in Operations (no rule, not contained): refused by the folder guard too",
          st in GUARD and exists(f"Operations/ctl-{n}/f.txt") and not exists(f"Operations/ctl-{n}-renamed"), f"HTTP {st}")
    # 2. CUI <-> Archive (owner decision 3), files and folders
    put(f"CUI/arc-{n}.txt", b"to archive and back\n")
    arc = allowed("MOVE", f"CUI/arc-{n}.txt", f"Archive/arc-{n}.txt")
    allowed("MOVE", arc, f"CUI/arc-{n}-back.txt")
    put(f"CUI/cpy-{n}.txt", b"copy to archive\n")
    acp = allowed("COPY", f"CUI/cpy-{n}.txt", f"Archive/cpy-{n}.txt")
    allowed("COPY", acp, f"CUI/cpy-{n}-from-archive.txt")
    adir = allowed("MOVE", cpy, f"Archive/dir-{n}", files=FS, guarded=True)
    allowed("COPY", sub, f"Archive/dir-{n}-copy", files=FS)
    allowed("COPY", f"Archive/dir-{n}-copy", f"CUI/dir-{n}-back", files=FS)
    # 3. refusals: out of the set, and between set members other than CUI <-> Archive
    put(f"FCI/fci-{n}.txt", b"FCI file\n")
    for verb, src, dst in (("MOVE", ren, f"FCI/x-{n}.txt"), ("COPY", ren, f"FCI/x-{n}.txt"),
                           ("MOVE", ren, f"Operations/x-{n}.txt"), ("COPY", ren, f"Operations/x-{n}.txt"),
                           ("MOVE", ren, f"x-home-{n}.txt"), ("COPY", ren, f"x-home-{n}.txt"),
                           ("MOVE", sub, f"Operations/dir-{n}"), ("COPY", sub, f"dir-home-{n}"),
                           ("MOVE", acp, f"FCI/y-{n}.txt"), ("COPY", acp, f"Operations/y-{n}.txt"),
                           ("MOVE", acp, f"y-home-{n}.txt"),
                           ("MOVE", f"FCI/fci-{n}.txt", f"CUI/z-{n}.txt"), ("COPY", f"FCI/fci-{n}.txt", f"Archive/z-{n}.txt"),
                           ("MOVE", f"FCI/fci-{n}.txt", f"Operations/z-{n}.txt"), ("COPY", f"FCI/fci-{n}.txt", f"z-home-{n}.txt")):
        refused(verb, src, dst)
    # 4. into containment is allowed and tagged
    put(f"Operations/in-{n}.txt", b"ops to cui\n"); put(f"home-in-{n}.txt", b"home to cui\n")
    allowed("MOVE", f"Operations/in-{n}.txt", f"CUI/in-ops-{n}.txt")
    allowed("COPY", f"home-in-{n}.txt", f"CUI/in-home-{n}.txt")
    # 5. trash restore across folders
    put(f"CUI/tr-{n}.txt", b"trash in CUI\n")
    st = req("DELETE", dav(f"CUI/tr-{n}.txt"))[0]
    check("DELETE a CUI file (to the team folder trash) works", st == 204, f"HTTP {st}")
    st = restore(f"CUI/tr-{n}.txt")
    check("trash restore of a CUI file: back in CUI and tagged", st in (201, 204) and "CUI" in (tags(f"CUI/tr-{n}.txt") or []),
          f"HTTP {st}; tags {tags(f'CUI/tr-{n}.txt')}")
    put(f"CUI/tra-{n}.txt", b"trash in Archive\n"); mv("MOVE", f"CUI/tra-{n}.txt", f"Archive/tra-{n}.txt")
    req("DELETE", dav(f"Archive/tra-{n}.txt"))
    st = restore(f"Archive/tra-{n}.txt")
    check("trash restore of a CUI file deleted in Archive: back in Archive and still tagged",
          st in (201, 204) and "CUI" in (tags(f"Archive/tra-{n}.txt") or []), f"HTTP {st}; tags {tags(f'Archive/tra-{n}.txt')}")
    put(f"CUI/trd-{n}.txt", b"restore elsewhere\n"); req("DELETE", dav(f"CUI/trd-{n}.txt"))
    href = trash_items().get(f"CUI/trd-{n}.txt")
    st = req("MOVE", href, headers=dest(dav(f"Operations/trd-{n}.txt")))[0] if href else None
    check("trash item MOVEd straight to Operations (restore elsewhere): refused, not created", st == 403 and not exists(f"Operations/trd-{n}.txt"), f"HTTP {st}")
    st = req("COPY", href, headers=dest(dav(f"trd-home-{n}.txt")))[0] if href else None
    check("trash item COPYed straight to home: refused, not created", st == 403 and not exists(f"trd-home-{n}.txt"), f"HTTP {st}")
    st = restore(f"CUI/trd-{n}.txt")
    check("and the normal restore still works, tagged", st in (201, 204) and "CUI" in (tags(f"CUI/trd-{n}.txt") or []), f"HTTP {st}")
    mkcol(f"CUI/trdir-{n}"); put(f"CUI/trdir-{n}/f.txt", b"folder in trash\n")
    st = req("DELETE", dav(f"CUI/trdir-{n}"))[0]
    check("DELETE a CUI folder with contents: refused by the folder guard, folder and file intact and tagged",
          st == 403 and exists(f"CUI/trdir-{n}/f.txt") and "CUI" in (tags(f"CUI/trdir-{n}/f.txt") or []), f"HTTP {st}")
    req("DELETE", dav(f"CUI/trdir-{n}/f.txt")); st = req("DELETE", dav(f"CUI/trdir-{n}"))[0]
    check("... after its file is deleted, the empty folder deletes", st == 204, f"HTTP {st}")
    st1 = restore(f"CUI/trdir-{n}"); st2 = restore(f"CUI/trdir-{n}/f.txt")
    check("restore the empty folder, then its file: back in CUI and tagged",
          st1 in (201, 204) and st2 in (201, 204) and "CUI" in (tags(f"CUI/trdir-{n}/f.txt") or []),
          f"HTTP {st1}, {st2}; tags {tags(f'CUI/trdir-{n}/f.txt')}")
    # 6. version restore across folders
    put(f"CUI/ver-{n}.txt", b"version ONE\n"); time.sleep(1.5); put(f"CUI/ver-{n}.txt", b"version TWO\n")   # versions are per second
    print(f"  CUI/ver-{n}.txt has {len(versions(f'CUI/ver-{n}.txt'))} version entries (oldest first)")
    allowed("MOVE", f"CUI/ver-{n}.txt", f"Archive/ver-{n}.txt", guarded=True)
    put(f"CUI/verA-{n}.txt", b"A one\n"); mv("MOVE", f"CUI/verA-{n}.txt", f"Archive/verA-{n}.txt"); time.sleep(1.5); put(f"Archive/verA-{n}.txt", b"A two\n")
    for p, old in ((f"CUI/ver-{n}.txt", b"version ONE\n"), (f"Archive/verA-{n}.txt", b"A one\n")):
        vs = versions(p)
        st = req("MOVE", vs[0], headers=dest(dav(f"Operations/ver-{n}-old.txt")))[0] if vs else None
        check(f"old version of {p} MOVEd straight to Operations: refused, not created", st == 403 and not exists(f"Operations/ver-{n}-old.txt"), f"HTTP {st}")
        st = req("MOVE", vs[0], headers=dest(f"/remote.php/dav/versions/{U}/restore/target", None))[0] if vs else None
        body = req("GET", dav(p))[1]
        check(f"version restore of {p}: old content back and tagged", st in (201, 204) and body == old and "CUI" in (tags(p) or []),
              f"{len(vs)} version(s); HTTP {st}; content {body!r}; tags {tags(p)}")
if STAGE == "failclosed":
    put(f"CUI/fc-{n}.txt", b"fail closed\n")
    refused("MOVE", f"CUI/fc-{n}.txt", f"Archive/fc-{n}.txt")
    refused("COPY", f"CUI/fc-{n}.txt", f"Operations/fc-{n}.txt")
    allowed("MOVE", f"CUI/fc-{n}.txt", f"CUI/fc-{n}-renamed.txt")
    put(f"Operations/fc-ops-{n}.txt", b"ops\n")
    st = mv("MOVE", f"Operations/fc-ops-{n}.txt", f"Archive/fc-ops-{n}.txt")
    check("policy unreadable: a move out of Operations (any team folder) refused too", st == 403, f"HTTP {st}")
print(f"{STAGE} {n}: {'ALL PASS' if not fails else str(fails) + ' FAIL'}" + (f" ({known} moves refused by the folder guard: database MD5 unavailable)" if known else ""))
sys.exit(1 if fails else 0)
