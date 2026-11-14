"""proofs.py (RUNS ON THE MAC, python3 -I, over an SSH tunnel to iso5-srv:8443): ISO 0.7.0 Plan 2 Task 9 product proofs
of the NextCloud server role, as the lab users, through the same WebDAV and OCS endpoints the browser uses. Based on
lab/docs-spike/proofs.py (made product: iso5 names, the six team folders, containment, DavGuard, FolderGuard).
Auth = each user's app password (~/idm-lab-secrets/iso5-nc-<u>-app.txt, made by occ user:auth-tokens:add; never printed).
argv: ROOT_CA FILES_PORT STAGE [RUN_ID]
Users: lab01 cui-users; lab02 plain; lab03 doc-reviewers only; lab04 doc-reviewers + cui-users."""
import base64
import http.client
import json
import os
import socket
import ssl
import sys
import unicodedata
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

FILES = "files.iso5.lab.test"
CA, PORT, STAGE = sys.argv[1], int(sys.argv[2]), sys.argv[3]
RUN = sys.argv[4] if len(sys.argv) > 4 else uuid.uuid4().hex[:6]
CTX = ssl.create_default_context(cafile=CA)
OC = "{http://owncloud.org/ns}"
fails = 0


def secret(u):
    return open(os.path.expanduser(f"~/idm-lab-secrets/iso5-nc-{u}-app.txt")).read().strip()


def req(user, method, path, body=None, headers=None):
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=CTX, timeout=120)
    c.sock = CTX.wrap_socket(socket.create_connection(("127.0.0.1", PORT), 60), server_hostname=FILES)
    h = {"Host": f"{FILES}:8443", "Authorization": "Basic " + base64.b64encode(f"{user}:{secret(user)}".encode()).decode(),
         "OCS-APIRequest": "true", "User-Agent": "CHP plan2 proofs"}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    return r.status, r.read()


def check(name, ok, detail=""):
    global fails
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
    fails += 0 if ok else 1


def dav(u, p):
    return f"/remote.php/dav/files/{u}/" + urllib.parse.quote(p)


def put(u, p, data):
    return req(u, "PUT", dav(u, p), data)[0]


def mkcol(u, p):
    return req(u, "MKCOL", dav(u, p))[0]


def dest(u, p):
    return {"Destination": f"https://{FILES}:8443" + dav(u, p), "Overwrite": "F"}


def mv(u, src, tgt):
    return req(u, "MOVE", dav(u, src), headers=dest(u, tgt))[0]


def cp(u, src, tgt):
    return req(u, "COPY", dav(u, src), headers=dest(u, tgt))[0]


def exists(u, p):
    return req(u, "PROPFIND", dav(u, p), None, {"Depth": "0"})[0] == 207


def chunked(u, p, data, size=5 * 1024 * 1024):
    """the web UI's upload: chunking v2 (MKCOL uploads/<u>/<id>, PUT chunks, MOVE .file to the target)"""
    up = f"/remote.php/dav/uploads/{u}/web-file-upload-{uuid.uuid4().hex}"
    d = f"https://{FILES}:8443" + dav(u, p)
    s1 = req(u, "MKCOL", up, headers={"Destination": d})[0]
    for i in range(0, max(len(data), 1), size):
        req(u, "PUT", f"{up}/{i // size + 1:05d}", data[i:i + size], {"Destination": d, "OC-Total-Length": str(len(data))})
    return s1, req(u, "MOVE", f"{up}/.file", headers={"Destination": d, "OC-Total-Length": str(len(data))})[0]


def fileid(u, p):
    body = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>'
    st, data = req(u, "PROPFIND", dav(u, p), body, {"Depth": "0", "Content-Type": "application/xml"})
    if st != 207:
        return None
    e = ET.fromstring(data).find(f".//{OC}fileid")
    return e.text if e is not None else None


def listing(u, p=""):
    st, data = req(u, "PROPFIND", dav(u, p), None, {"Depth": "1"})
    if st != 207:
        return st, []
    hrefs = [urllib.parse.unquote(e.text) for e in ET.fromstring(data).iter("{DAV:}href")]
    base = urllib.parse.unquote(dav(u, p))
    return st, sorted(h[len(base):].strip("/") for h in hrefs if h.rstrip("/") != base.rstrip("/"))


def share(u, p, stype, to=None):
    f = {"path": "/" + p, "shareType": str(stype), "permissions": "1"}
    if to:
        f["shareWith"] = to
    if stype == 3:
        f["password"] = "Lab-Link-" + uuid.uuid4().hex[:12] + "-x9"   # policy: links need a password (not a real secret)
    st, data = req(u, "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json", urllib.parse.urlencode(f),
                   {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        m = json.loads(data)["ocs"]["meta"]
        return st, m.get("statuscode"), m.get("message")
    except Exception:
        return st, None, data[:160]


def tags_of(u, fid):
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>'
            '<oc:display-name/></d:prop></d:propfind>')
    st, data = req(u, "PROPFIND", f"/remote.php/dav/systemtags-relations/files/{fid}", body,
                   {"Depth": "1", "Content-Type": "application/xml"})
    if st != 207:
        return []
    return sorted(e.text for e in ET.fromstring(data).iter(f"{OC}display-name") if e.text)


def tags(u, p):
    fid = fileid(u, p)
    return tags_of(u, fid) if fid else None


def trash(u):
    """[(href, original-location)] in the user's trash"""
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:nc="http://nextcloud.org/ns"><d:prop>'
            '<nc:trashbin-original-location/></d:prop></d:propfind>')
    st, data = req(u, "PROPFIND", f"/remote.php/dav/trashbin/{u}/trash", body, {"Depth": "1", "Content-Type": "application/xml"})
    out = []
    if st == 207:
        for r in ET.fromstring(data).iter("{DAV:}response"):
            loc = r.find(".//{http://nextcloud.org/ns}trashbin-original-location")
            if loc is not None and loc.text:
                out.append((r.find("{DAV:}href").text, loc.text))
    return out


def versions(u, fid):
    st, data = req(u, "PROPFIND", f"/remote.php/dav/versions/{u}/versions/{fid}", None, {"Depth": "1"})
    if st != 207:
        return []
    return [e.text for e in ET.fromstring(data).iter("{DAV:}href") if not e.text.rstrip("/").endswith(f"/{fid}")]


H = f"https://{FILES}:8443"
R = RUN
if STAGE == "upload":
    check("lab01 WebDAV PUT CUI file", put("lab01", f"CUI/CUI_webdav-{R}_v1.0.txt", b"CUI test file (plan2)\n") in (201, 204))
    s1, s2 = chunked("lab01", f"CUI/browser-{R}.docx", b"PK\x03\x04" + b"plan2 docx stand-in " * 2000)
    check("lab01 browser-style chunked upload into CUI", s1 == 201 and s2 in (201, 204), f"MKCOL {s1}, MOVE {s2}")
    check("lab01 WebDAV PUT FCI file", put("lab01", f"FCI/fci-{R}.md", b"# FCI note\n") in (201, 204))
    check("lab01 WebDAV PUT Archive file", put("lab01", f"Archive/arch-{R}.txt", b"archive\n") in (201, 204))
    check("lab01 WebDAV PUT Operations file", put("lab01", f"Operations/ops-{R}.txt", b"ops\n") in (201, 204))
    nfc = unicodedata.normalize("NFC", f"CUI/Résumé-ü-{R}-nfc.txt"); nfd = unicodedata.normalize("NFD", f"CUI/Résumé-ü-{R}-nfd.txt")
    check("lab01 PUT non-ASCII NFC name into CUI", put("lab01", nfc, b"nfc\n") in (201, 204))
    check("lab01 PUT non-ASCII NFD name into CUI", put("lab01", nfd, b"nfd\n") in (201, 204))
    for p, want in ((f"CUI/CUI_webdav-{R}_v1.0.txt", ["CUI"]), (f"CUI/browser-{R}.docx", ["CUI"]), (f"FCI/fci-{R}.md", ["FCI"]),
                    (f"Archive/arch-{R}.txt", ["CUI"]), (f"Operations/ops-{R}.txt", []), (nfc, ["CUI"]),
                    (unicodedata.normalize("NFC", nfd), ["CUI"])):
        t = tags("lab01", p); check(f"tag on {p}", t == want, f"tags {t}")
    fid = fileid("lab01", f"CUI/browser-{R}.docx")
    st = req("lab01", "DELETE", f"/remote.php/dav/systemtags-relations/files/{fid}/" + os.environ.get("CUI_TAG_ID", "1"))[0]
    check("lab01 cannot remove the CUI tag (restricted tag)", st in (403, 404), f"DELETE -> {st}")
    check("CUI tag still on the file afterwards", tags_of("lab01", fid) == ["CUI"])
elif STAGE == "share":
    put("lab01", f"CUI/CUI_share-{R}.txt", b"share test\n"); put("lab01", f"FCI/fci-share-{R}.txt", b"fci\n")
    put("lab01", f"Archive/arch-share-{R}.txt", b"arch\n"); put("lab01", f"Operations/ops-share-{R}.txt", b"ops\n")
    for p, to, st_, what in ((f"CUI/CUI_share-{R}.txt", "lab02", 0, "internal share of a CUI file to lab02"),
                             (f"CUI/CUI_share-{R}.txt", "lab04", 0, "internal share of a CUI file to lab04 (cui-users)"),
                             (f"CUI/CUI_share-{R}.txt", None, 3, "public link on a CUI file"),
                             (f"FCI/fci-share-{R}.txt", None, 3, "public link on an FCI file"),
                             (f"FCI/fci-share-{R}.txt", "lab02", 0, "internal share of an FCI file"),
                             (f"Archive/arch-share-{R}.txt", None, 3, "public link on an Archive file"),
                             ("CUI", "lab02", 0, "internal share of the CUI folder itself")):
        st, code, msg = share("lab01", p, st_, to)
        check(f"{what} REFUSED", code not in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
    st, code, msg = share("lab01", f"Operations/ops-share-{R}.txt", 0, "lab02")
    check("control: internal share of an Operations file to lab02 ALLOWED", code in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
    st, code, msg = share("lab01", f"Operations/ops-share-{R}.txt", 3)
    check("control: public link (with password) on an Operations file ALLOWED", code in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
elif STAGE == "see":
    put("lab01", f"CUI/CUI_see-{R}.txt", b"CUI test file\n"); put("lab01", f"Operations/ops-see-{R}.txt", b"ops\n")
    st, l3 = listing("lab03"); print(f"  lab03 (doc-reviewers, NOT cui-users) sees: {l3}")
    check("lab03 sees no CUI/FCI/Archive, sees Operations", not {"CUI", "FCI", "Archive"} & set(l3) and "Operations" in l3)
    check("lab03 cannot read the CUI file by path", req("lab03", "GET", dav("lab03", f"CUI/CUI_see-{R}.txt"))[0] == 404)
    check("lab03 reads Operations", req("lab03", "GET", dav("lab03", f"Operations/ops-see-{R}.txt"))[0] == 200)
    check("lab03 writes in Operations (owner decision 7: normal access outside CUI/FCI/Archive)",
          put("lab03", f"Operations/reviewer-{R}.txt", b"x") in (201, 204))
    st, l2 = listing("lab02"); print(f"  lab02 (plain user) sees: {l2}")
    check("lab02 sees no CUI/FCI/Archive", not {"CUI", "FCI", "Archive"} & set(l2) and "Operations" in l2)
    st, l4 = listing("lab04"); print(f"  lab04 (doc-reviewers + cui-users) sees: {l4}")
    check("lab04 sees CUI, FCI, Archive", {"CUI", "FCI", "Archive"} <= set(l4))
    st, data = req("lab04", "GET", dav("lab04", f"CUI/CUI_see-{R}.txt"))
    check("lab04 reads (downloads) the CUI file", st == 200 and data.startswith(b"CUI test file"), f"GET {st}")
    check("lab04 cannot change the CUI file", put("lab04", f"CUI/CUI_see-{R}.txt", b"changed") in (403, 404), "PUT")
    check("lab04 cannot add a file to CUI", put("lab04", f"CUI/reviewer-{R}.txt", b"x") in (403, 404), "PUT new")
    check("lab04 cannot delete the CUI file", req("lab04", "DELETE", dav("lab04", f"CUI/CUI_see-{R}.txt"))[0] in (403, 404))
    check("lab04 cannot add a file to FCI or Archive", put("lab04", f"FCI/r-{R}.txt", b"x") in (403, 404)
          and put("lab04", f"Archive/r-{R}.txt", b"x") in (403, 404))
    check("lab04 writes in Operations", put("lab04", f"Operations/r4-{R}.txt", b"x") in (201, 204))
    check("CUI file unchanged afterwards", req("lab01", "GET", dav("lab01", f"CUI/CUI_see-{R}.txt"))[1].startswith(b"CUI test file"))
elif STAGE == "contain":
    put("lab01", f"CUI/CUI_c-{R}.txt", b"CUI containment test\n")
    for verb, tgt in (("COPY", f"FCI/c-{R}.txt"), ("MOVE", f"FCI/m-{R}.txt"), ("COPY", f"Operations/c-{R}.txt"),
                      ("MOVE", f"Operations/m-{R}.txt"), ("COPY", f"home-c-{R}.txt"), ("MOVE", f"home-m-{R}.txt"),
                      ("COPY", f"Public/c-{R}.txt"), ("COPY", f"Internal/c-{R}.txt")):
        st = (cp if verb == "COPY" else mv)("lab01", f"CUI/CUI_c-{R}.txt", tgt)
        check(f"{verb} CUI file -> {tgt.split('/')[0] if '/' in tgt else 'home'} REFUSED (403, nothing created)",
              st == 403 and not exists("lab01", tgt), f"HTTP {st}, target exists {exists('lab01', tgt)}")
    check("source still in CUI and tagged", tags("lab01", f"CUI/CUI_c-{R}.txt") == ["CUI"])
    # FCI -> Operations also contained
    put("lab01", f"FCI/f-{R}.txt", b"fci\n")
    st = cp("lab01", f"FCI/f-{R}.txt", f"Operations/f-{R}.txt")
    check("COPY FCI file -> Operations REFUSED", st == 403 and not exists("lab01", f"Operations/f-{R}.txt"), f"HTTP {st}")
    st = mv("lab01", f"FCI/f-{R}.txt", f"CUI/f-{R}.txt")
    check("MOVE FCI file -> CUI REFUSED (only CUI<->Archive allowed)", st == 403, f"HTTP {st}")
    # CUI <-> Archive allowed and tagged
    st = cp("lab01", f"CUI/CUI_c-{R}.txt", f"Archive/CUI_c-copy-{R}.txt")
    check("COPY CUI file -> Archive ALLOWED, copy tagged CUI", st in (201, 204) and tags("lab01", f"Archive/CUI_c-copy-{R}.txt") == ["CUI"],
          f"HTTP {st}, tags {tags('lab01', f'Archive/CUI_c-copy-{R}.txt')}")
    put("lab01", f"CUI/CUI_mv-{R}.txt", b"move me\n")
    st = mv("lab01", f"CUI/CUI_mv-{R}.txt", f"Archive/CUI_mv-{R}.txt")
    check("MOVE CUI file (no old versions) -> Archive ALLOWED, tagged CUI", st in (201, 204) and tags("lab01", f"Archive/CUI_mv-{R}.txt") == ["CUI"],
          f"HTTP {st}, tags {tags('lab01', f'Archive/CUI_mv-{R}.txt')}")
    st = mv("lab01", f"Archive/CUI_mv-{R}.txt", f"CUI/CUI_back-{R}.txt")
    check("MOVE Archive file -> CUI ALLOWED, tagged CUI", st in (201, 204) and tags("lab01", f"CUI/CUI_back-{R}.txt") == ["CUI"], f"HTTP {st}")
    # folder copy (with a subfolder) CUI -> Archive: every copy carries the CUI tag
    mkcol("lab01", f"CUI/Proj-{R}"); mkcol("lab01", f"CUI/Proj-{R}/Sub")
    put("lab01", f"CUI/Proj-{R}/a.txt", b"a\n"); put("lab01", f"CUI/Proj-{R}/Sub/b.txt", b"b\n")
    st = cp("lab01", f"CUI/Proj-{R}", f"Archive/Proj-{R}")
    # by design (chp_foldertag README): FILES are tagged; folders are walked, not tagged
    ta = [tags("lab01", f"Archive/Proj-{R}/{x}") for x in ("a.txt", "Sub/b.txt")]
    check("COPY CUI folder with a subfolder -> Archive ALLOWED, every file in the copy tagged CUI", st in (201, 204) and all(t == ["CUI"] for t in ta),
          f"HTTP {st}, file tags {ta}; folder tags {[tags('lab01', f'Archive/Proj-{R}/{x}') for x in ('', 'Sub')]}")
    st = cp("lab01", f"CUI/Proj-{R}", f"Operations/Proj-{R}")
    check("COPY CUI folder -> Operations REFUSED, nothing created", st == 403 and not exists("lab01", f"Operations/Proj-{R}"), f"HTTP {st}")
elif STAGE == "inside":
    # rename and subfolder moves inside CUI keep the tag
    put("lab01", f"CUI/CUI_r-{R}.txt", b"rename me\n")
    st = mv("lab01", f"CUI/CUI_r-{R}.txt", f"CUI/CUI_r2-{R}.txt")
    check("rename a file inside CUI ALLOWED, tag kept", st in (201, 204) and tags("lab01", f"CUI/CUI_r2-{R}.txt") == ["CUI"], f"HTTP {st}")
    check("make a subfolder in CUI (folders are not tagged, by design)", mkcol("lab01", f"CUI/Sub-{R}") == 201,
          f"folder tags {tags('lab01', f'CUI/Sub-{R}')}")
    st = mv("lab01", f"CUI/CUI_r2-{R}.txt", f"CUI/Sub-{R}/CUI_r2-{R}.txt")
    check("move a file into a CUI subfolder ALLOWED, tag kept", st in (201, 204) and tags("lab01", f"CUI/Sub-{R}/CUI_r2-{R}.txt") == ["CUI"], f"HTTP {st}")
    mkcol("lab01", f"CUI/Empty-{R}")
    st = mv("lab01", f"CUI/Empty-{R}", f"CUI/Empty2-{R}")
    check("rename an EMPTY folder inside CUI ALLOWED", st in (201, 204), f"HTTP {st}")
    st = mv("lab01", f"CUI/Sub-{R}", f"CUI/Sub2-{R}")
    check("rename a NON-EMPTY folder inside CUI REFUSED while DEGRADED (FolderGuard), folder intact", st in (403, 500) and exists("lab01", f"CUI/Sub-{R}/CUI_r2-{R}.txt")
          and not exists("lab01", f"CUI/Sub2-{R}"), f"HTTP {st}" + (" (DEFECT D7: 500, not 403)" if st == 500 else ""))
    st = req("lab01", "DELETE", dav("lab01", f"CUI/Sub-{R}"))[0]
    check("delete a NON-EMPTY folder REFUSED while DEGRADED (FolderGuard)", st == 403 and exists("lab01", f"CUI/Sub-{R}"), f"HTTP {st}")
    st = req("lab01", "DELETE", dav("lab01", f"CUI/Empty2-{R}"))[0]
    check("delete an EMPTY folder ALLOWED", st in (204,), f"HTTP {st}")
elif STAGE == "trash":
    p = f"CUI/CUI_t-{R}.txt"
    put("lab01", p, b"v1\n"); fid = fileid("lab01", p)
    st = req("lab01", "DELETE", dav("lab01", p))[0]
    items = [h for h, loc in trash("lab01") if loc.endswith(f"CUI_t-{R}.txt")]
    check("delete a CUI file -> in lab01's trash", st == 204 and len(items) == 1, f"HTTP {st}, trash {items}")
    if items:
        st = req("lab01", "MOVE", items[0], headers={"Destination": H + dav("lab01", f"Operations/from-trash-{R}.txt")})[0]
        check("DavGuard: MOVE trash item -> files path (Operations) REFUSED", st == 403 and not exists("lab01", f"Operations/from-trash-{R}.txt"), f"HTTP {st}")
        st = req("lab01", "COPY", items[0], headers={"Destination": H + dav("lab01", f"Operations/copy-trash-{R}.txt")})[0]
        check("DavGuard: COPY trash item -> files path REFUSED", st == 403 and not exists("lab01", f"Operations/copy-trash-{R}.txt"), f"HTTP {st}")
        st = req("lab01", "MOVE", items[0], headers={"Destination": H + f"/remote.php/dav/trashbin/lab01/restore/x"})[0]
        check("restore from trash (restore endpoint) -> back in CUI, same id, tag kept",
              st in (201, 204) and fileid("lab01", p) == fid and tags("lab01", p) == ["CUI"], f"HTTP {st}, id {fileid('lab01', p)} vs {fid}, tags {tags('lab01', p)}")
    __import__("time").sleep(2)   # versions are keyed by mtime (seconds): a change in the same second has no v1 to restore
    put("lab01", p, b"v2 changed\n")
    vs = versions("lab01", fid)
    check("an old version exists after the change", len(vs) >= 1, f"{len(vs)} versions")
    if vs:
        st = req("lab01", "COPY", vs[0], headers={"Destination": H + dav("lab01", f"Operations/from-version-{R}.txt")})[0]
        check("DavGuard: COPY old version -> files path REFUSED", st == 403 and not exists("lab01", f"Operations/from-version-{R}.txt"), f"HTTP {st}")
        v1 = next((v for v in vs if req("lab01", "GET", v)[1] == b"v1\n"), vs[0])
        st = req("lab01", "MOVE", v1, headers={"Destination": H + f"/remote.php/dav/versions/lab01/restore/target"})[0]
        body = req("lab01", "GET", dav("lab01", p))[1]
        check("version restore -> content v1, tag kept", st in (201, 204) and body == b"v1\n" and tags("lab01", p) == ["CUI"],
              f"HTTP {st}, body {body[:10]!r}, tags {tags('lab01', p)}")
    st = mv("lab01", p, f"Archive/CUI_t-{R}.txt")
    check("MOVE a CUI file WITH old versions -> Archive REFUSED while DEGRADED (FolderGuard), file intact", st in (403, 500) and exists("lab01", p)
          and not exists("lab01", f"Archive/CUI_t-{R}.txt"), f"HTTP {st}" + (" (DEFECT D7: 500, not 403)" if st == 500 else ""))
elif STAGE == "download":
    put("lab01", f"CUI/CUI_dl-{R}.txt", b"download me\n")
    st, data = req("lab01", "GET", dav("lab01", f"CUI/CUI_dl-{R}.txt"))
    check("download a CUI file (browser GET of the WebDAV URL)", st == 200 and data == b"download me\n", f"GET {st}")
    so = b"\x7fELF" + os.urandom(4096)
    check("upload a user .so into Operations", put("lab01", f"Operations/lib-{R}.so", so) in (201, 204))
    st, data = req("lab01", "GET", dav("lab01", f"Operations/lib-{R}.so"))
    check("download the user .so back unchanged (no fapolicyd 42-trusted-elf denial for php-fpm)", st == 200 and data == so, f"GET {st}")
elif STAGE == "hidden-setup":
    # a CUI folder with a child that lab01 cannot see (an ACL deny for lab01 on that child; occ sets it afterwards)
    mkcol("lab01", f"CUI/HidP-{R}"); put("lab01", f"CUI/HidP-{R}/visible.txt", b"v\n"); put("lab01", f"CUI/HidP-{R}/hidden.txt", b"h\n")
    mkcol("lab01", f"CUI/HidQ-{R}"); put("lab01", f"CUI/HidQ-{R}/hidden.txt", b"h\n")
    print("hidden-setup: made CUI/HidP-%s (visible.txt, hidden.txt) and CUI/HidQ-%s (hidden.txt)" % (R, R))
elif STAGE == "hidden":
    st, lq = listing("lab01", f"CUI/HidQ-{R}"); st2, lp = listing("lab01", f"CUI/HidP-{R}")
    check("ACL works: lab01 sees no hidden.txt", "hidden.txt" not in lq and "hidden.txt" not in lp, f"HidQ {lq}, HidP {lp}")
    st = mv("lab01", f"CUI/HidQ-{R}", f"CUI/HidQ2-{R}")
    check("FolderGuard counts the ACL-hidden child: rename of a folder that LOOKS empty REFUSED", st in (403, 500) and exists("lab01", f"CUI/HidQ-{R}"), f"HTTP {st}")
    st = req("lab01", "DELETE", dav("lab01", f"CUI/HidQ-{R}"))[0]
    check("FolderGuard: delete of a folder that LOOKS empty REFUSED", st == 403, f"HTTP {st}")
    st = cp("lab01", f"CUI/HidP-{R}", f"Archive/HidP-{R}")
    print(f"  COPY CUI/HidP-{R} -> Archive: HTTP {st}; lab01 sees in the copy {listing('lab01', f'Archive/HidP-{R}')[1]}")
    check("COPY folder with an ACL-hidden child -> Archive: copy + visible child tagged CUI", st in (201, 204)
          and tags("lab01", f"Archive/HidP-{R}") == ["CUI"] and tags("lab01", f"Archive/HidP-{R}/visible.txt") == ["CUI"], f"HTTP {st}")
print(f"{STAGE}: {'ALL PASS' if not fails else str(fails) + ' FAIL'}")
sys.exit(1 if fails else 0)
