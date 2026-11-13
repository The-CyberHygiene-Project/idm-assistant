"""proofs.py (RUNS ON THE MAC, python3 -I, over the spike.sh tunnel): Step 6 + 7 proofs as the lab users, through the same
WebDAV and OCS endpoints the browser uses. Auth = each user's app password (~/idm-lab-secrets/docs-<u>-app.txt; never
printed). argv: ROOT_CA FILES_PORT STAGE  (STAGE: upload | share | see | tags)."""
import base64
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

FILES = "files.docs.lab.test"
CA, PORT, STAGE = sys.argv[1], int(sys.argv[2]), sys.argv[3]
CTX = ssl.create_default_context(cafile=CA)
fails = 0


def secret(u):
    return open(os.path.expanduser(f"~/idm-lab-secrets/docs-{u}-app.txt")).read().strip()


def req(user, method, path, body=None, headers=None):
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=CTX, timeout=60)
    c.sock = CTX.wrap_socket(socket.create_connection(("127.0.0.1", PORT), 60), server_hostname=FILES)
    h = {"Host": f"{FILES}:8443", "Authorization": "Basic " + base64.b64encode(f"{user}:{secret(user)}".encode()).decode(),
         "OCS-APIRequest": "true", "User-Agent": "CHP spike proofs"}
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


def chunked(u, p, data, size=5 * 1024 * 1024):
    """the web UI's upload: chunking v2 (MKCOL uploads/<u>/<id>, PUT chunks, MOVE .file to the target)"""
    up = f"/remote.php/dav/uploads/{u}/web-file-upload-{uuid.uuid4().hex}"
    dest = f"https://{FILES}:8443" + dav(u, p)
    s1 = req(u, "MKCOL", up, headers={"Destination": dest})[0]
    for i in range(0, max(len(data), 1), size):
        req(u, "PUT", f"{up}/{i // size + 1:05d}", data[i:i + size], {"Destination": dest, "OC-Total-Length": str(len(data))})
    return s1, req(u, "MOVE", f"{up}/.file", headers={"Destination": dest, "OC-Total-Length": str(len(data))})[0]


def fileid(u, p):
    body = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>'
    st, data = req(u, "PROPFIND", dav(u, p), body, {"Depth": "0", "Content-Type": "application/xml"})
    if st != 207:
        return None
    e = ET.fromstring(data).find(".//{http://owncloud.org/ns}fileid")
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
        f["password"] = "Spike-Link-" + uuid.uuid4().hex[:12]   # policy: links need a password (not a real secret)
    st, data = req(u, "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json", urllib.parse.urlencode(f),
                   {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        m = json.loads(data)["ocs"]["meta"]
        return st, m.get("statuscode"), m.get("message")
    except Exception:
        return st, None, data[:120]


def tags_of(u, fid):
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>'
            '<oc:display-name/></d:prop></d:propfind>')
    st, data = req(u, "PROPFIND", f"/remote.php/dav/systemtags-relations/files/{fid}", body, {"Depth": "1", "Content-Type": "application/xml"})
    if st != 207:
        return st, []
    return st, sorted(e.text for e in ET.fromstring(data).iter("{http://owncloud.org/ns}display-name") if e.text)


DOCX = b"PK\x03\x04" + b"spike docx stand-in " * 2000
if STAGE == "upload":
    check("lab01 WebDAV PUT CUI/CUI_spike-webdav_v1.0.txt", put("lab01", "CUI/CUI_spike-webdav_v1.0.txt", b"CUI test file (spike)\n") in (201, 204))
    s1, s2 = chunked("lab01", "CUI/browser-upload.docx", DOCX)
    check("lab01 browser-style chunked upload CUI/browser-upload.docx", s1 == 201 and s2 in (201, 204), f"MKCOL {s1}, MOVE {s2}")
    check("lab01 WebDAV PUT FCI/fci-note.md", put("lab01", "FCI/fci-note.md", b"# FCI note\n") in (201, 204))
    s1, s2 = chunked("lab01", "FCI/browser-fci.xlsx", DOCX)
    check("lab01 browser-style chunked upload FCI/browser-fci.xlsx", s1 == 201 and s2 in (201, 204), f"MKCOL {s1}, MOVE {s2}")
    check("lab01 WebDAV PUT Operations/ops-plan.txt", put("lab01", "Operations/ops-plan.txt", b"ops\n") in (201, 204))
elif STAGE == "tags":
    for p, want in (("CUI/CUI_spike-webdav_v1.0.txt", ["CUI"]), ("CUI/browser-upload.docx", ["CUI"]),
                    ("FCI/fci-note.md", ["FCI"]), ("FCI/browser-fci.xlsx", ["FCI"]), ("Operations/ops-plan.txt", [])):
        fid = fileid("lab01", p); st, t = tags_of("lab01", fid)
        check(f"tag on {p} (file {fid})", t == want, f"tags {t}")
    fid = fileid("lab01", "CUI/browser-upload.docx")
    st = req("lab01", "DELETE", f"/remote.php/dav/systemtags-relations/files/{fid}/1")[0]
    check("lab01 cannot remove the CUI tag (restricted tag)", st in (403, 404), f"DELETE -> {st}")
    st, t = tags_of("lab01", fid); check("CUI tag still on the file afterwards", t == ["CUI"], f"tags {t}")
elif STAGE == "share":
    st, code, msg = share("lab01", "CUI/CUI_spike-webdav_v1.0.txt", 0, "lab02")
    check("internal share of a CUI file to lab02 (not cui-users) REFUSED", code not in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
    st, code, msg = share("lab01", "CUI/CUI_spike-webdav_v1.0.txt", 0, "lab04")
    check("internal share of a CUI file even to lab04 (cui-users) REFUSED", code not in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
    st, code, msg = share("lab01", "CUI/CUI_spike-webdav_v1.0.txt", 3)
    check("public link on a CUI file REFUSED", code not in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
    st, code, msg = share("lab01", "FCI/fci-note.md", 3)
    check("public link on an FCI file REFUSED", code not in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
    st, code, msg = share("lab01", "CUI", 0, "lab02")
    check("internal share of the CUI folder itself REFUSED", code not in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
    st, code, msg = share("lab01", "Operations/ops-plan.txt", 0, "lab02")
    check("control: internal share of an Operations file to lab02 ALLOWED", code in (100, 200), f"HTTP {st}, OCS {code}: {msg}")
elif STAGE == "see":
    st, l3 = listing("lab03"); print(f"  lab03 (doc-reviewers, NOT cui-users) sees: {l3}")
    check("lab03 sees no CUI/FCI/Archive", not {"CUI", "FCI", "Archive"} & set(l3) and "Operations" in l3)
    check("lab03 cannot read the CUI file by path", req("lab03", "GET", dav("lab03", "CUI/CUI_spike-webdav_v1.0.txt"))[0] == 404)
    check("lab03 reads Operations (read-only layer)", req("lab03", "GET", dav("lab03", "Operations/ops-plan.txt"))[0] == 200)
    check("lab03 cannot write in Operations", put("lab03", "Operations/reviewer-wrote.txt", b"x") in (403, 404))
    st, l2 = listing("lab02"); print(f"  lab02 (plain user) sees: {l2}")
    check("lab02 sees no CUI/FCI/Archive", not {"CUI", "FCI", "Archive"} & set(l2))
    st, l4 = listing("lab04"); print(f"  lab04 (doc-reviewers + cui-users) sees: {l4}")
    check("lab04 sees CUI", "CUI" in l4)
    st, data = req("lab04", "GET", dav("lab04", "CUI/CUI_spike-webdav_v1.0.txt"))
    check("lab04 reads the CUI file", st == 200 and data.startswith(b"CUI test file"), f"GET {st}")
    check("lab04 cannot change the CUI file", put("lab04", "CUI/CUI_spike-webdav_v1.0.txt", b"changed") in (403, 404), "PUT")
    check("lab04 cannot add a file to CUI", put("lab04", "CUI/reviewer-new.txt", b"x") in (403, 404), "PUT new")
    check("lab04 cannot delete the CUI file", req("lab04", "DELETE", dav("lab04", "CUI/CUI_spike-webdav_v1.0.txt"))[0] in (403, 404), "DELETE")
    st, data = req("lab04", "GET", dav("lab04", "CUI/CUI_spike-webdav_v1.0.txt"))
    check("CUI file unchanged afterwards", data.startswith(b"CUI test file"))
if STAGE in ("copyout", "copyout-blocked"):
    # copy-out-of-CUI: a cui-users member also has write + share in Operations
    want_blocked = STAGE == "copyout-blocked"; n = uuid.uuid4().hex[:6]
    put("lab01", f"CUI/CUI_copyout-{n}.txt", b"CUI copy-out test\n"); put("lab01", f"CUI/CUI_moveout-{n}.txt", b"CUI move-out test\n")
    dst = lambda p: {"Destination": f"https://{FILES}:8443" + dav("lab01", p)}
    for verb, src, tgt in (("COPY", f"CUI/CUI_copyout-{n}.txt", f"Operations/copied-{n}.txt"), ("MOVE", f"CUI/CUI_moveout-{n}.txt", f"Operations/moved-{n}.txt"),
                           ("COPY", f"CUI/CUI_copyout-{n}.txt", f"copied-home-{n}.txt"), ("MOVE", f"CUI/CUI_moveout-{n}.txt", f"FCI/moved-fci-{n}.txt")):
        st = req("lab01", verb, dav("lab01", src), headers=dst(tgt))[0]
        there = req("lab01", "GET", dav("lab01", tgt))[0] == 200
        fid = fileid("lab01", tgt) if there else None; tg = tags_of("lab01", fid)[1] if fid else None
        print(f"  {verb} {src} -> {tgt}: HTTP {st}; target exists {there}; tags on the target {tg}")
        if tgt.startswith("Operations/") or tgt.startswith("copied-home"):
            if there:
                s1 = share("lab01", tgt, 0, "lab02"); s2 = share("lab01", tgt, 3)
                print(f"    share to lab02: OCS {s1[1]} ({s1[2]}); public link: OCS {s2[1]} ({s2[2]})")
                if s1[1] in (100, 200):
                    print(f"    lab02 reads it: GET {req('lab02', 'GET', dav('lab02', tgt.split('/')[-1]))[0]}")
            check(f"{verb} out of CUI to {tgt.split('/')[0] if '/' in tgt else 'home'} {'blocked' if want_blocked else 'possible (the bypass)'}",
                  (not there) if want_blocked else there)
print(f"{STAGE}: {'ALL PASS' if not fails else str(fails) + ' FAIL'}")
sys.exit(1 if fails else 0)
