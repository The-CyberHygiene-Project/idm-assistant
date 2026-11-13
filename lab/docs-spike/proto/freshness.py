"""proto/freshness.py (Task 2 SPIKE, throwaway; RUNS ON THE MAC, python3 -I, over the spike tunnel 18443): does NextCloud's
WebDAV change marker move on every canonical update and on nothing else? For one controlled file in CUI it records
(getetag, fileid, size, lastmodified, version count) after each event and says CHANGED / same, against what checkout
must expect. Auth: the lab users' app passwords (~/idm-lab-secrets/docs-<u>-app.txt; the transport does not matter for
the marker, proto/doc_fresh.py repeats the key steps with the Bearer route). Admin events go over ssh (occ, the disk).
argv: ROOT_CA"""
import base64
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET

FILES = "files.docs.lab.test"
CA = sys.argv[1]
CTX = ssl.create_default_context(cafile=CA)
HERE = os.path.dirname(os.path.abspath(__file__))
P = "CUI/Compliance/CUI_spike-ssp_v1.0.docx"
OPS = "Operations/spike-fresh-ops.txt"
NS = {"d": "DAV:", "oc": "http://owncloud.org/ns", "nc": "http://nextcloud.org/ns"}
fails = 0


def secret(u):
    return open(os.path.expanduser(f"~/idm-lab-secrets/docs-{u}-app.txt")).read().strip()


def req(user, method, path, body=None, headers=None):
    c = http.client.HTTPSConnection("127.0.0.1", 18443, context=CTX, timeout=60)
    c.sock = CTX.wrap_socket(socket.create_connection(("127.0.0.1", 18443), 60), server_hostname=FILES)
    h = {"Host": f"{FILES}:8443", "OCS-APIRequest": "true", "User-Agent": "CHP spike freshness",
         "Authorization": "Basic " + base64.b64encode(f"{user}:{secret(user)}".encode()).decode()}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()


def dav(u, p):
    return f"/remote.php/dav/files/{u}/" + urllib.parse.quote(p)


def ssh_docs(cmd):
    return subprocess.run(["ssh", "-F", os.path.join(HERE, "..", "ssh_config"), "-o", "BatchMode=yes", "docs", cmd],
                          capture_output=True, text=True).stdout.strip()


PROPS = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" '
         'xmlns:nc="http://nextcloud.org/ns"><d:prop><d:getetag/><oc:fileid/><oc:size/><d:getlastmodified/>'
         '<oc:checksums/><nc:lock/></d:prop></d:propfind>')


def marker(u, p):
    st, _, data = req(u, "PROPFIND", dav(u, p), PROPS, {"Depth": "0", "Content-Type": "application/xml"})
    if st != 207:
        return {"status": st}
    r = ET.fromstring(data)
    g = lambda q: (r.find(".//" + q, NS).text if r.find(".//" + q, NS) is not None else None)
    m = {"etag": g("d:getetag"), "fileid": g("oc:fileid"), "size": g("oc:size"), "mtime": g("d:getlastmodified")}
    st, _, data = req(u, "PROPFIND", f"/remote.php/dav/versions/{u}/versions/{m['fileid']}", None, {"Depth": "1"})
    m["versions"] = (len(list(ET.fromstring(data).iter("{DAV:}response"))) - 1) if st == 207 else f"HTTP {st}"
    return m


LAST = {}


def step(name, expect, u="lab01", p=P):
    """expect: 'same' or 'changed' (the etag); records the whole marker."""
    global fails
    m = marker(u, p)
    prev = LAST.get(p)
    if prev is None:
        verdict, ok = "baseline", True
    else:
        moved = m.get("etag") != prev.get("etag")
        verdict = "CHANGED" if moved else "same"
        ok = (expect == "changed") == moved
        idm = "fileid same" if m.get("fileid") == prev.get("fileid") else "FILEID CHANGED"
        verdict += f"; {idm}; versions {prev.get('versions')}->{m.get('versions')}"
    LAST[p] = m
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} [{expect:7}] {name}: etag {m.get('etag')} ({verdict})")


def put(u, p, data, headers=None):
    return req(u, "PUT", dav(u, p), data, headers)[0]


V1 = b"PK\x03\x04 controlled document SSP v1.0 (spike stand-in)\n" * 50
V2 = b"PK\x03\x04 controlled document SSP v1.1 (spike stand-in)\n" * 50

print(f"# file: {P} (team folder CUI, author lab01); reviewer lab04 (cui-users + doc-reviewers)")
req("lab01", "MKCOL", dav("lab01", "CUI/Compliance"))
put("lab01", P, V1)
step("create (PUT v1.0)", "baseline")
req("lab01", "GET", dav("lab01", P)); step("download by the author (GET)", "same")
step("PROPFIND again (no event)", "same")
req("lab04", "GET", dav("lab04", P)); step("download by a reviewer (lab04 GET)", "same")
st = put("lab04", P, V2); step(f"reviewer write attempt (lab04 PUT -> {st}, refused)", "same")
body = ('<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop>'
        '<oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>')
st = req("lab01", "PROPPATCH", dav("lab01", P), body, {"Content-Type": "application/xml"})[0]
step(f"favourite set (PROPPATCH -> {st})", "same")
fid = LAST[P]["fileid"]
st = req("lab01", "POST", f"/remote.php/dav/comments/files/{fid}", json.dumps({"actorType": "users", "verb": "comment",
         "message": "spike comment"}), {"Content-Type": "application/json"})[0]
step(f"comment added (POST comments -> {st})", "same")
tag = ssh_docs("sudo occ tag:list --output=json")
print(f"  (system tags: {tag[:200]})")
st = req("lab01", "LOCK", dav("lab01", P), '<?xml version="1.0"?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/>'
         '</d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>', {"Content-Type": "application/xml",
         "Timeout": "Second-60"})
lock_token = st[1].get("lock-token")
step(f"WebDAV LOCK (-> {st[0]})", "same")
if lock_token:
    st = req("lab01", "UNLOCK", dav("lab01", P), None, {"Lock-Token": lock_token})[0]
    step(f"UNLOCK (-> {st})", "same")
st = req("lab01", "MOVE", dav("lab01", P), None, {"Destination": f"https://{FILES}:8443" + dav("lab01", P + ".tmp")})[0]
st2 = req("lab01", "MOVE", dav("lab01", P + ".tmp"), None, {"Destination": f"https://{FILES}:8443" + dav("lab01", P)})[0]
step(f"rename away and back (MOVE {st}, {st2})", "same")
print("  + occ groupfolders:scan 1 (no change on disk)"); ssh_docs("sudo occ groupfolders:scan 1 >/dev/null")
step("admin rescan, nothing changed", "same")
print("  + systemctl start nextcloud-cron.service (background jobs)"); ssh_docs("sudo systemctl start nextcloud-cron.service")
step("background jobs ran", "same")
st = put("lab01", P, V1); step(f"author re-uploads the SAME bytes (PUT -> {st})", "changed")
st = put("lab01", P, V2); step(f"author uploads new content (PUT v1.1 -> {st})", "changed")
cur = LAST[P]["etag"]
st = put("lab01", P, V1, {"If-Match": '"stale-etag-0000"'}); step(f"PUT with a STALE If-Match (-> {st}, expect 412)", "same")
st = put("lab01", P, V1, {"If-Match": cur}); step(f"PUT with the CURRENT If-Match (-> {st})", "changed")
# a version restore: copy the oldest version back over the file (what the web UI's Restore does)
st, _, data = req("lab01", "PROPFIND", f"/remote.php/dav/versions/lab01/versions/{fid}", None, {"Depth": "1"})
vs = sorted(urllib.parse.unquote(e.text) for e in ET.fromstring(data).iter("{DAV:}href"))[1:]
if vs:
    st = req("lab01", "MOVE", vs[0], None, {"Destination": f"https://{FILES}:8443/remote.php/dav/versions/lab01/restore/target"})[0]
    step(f"restore an old version (MOVE version -> restore, {st})", "changed")
print("  + on the server's disk: touch -d now (mtime only), then occ groupfolders:scan 1")
path = f"/data/nextcloud/data/__groupfolders/1/files/Compliance/{os.path.basename(P)}"
ssh_docs(f"sudo touch {path} && sudo occ groupfolders:scan 1 >/dev/null")
step("out-of-band: mtime changed on disk + rescan (an update NextCloud did not see happen)", "changed")
print("  + on the server's disk: content replaced with the same size and mtime kept, then rescan")
ssh_docs(f"sudo python3 -c \"import os;p='{path}';s=os.stat(p);d=open(p,'rb').read();open(p,'wb').write(d.replace(b'v1.0',b'v9.9'));os.utime(p,(s.st_atime,s.st_mtime))\" && sudo occ groupfolders:scan 1 >/dev/null")
step("out-of-band: content changed, size + mtime kept, rescan (NextCloud cannot see it)", "same")
# a share's effect, on a file where sharing is allowed (Operations)
put("lab01", OPS, b"ops v1\n"); step("Operations file created", "baseline", p=OPS)
f = {"path": "/" + OPS, "shareType": "0", "shareWith": "lab02", "permissions": "1"}
st = req("lab01", "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json", urllib.parse.urlencode(f),
         {"Content-Type": "application/x-www-form-urlencoded"})[0]
step(f"shared to lab02 (-> {st})", "same", p=OPS)
print(f"freshness: {'ALL PASS' if not fails else f'{fails} FAIL'}")
