"""proto/etag_collide.py (Task 2 SPIKE, throwaway; RUNS ON THE MAC over the tunnel): NextCloud's ETag for a file on local
storage is md5(mtime_seconds . inode . dev . size) (lib/private/Files/Storage/Local.php calculateEtag). So two different
contents can share an ETag. Cases, 10 tries each, as lab01 on a CUI file:
  A  two PUTs of different content, same size, back to back (same second)
  B  the same, 1.2 s apart
  C  different sizes, back to back
  E  as A without the server stat between the PUTs (A's ssh stat pushed the PUTs into different seconds)
  D  same size, 2.2 s apart, the second PUT sends X-OC-Mtime = the first one's mtime (a client may set mtime)
For each try: did the ETag change, and the server's inode before/after. argv: ROOT_CA"""
import os
import subprocess
import sys
import time

sys.argv = [sys.argv[0], sys.argv[1]]
HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "freshness.py")).read()
ns = {"__name__": "lib", "__file__": os.path.join(HERE, "freshness.py")}
exec(compile(src.split("V1 = b")[0], "freshness.py", "exec"), ns)   # reuse req/dav/marker, not the experiment
req, dav, marker, ssh_docs = ns["req"], ns["dav"], ns["marker"], ns["ssh_docs"]

P = "CUI/Compliance/CUI_spike-collide.txt"
DISK = "/data/nextcloud/data/__groupfolders/1/files/Compliance/CUI_spike-collide.txt"


def put(data, h=None):
    return req("lab01", "PUT", dav("lab01", P), data, h)[0]


def ino():
    return ssh_docs(f"sudo stat -c '%i %Y' {DISK}")


def run(name, gap, size2, mtime_hdr=False, n=10, stat=True):
    same = 0
    for i in range(n):
        put(b"A" * 100 + str(i).encode())
        m1 = marker("lab01", P)
        a = ino() if stat or mtime_hdr else "- -"
        if gap:
            time.sleep(gap)
        h = {"X-OC-Mtime": str(int(a.split()[1]))} if mtime_hdr else None
        put(b"B" * (100 + size2) + str(i).encode(), h)
        m2 = marker("lab01", P)
        b = ino() if stat else "- -"
        hit = m1["etag"] == m2["etag"]
        same += hit
        print(f"  {name} try {i}: etag {'SAME (collision)' if hit else 'changed'}; inode/mtime {a} -> {b}")
    print(f"{name}: {same}/{n} tries kept the ETag across a content change")
    return same


r = {}
r["A"] = run("A same size, back to back", 0, 0)
r["B"] = run("B same size, 1.2 s apart", 1.2, 0)
r["C"] = run("C different size, back to back", 0, 7)
r["E"] = run("E same size, back to back, no server stat in between (truly the same second)", 0, 0, stat=False)
r["D"] = run("D same size, 2.2 s apart, X-OC-Mtime = first mtime", 2.2, 0, mtime_hdr=True)
print("summary:", r)
