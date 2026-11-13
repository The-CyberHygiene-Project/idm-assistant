"""proto/colleague.py (Task 2 SPIKE; RUNS ON THE MAC over the tunnel): another session changes the canonical copy.
argv: ROOT_CA PATH MODE   MODE = plain (an ordinary PUT of new content) | same-etag (new content of the same size,
sent with X-OC-Mtime = the file's current mtime: the ETag does not move, logs/51-52 case D)."""
import os
import sys
import time
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ca, path, mode = sys.argv[1:4]
sys.argv = [sys.argv[0], ca]
ns = {"__name__": "lib", "__file__": os.path.join(HERE, "freshness.py")}
exec(compile(open(os.path.join(HERE, "freshness.py")).read().split("V1 = b")[0], "freshness.py", "exec"), ns)
req, dav, marker = ns["req"], ns["dav"], ns["marker"]
before = marker("lab01", path)
st, _, data = req("lab01", "GET", dav("lab01", path))
new = data.replace(b"SSP", b"S5P") if b"SSP" in data else data[:-1] + b"X"
assert len(new) == len(data)
h = {}
if mode == "same-etag":
    body = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/></d:prop></d:propfind>'
    _, _, x = req("lab01", "PROPFIND", dav("lab01", path), body, {"Depth": "0", "Content-Type": "application/xml"})
    lm = ET.fromstring(x).find(".//{DAV:}getlastmodified").text
    import email.utils
    h["X-OC-Mtime"] = str(int(email.utils.parsedate_to_datetime(lm).timestamp()))
else:
    new = new + b"colleague's change\n"
st = req("lab01", "PUT", dav("lab01", path), new, h)[0]
after = marker("lab01", path)
print(f"COLLEAGUE ({mode}) PUT -> {st}: content changed ({len(data)} -> {len(new)} bytes); "
      f"etag {before['etag']} -> {after['etag']} ({'SAME' if before['etag'] == after['etag'] else 'changed'})")
