# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Wazuh alerts to the site (security bundle spec §5): level >= threshold (and agent lifecycle) to the hook, repeats
grouped per host+rule for 15 minutes, a daily line for levels 7-9, and the chp-site alerts summary."""
import json
import os
import re
import time
from collections import Counter
from datetime import datetime

LIFECYCLE = {"504", "505", "506"}          # agent disconnected / removed / stopped (planning ruling: always sent)
DAY = 86400


def line(a):
    r, ag = a.get("rule", {}), a.get("agent", {})
    return f"{ag.get('name', '?')} rule {r.get('id', '?')} level {r.get('level', '?')}: {r.get('description', '?')}"


class Forwarder:
    def __init__(self, level, window=900):
        self.level, self.window = level, window
        self.groups = {}                    # (host, rule) -> [first_sent_epoch, repeats, text]
        self.medium, self.day_start = [], None

    def feed(self, a, now):
        if self.day_start is None:
            self.day_start = now
        r = a.get("rule", {})
        lvl = int(r.get("level", 0) or 0)
        rid = str(r.get("id", ""))
        if not (lvl >= self.level or rid in LIFECYCLE):
            if 7 <= lvl <= 9:
                self.medium.append(a.get("agent", {}).get("name", "?"))
            return []
        key = (a.get("agent", {}).get("name", "?"), rid)
        g = self.groups.get(key)
        if g and now - g[0] < self.window:
            g[1] += 1
            return []
        self.groups[key] = [now, 0, line(a)]
        return [line(a)]

    def flush(self, now):
        out = []
        for key, (t0, n, text) in list(self.groups.items()):
            if now - t0 >= self.window:
                if n:
                    out.append(f"{text} ({n} more in the last {self.window // 60} min)")
                del self.groups[key]
        return out

    def daily(self, now):
        if self.day_start is None or now - self.day_start < DAY:
            return None
        n, hosts = len(self.medium), len(set(self.medium))
        self.medium, self.day_start = [], now
        return (f"{n} medium alerts (levels 7-9) on {hosts} hosts in the last 24 h; run chp-site alerts") if n else None


def _read_state(p):
    try:
        ino, off = open(p).read().split()
        return int(ino), int(off)
    except (OSError, ValueError):
        return None, 0


def follow(path, state_path, sleep=time.sleep, stop=lambda: False):
    """Yield each new alert (a dict) appended to path; the (inode, offset) state survives restarts; a new inode
    (rotation) restarts at 0; lines that are not JSON are skipped."""
    ino, off = _read_state(state_path)
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if st.st_ino != ino or st.st_size < off:
                ino, off = st.st_ino, 0
            with open(path, "rb") as fh:
                fh.seek(off)
                for raw in fh:
                    if not raw.endswith(b"\n"):
                        break                       # a partly written line: read it next time
                    off += len(raw)
                    try:
                        yield json.loads(raw)
                    except ValueError:
                        pass
            tmp = f"{state_path}.tmp"
            with open(tmp, "w") as fh:
                fh.write(f"{ino} {off}\n")
            os.replace(tmp, state_path)
        if stop():
            return
        sleep(2)


def _epoch(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except (TypeError, ValueError):
        return 0.0


def summarize(alerts, since_epoch, min_level):
    c = Counter()
    for a in alerts:
        r = a.get("rule", {})
        if int(r.get("level", 0) or 0) >= min_level and _epoch(a.get("timestamp")) >= since_epoch:
            c[(a.get("agent", {}).get("name", "?"), str(r.get("id", "?")), int(r.get("level", 0)),
               r.get("description", "?"))] += 1
    if not c:
        return "no alerts at or above that level in that period"
    rows = [f"{'host':<16} {'rule':>6} {'level':>5} {'count':>5}  description"]
    for (h, rid, lvl, d), n in sorted(c.items(), key=lambda kv: (-kv[0][2], -kv[1])):
        rows.append(f"{h:<16} {rid:>6} {lvl:>5} {n:>5}  {d}")
    return "\n".join(rows)


def parse_since(s):
    m = re.fullmatch(r"(\d+)([mhd])", s or "")
    if not m:
        raise ValueError(f"--since: {s!r} is not like 90m, 24h or 7d")
    return int(m.group(1)) * {"m": 60, "h": 3600, "d": DAY}[m.group(2)]
