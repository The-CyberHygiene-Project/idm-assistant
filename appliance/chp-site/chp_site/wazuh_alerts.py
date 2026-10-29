# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Wazuh alerts to the site (security bundle spec §5): level >= threshold (and agent lifecycle) to the hook, repeats
grouped per host+rule for 15 minutes, a daily line for levels 7-9, and the chp-site alerts summary."""
import gzip
import json
import os
import re
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

LIFECYCLE = {"504", "505", "506"}          # agent disconnected / removed / stopped (planning ruling: always sent)
DAY = 86400


def _parts(a):
    """(rule dict, agent dict, level int, rule id str) from any JSON value; odd input gives safe empties."""
    a = a if isinstance(a, dict) else {}
    r = a.get("rule") if isinstance(a.get("rule"), dict) else {}
    ag = a.get("agent") if isinstance(a.get("agent"), dict) else {}
    try:
        lvl = int(r.get("level", 0) or 0)
    except (TypeError, ValueError):
        lvl = 0
    return r, ag, lvl, str(r.get("id", ""))


def line(a):
    r, ag, _lvl, _rid = _parts(a)
    return f"{ag.get('name', '?')} rule {r.get('id', '?')} level {r.get('level', '?')}: {r.get('description', '?')}"


class Forwarder:
    def __init__(self, level, window=900):
        self.level, self.window = level, window
        self.groups = {}                    # (host, rule) -> [first_sent_epoch, repeats, text]
        self.medium, self.day_start = [], None

    def feed(self, a, now):
        if self.day_start is None:
            self.day_start = now
        r, ag, lvl, rid = _parts(a)
        if not r:
            return []                                   # not an alert (final review I4: never crash on odd lines)
        if not (lvl >= self.level or rid in LIFECYCLE):
            if 7 <= lvl <= 9:
                self.medium.append(ag.get("name", "?"))
            return []
        key = (ag.get("name", "?"), rid)
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
    """Yield each new alert (a dict) appended to path, and None after each idle pass. The (inode, offset) state is saved
    before each alert is handed over, so a restart never re-sends one. On rotation (a new inode) the old file is read to
    its end first, then the new one from 0. Lines that are not JSON are skipped; a partly written line waits."""
    ino, off = _read_state(state_path)
    fh = None

    def save():
        tmp = f"{state_path}.tmp"
        with open(tmp, "w") as s:
            s.write(f"{ino} {off}\n")
        os.replace(tmp, state_path)

    def lines():
        nonlocal off
        while True:
            pos = fh.tell()
            raw = fh.readline()
            if not raw or not raw.endswith(b"\n"):
                fh.seek(pos)                            # nothing, or a partly written line: read it next time
                return
            off += len(raw)
            save()
            try:
                yield json.loads(raw)
            except ValueError:
                pass

    try:
        while True:
            try:
                st = os.stat(path)
            except FileNotFoundError:
                st = None
            if fh is not None and st is not None and st.st_ino != ino:
                yield from lines()                      # rotation: finish the old file first
                fh.close(); fh = None
                ino, off = st.st_ino, 0
                save()
            if fh is None and st is not None:
                if st.st_ino != ino or st.st_size < off:
                    ino, off = st.st_ino, 0
                fh = open(path, "rb")
                fh.seek(off)
            elif fh is not None and st is not None and st.st_size < off:
                fh.seek(0); off = 0                    # truncated in place
            if fh is not None:
                yield from lines()
            if stop():
                return
            yield None                                  # idle pass: lets the caller flush groups and the daily line
            sleep(2)
    finally:
        if fh is not None:
            fh.close()


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


def load_alerts(base, since_epoch):
    """Every alert in base (alerts.json and the dated YYYY/Mon/ossec-alerts-DD.json[.gz] files). Wazuh's alerts.json is
    a hard link to today's dated file, so each file is read once (by device + inode)."""
    seen, out = set(), []
    for p in sorted(Path(base).rglob("*.json*")):
        st = p.stat()
        if (st.st_dev, st.st_ino) in seen or st.st_mtime < since_epoch - DAY:
            continue
        seen.add((st.st_dev, st.st_ino))
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", errors="replace") as fh:
            for ln in fh:
                try:
                    out.append(json.loads(ln))
                except ValueError:
                    pass
    return out


def parse_since(s):
    m = re.fullmatch(r"(\d+)([mhd])", s or "")
    if not m:
        raise ValueError(f"--since: {s!r} is not like 90m, 24h or 7d")
    return int(m.group(1)) * {"m": 60, "h": 3600, "d": DAY}[m.group(2)]
