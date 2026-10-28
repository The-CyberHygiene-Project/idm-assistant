# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""File integrity (core 0.2.0, spec 2026-10-12): AIDE baseline records, the site-stick pin, report parsing, and the
approved, audited baseline change (aide-accept). The daily check itself is a shell wrapper (chp-integrity RPM)."""
import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import audit
from .sitefile import SiteError

DB = Path("/var/lib/aide/aide.db.gz")
NEW_DB = Path("/var/lib/aide/aide.db.new.gz")
STATE = Path("/var/lib/chp/aide")
LOGDIR = Path("/var/log/aide")
_BUILT_BY = re.compile(r"first-boot|package-install|accepted:[^\x00-\x1f=]{1,64}")


def stamp(t=None):
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t))


def sha512_file(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_record(path):
    """KEY=value lines -> dict; a missing file is {}."""
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        return {}
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def write_record(path, rec, mode=0o644):
    """Atomic: write a temp file, fsync, chmod, rename over the old one (a reader never sees half a record)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write("".join(f"{k}={v}\n" for k, v in rec.items()))
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def baseline_record(db, built_by, now):
    if not _BUILT_BY.fullmatch(built_by):
        raise ValueError(f"BUILT_BY {built_by!r}")
    return {"DB_SHA512": sha512_file(db), "BUILT_AT": stamp(now), "BUILT_EPOCH": str(int(now)), "BUILT_BY": built_by}


PINNED_SIGNERS = {"521276f43c908f8e": "CyberHygiene", "8a3872bf3228467c": "EPEL 9", "702d426d350d275d": "Rocky 9",
                  "96b3ee5f29111145": "Wazuh"}          # = the keys in appliance/release/trusted-keys.txt (tested)
_SIGQF = "%{INSTALLTIME} %|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{(none)}|}|\n"


class Rpm:
    """Read-only questions to the rpm database (cached per package)."""
    def __init__(self, run=subprocess.run):
        self.run, self._info, self._mod = run, {}, {}

    def owner(self, path):
        r = self.run(["rpm", "-qf", "--qf", "%{NAME}\n", path], capture_output=True, text=True)
        return r.stdout.splitlines()[0].strip() if r.returncode == 0 and r.stdout.strip() else None

    def info(self, name):
        if name not in self._info:
            r = self.run(["rpm", "-q", "--qf", _SIGQF, name], capture_output=True, text=True)
            line = r.stdout.splitlines()[0] if r.returncode == 0 and r.stdout else ""
            t, _, sig = line.partition(" ")
            m = re.search(r"Key ID ([0-9a-f]{16})", sig)
            self._info[name] = (int(t) if t.isdigit() else 0, m.group(1) if m else None)
        return self._info[name]

    def modified(self, name):
        if name not in self._mod:
            r = self.run(["rpm", "-V", name], capture_output=True, text=True)
            self._mod[name] = {line.split()[-1] for line in r.stdout.splitlines() if line.strip()}
        return self._mod[name]


def group(changes, rpm, built_epoch):
    """Split AIDE's paths into (explained, unexplained). Explained = added/changed path owned by a package installed or
    updated after the baseline, that rpm -V reports unmodified, signed by a pinned key. A reading aid only: nothing is
    accepted automatically. A removed path is always unexplained (no owner left to ask)."""
    explained, unexplained = {}, []
    for kind in ("added", "removed", "changed"):
        for p in changes.get(kind, []):
            name = rpm.owner(p) if kind != "removed" else None
            if name:
                t, key = rpm.info(name)
                if t > built_epoch and key in PINNED_SIGNERS and p not in rpm.modified(name):
                    explained.setdefault(name, []).append(p)
                    continue
            unexplained.append((kind, p))
    return explained, unexplained

def write_pin(stick, host, base, now):
    """aide/<host>.txt on the site stick; an existing record is first renamed aide/<host>.<its PINNED_AT>[-n].txt
    (history kept, nothing overwritten). Written, fsync'd and read back."""
    if not base.get("DB_SHA512"):
        raise SiteError("no AIDE baseline on this host yet (nothing to pin)")
    d = Path(stick) / "aide"
    d.mkdir(exist_ok=True)
    cur = d / f"{host}.txt"
    if cur.exists():
        old = read_record(cur).get("PINNED_AT", "unknown")
        n = 0
        while (d / f"{host}.{old}{'' if n == 0 else f'-{n}'}.txt").exists():
            n += 1
        os.rename(cur, d / f"{host}.{old}{'' if n == 0 else f'-{n}'}.txt")
    rec = {"HOST": host, "DB_SHA512": base["DB_SHA512"], "BUILT_AT": base.get("BUILT_AT", ""),
           "BUILT_BY": base.get("BUILT_BY", ""), "PINNED_AT": stamp(now)}
    text = "".join(f"{k}={v}\n" for k, v in rec.items())
    with open(cur, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    if cur.read_text() != text:
        raise SiteError(f"the pin record on the stick reads back differently ({cur}); do not trust it")
    return cur


def verify_pin(stick, host, db_sha):
    rec = read_record(Path(stick) / "aide" / f"{host}.txt")
    if not rec.get("DB_SHA512"):
        raise SiteError(f"the site stick has no AIDE pin for {host} (aide/{host}.txt)")
    return rec["DB_SHA512"] == db_sha, rec["DB_SHA512"]


_SECTION = re.compile(r"^(Added|Removed|Changed) entries:\s*$")
_ENTRY = re.compile(r"^\S[^:]*:\s(/.*)$")


def parse_report(text):
    """Paths from AIDE's plain grouped report (report_grouped=yes): the Added/Removed/Changed sections only."""
    out, cur = {"added": [], "removed": [], "changed": []}, None
    for line in text.splitlines():
        s = line.rstrip()
        if s.startswith(("Detailed information about changes", "The attributes of the")):
            break
        m = _SECTION.match(s)
        if m:
            cur = m.group(1).lower()
            continue
        e = _ENTRY.match(s) if cur else None
        if e:
            out[cur].append(e.group(1))
    return out


def run_aide(*args):
    import subprocess as sp
    r = sp.run(["aide", *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def _summary(changes, explained, unexplained):
    lines = [f"AIDE changes since the baseline: {len(changes['added'])} added, {len(changes['removed'])} removed, "
             f"{len(changes['changed'])} changed", ""]
    n_exp = sum(len(v) for v in explained.values())
    lines.append(f"Explained by signed package updates: {n_exp} paths in {len(explained)} packages")
    for pkg in sorted(explained):
        lines.append(f"  {pkg}: {len(explained[pkg])} paths")
    lines += ["", f"NOT explained: {len(unexplained)} paths (review every one)"]
    lines += [f"  {kind:8} {p}" for kind, p in unexplained]
    return "\n".join(lines)


def accept(site, approver, reason, *, host, aide, rpm, confirm, say=print, rec=audit.record,
           investigated_mismatch=False, db=DB, new_db=NEW_DB, state=STATE, logdir=LOGDIR, now=time.time):
    """spec §6.1: approve (ISSO or BASELINE_DELEGATES), fresh check, grouped summary, confirm, audit, new baseline.
    Returns the new baseline record, or None when there is nothing to accept."""
    from .ops import approved_by, checked_reason
    approver = approved_by(site, approver, "BASELINE_DELEGATES")
    reason = checked_reason(reason, "why these changes are legitimate")
    state, logdir, db, new_db = Path(state), Path(logdir), Path(db), Path(new_db)
    base = read_record(state / "baseline")
    if not base.get("DB_SHA512") or not db.exists():
        raise SiteError("no AIDE baseline on this host (nothing to accept against): see the 60-aide-result alert")
    mismatch = sha512_file(db) != base["DB_SHA512"]
    if mismatch and not investigated_mismatch:
        raise SiteError("the AIDE database is NOT the recorded baseline (replaced outside aide-accept?): investigate "
                        "first; only then re-run with --database-mismatch-investigated")
    rc, text = aide("--check")
    if rc < 0 or rc >= 14:
        raise SiteError(f"the fresh AIDE check failed (exit {rc}); nothing was changed")
    if rc == 0 and not mismatch:
        say("AIDE: no changes since the baseline; nothing to accept")
        return None
    t = now()
    logdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    rep = logdir / f"accept-{stamp(t)}.log"
    rep.write_text(text)
    rep.chmod(0o600)
    changes = parse_report(text)
    explained, unexplained = group(changes, rpm, int(base.get("BUILT_EPOCH", "0") or 0))
    say(_summary(changes, explained, unexplained))
    if not confirm():
        raise SiteError("not accepted; nothing was changed")
    fields = {"host": host, "approver": approver, "reason": reason, "operator": audit.operator(),
              "explained": sum(len(v) for v in explained.values()), "unexplained": len(unexplained),
              "db_mismatch": "investigated" if mismatch else "no", "old_sha512": base["DB_SHA512"], "report": str(rep)}
    rec("aide-accept", fields)
    if new_db.exists():
        new_db.unlink()
    rc2, _out = aide("--init")
    if rc2 != 0 or not new_db.exists():
        raise SiteError(f"aide --init failed (exit {rc2}); the old baseline is unchanged")
    os.replace(new_db, db)
    os.chmod(db, 0o600)
    t2 = now()
    nb = baseline_record(db, f"accepted:{approver}", t2)
    write_record(state / "baseline", nb, 0o600)
    acc = logdir / "accepted"
    acc.mkdir(mode=0o700, exist_ok=True)
    shutil.copy2(rep, acc / rep.name)
    write_record(state / "last-result", {"TIME": stamp(t2), "EPOCH": str(int(t2)), "EXIT": "0", "ADDED": "0",
                                         "REMOVED": "0", "CHANGED": "0", "DB_MATCH": "yes",
                                         "REPORT": str(acc / rep.name)}, 0o644)
    rec("aide-accept.done", {**fields, "new_sha512": nb["DB_SHA512"]}, after=True)
    say(f"accepted by {approver}: new baseline {nb['DB_SHA512'][:16]}… (recorded in the audit log)")
    return nb
