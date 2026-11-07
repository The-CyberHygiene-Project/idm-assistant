# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The ISSO's sign-off ledger (review spec §5): one JSON line per signed day, append-only, each entry carrying the
SHA-256 of the previous line, kept forever. A broken chain is reported and never silently restarted."""
import fcntl
import hashlib
import json
import os
from datetime import date, timedelta
from pathlib import Path

from . import review_store as st
from .sitefile import SiteError

LEDGER = st.REVIEW_DIR / "ledger.jsonl"
GENESIS = "0" * 64
FIELDS = ("date", "report_sha256", "approver", "operator", "time", "notes", "prev")


def _path(root):
    return Path(root) / LEDGER.relative_to("/")


def entry_hash(line):
    return hashlib.sha256(line.rstrip("\n").encode()).hexdigest()


def _lines(path):
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text()
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    elif lines:
        raise SiteError(f"ledger {p}: line {len(lines)} is incomplete (no line end; an interrupted write?): "
                        "do not sign until the ISSO has checked it")
    return lines


def read(path):
    """Every entry, after checking the chain; SiteError naming the first bad line."""
    out, prev = [], GENESIS
    for n, ln in enumerate(_lines(path), 1):
        try:
            e = json.loads(ln)
        except ValueError:
            raise SiteError(f"ledger {path}: line {n} is not a valid entry") from None
        if not isinstance(e, dict) or set(e) != set(FIELDS):
            raise SiteError(f"ledger {path}: line {n} has the wrong fields")
        if e["prev"] != prev:
            raise SiteError(f"ledger {path}: entry {n} does not follow entry {n - 1} (the chain is broken there)")
        out.append(e)
        prev = entry_hash(ln)
    return out


def head(path):
    lines = _lines(path)
    return (len(lines), entry_hash(lines[-1]) if lines else GENESIS)


def append(path, *, date, report_sha256, approver, operator, notes, now):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        read(p)                                           # refuse a broken chain (and wait out a concurrent signer)
        e = {"date": date, "report_sha256": report_sha256, "approver": approver, "operator": operator, "time": now,
             "notes": notes, "prev": head(p)[1]}
        line = json.dumps(e, sort_keys=True, separators=(",", ":"))
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(p, 0o600)
    return e


def verify(path, *, root=Path("/")):
    """Problems found (empty = fine): the chain, then every entry whose report is still kept is re-hashed."""
    try:
        entries = read(path)
    except SiteError as err:
        return [str(err)]
    problems = []
    for n, e in enumerate(entries, 1):
        d = st._dir(root) / e["date"]
        if (d / "report.md").exists() and st.report_sha256(d) != e["report_sha256"]:
            problems.append(f"entry {n}: the kept report for {e['date']} no longer matches the one that was signed")
    return problems


def sign(*, site, approver, notes, days, root=Path("/"), now, operator, confirm, say=print, rec=None):
    from . import audit
    from .ops import approved_by
    rec = rec or audit.record
    approver = approved_by(site, approver, "REVIEW_DELEGATES")
    path = _path(root)
    signed = {e["date"] for e in read(path)}
    built = [d.isoformat() for d in st._days(root)]
    want = [d.isoformat() for d in days] if days else [d for d in built if d not in signed]
    if not want:
        raise SiteError("nothing to sign: every built review is already signed")
    for d in want:
        if d not in built:
            raise SiteError(f"no review for {d}")
        if d in signed:
            raise SiteError(f"the review for {d} is already signed")
    for d in want:
        say(st.show(root=root, day=date.fromisoformat(d)).split("\n## ")[0])
    if not confirm(f"sign {len(want)} review(s) ({', '.join(want)}) as {approver}?"):
        raise SiteError("not signed")
    out = []
    for d in want:
        e = append(path, date=d, report_sha256=st.report_sha256(st._dir(root) / d), approver=approver,
                   operator=operator, notes=notes, now=now)
        rec("review-sign", {"date": d, "approver": approver, "notes": notes, "entry": head(path)[1]})
        out.append(e)
    return out


def verify_heads(path, heads_text):
    """Every head the stick recorded must still be in the server's chain at the same position: catches the whole ledger
    being rewritten, or its newest entries removed (spec §5, owner 2026-11-07: detect, don't prevent)."""
    lines = _lines(path)
    problems = []
    for n, ln in enumerate(heads_text.splitlines(), 1):
        f = ln.split()
        if len(f) < 3 or not f[0].isdigit() or len(f[1]) != 64:
            return [f"stick heads.txt line {n} is not '<count> <hash> <time>'"]
        count, h = int(f[0]), f[1]
        if count > len(lines):
            problems.append(f"head {n} ({f[2]}): the stick saw {count} entries; the server has {len(lines)} "
                            "(entries removed)")
        elif count and entry_hash(lines[count - 1]) != h:
            problems.append(f"head {n} ({f[2]}): entry {count} on the server is not the one the stick recorded "
                            "(the ledger was rewritten)")
    return problems


def export(stick, *, root=Path("/"), now):
    """Copy every kept review, the ledger and its check result to <stick>/review/, then append the ledger head."""
    import shutil
    from datetime import datetime, timezone
    out = Path(stick) / "review"
    out.mkdir(parents=True, exist_ok=True)
    days = [d.isoformat() for d in st._days(root)]
    for d in days:
        dst = out / d
        if not dst.exists():
            shutil.copytree(st._dir(root) / d, dst)
    src = _path(root)
    if src.exists():
        shutil.copyfile(src, out / "ledger.jsonl")
    problems = verify(src, root=root)
    (out / "verify.txt").write_text(("OK: chain and kept reports match\n" if not problems else
                                     "PROBLEMS:\n" + "".join(f"- {p}\n" for p in problems)))
    count, h = head(src)
    stamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(out / "heads.txt", "a") as f:
        f.write(f"{count} {h} {stamp}\n")
    return {"days": days, "head": (count, h), "problems": problems}
