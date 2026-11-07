# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Where the daily reviews live (review spec §4): one folder per day, root-only, FROZEN once written (never rebuilt),
kept 365 days; catch-up after downtime builds each missing day once. The ledger and the stick-head record are never
pruned."""
import hashlib
import json
import os
import shutil
from datetime import date, timedelta
from pathlib import Path

from .sitefile import SiteError

REVIEW_DIR = Path("/var/lib/chp/review")
KEEP = {"ledger.jsonl", "stick-heads.json"}
CATCH_UP = 31


def _dir(root):
    return Path(root) / REVIEW_DIR.relative_to("/")


def _days(root):
    d = _dir(root)
    out = []
    if d.is_dir():
        for p in d.iterdir():
            try:
                out.append(date.fromisoformat(p.name))
            except ValueError:
                pass
    return sorted(out)


def _put(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(path, 0o600)


def write_day(day, data, md, html, *, root=Path("/")):
    base = _dir(root)
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    d = base / day.isoformat()
    if d.exists():
        raise SiteError(f"the review for {day} already exists and is frozen (reviews are never rebuilt)")
    tmp = base / f".{day.isoformat()}.partial"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(mode=0o700)
    _put(tmp / "report.md", md)
    _put(tmp / "report.html", html)
    _put(tmp / "data.json", json.dumps(data, sort_keys=True, indent=1))
    os.chmod(tmp, 0o700)
    os.replace(tmp, d)                                     # all three files appear together, or none
    return d


def report_sha256(day_dir):
    return hashlib.sha256((Path(day_dir) / "report.md").read_bytes()).hexdigest()


def missing_days(*, root=Path("/"), today):
    yesterday = today - timedelta(days=1)
    have = _days(root)
    if not have:
        return [yesterday]
    start = max(have[-1] + timedelta(days=1), today - timedelta(days=CATCH_UP))
    return [start + timedelta(days=i) for i in range((yesterday - start).days + 1)]


def build_missing(*, root=Path("/"), today, make):
    built = []
    for day in missing_days(root=root, today=today):
        write_day(day, *make(day), root=root)
        built.append(day)
    return built


def prune(*, root=Path("/"), today, keep_days=365):
    gone = []
    for day in _days(root):
        if (today - day).days > keep_days:
            shutil.rmtree(_dir(root) / day.isoformat())
            gone.append(day.isoformat())
    return gone


def previous(*, root=Path("/"), day, n=7):
    out = []
    for d in reversed([x for x in _days(root) if x < day][-n:]):
        try:
            out.append(json.loads((_dir(root) / d.isoformat() / "data.json").read_text()))
        except (OSError, ValueError):
            pass
    return out


def show(*, root=Path("/"), day=None):
    days = _days(root)
    if not days:
        raise SiteError("no review has been built yet (chp-review-build.timer builds yesterday's after midnight)")
    day = day or days[-1]
    p = _dir(root) / day.isoformat() / "report.md"
    if not p.exists():
        raise SiteError(f"no review for {day}")
    return p.read_text()


def nightly(*, root=Path("/"), today, site, hosts, alerts, now):
    """The timer's job: build every missing day (frozen), then remove reports older than a year."""
    from . import review_report as rr

    def make(day):
        data = rr.build(day, alerts=alerts, hosts=hosts, site=site, now=now, previous=previous(root=root, day=day))
        return data, rr.render_md(data), rr.render_html(data)

    built = build_missing(root=root, today=today, make=make)
    prune(root=root, today=today)
    return built
