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
            (_dir(root) / f".alerted-{day.isoformat()}").unlink(missing_ok=True)      # monitor 75's marker for it
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


def immediate(*, site, hosts, alerts, now):
    """Monitor 75's 'alert at once' items: today's status so far (the same builder), immediate and not owned by an
    existing monitor check (a long-lived certificate or key within 7 days of expiry)."""
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from . import review_report as rr
    today = datetime.fromtimestamp(now, ZoneInfo(site.get("TIMEZONE") or "UTC")).date()
    data = rr.build(today, alerts=alerts, hosts=hosts, site=site, now=now, previous=[])
    return [s for s in data["status"] if s["immediate"] and s["owner"] is None and s["state"] != "OK"]


SIGN_WAIT = 2 * 86400                                    # owner 2026-11-07: alert after 2 days without a sign-off


def _signed(root):
    out = set()
    p = _dir(root) / "ledger.jsonl"
    if p.exists():
        for ln in p.read_text().splitlines():
            try:
                out.add(json.loads(ln)["date"])
            except (ValueError, KeyError, TypeError):
                pass                                     # a damaged ledger is reported by verify, not here
    return out


def monitor_lines(*, root=Path("/"), today, now, tz, verify_problems, immediate_items):
    """Monitor 75's lines (spec §6): yesterday's review missing (after 01:00), a review unsigned for 2 days, the latest
    review's attention items (once per day), a ledger problem, and the 'at once' items."""
    from datetime import datetime
    from zoneinfo import ZoneInfo
    lines, base = [], _dir(root)
    days = _days(root)
    yesterday = today - timedelta(days=1)
    if yesterday not in days and datetime.fromtimestamp(now, ZoneInfo(tz or "UTC")).hour >= 1:
        lines.append(f"ALERT the daily review for {yesterday} was not built (systemctl status chp-review-build)")
    signed = _signed(root)
    waiting = [d.isoformat() for d in days if d.isoformat() not in signed
               and (base / d.isoformat()).stat().st_mtime < now - SIGN_WAIT]
    if waiting:
        lines.append(f"ALERT {len(waiting)} daily review(s) have waited more than 2 days for a sign-off "
                     f"({', '.join(waiting[:5])}{' ...' if len(waiting) > 5 else ''}): chp-site review sign")
    if days:
        latest = days[-1].isoformat()
        marker = base / f".alerted-{latest}"
        if not marker.exists():
            try:
                att = json.loads((base / latest / "data.json").read_text()).get("attention", [])
            except (OSError, ValueError):
                att = []
            lines += [f"ALERT review {latest}: {a['host']}: {a['item']}: {a['detail']}" for a in att]
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
    if verify_problems:
        lines.append(f"ALERT the review ledger check failed: {verify_problems[0]}"
                     + (f" (+{len(verify_problems) - 1} more; chp-site review verify)" if len(verify_problems) > 1 else ""))
    lines += [f"ALERT {i['host']}: {i['item']}: {i['detail']} (within 7 days of expiry)" for i in immediate_items]
    return lines or ["OK daily review: built, signed, nothing waiting"]
