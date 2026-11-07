# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The daily review report (review spec §4): intrusions by source, every host's security status, resources. Pure:
build() turns one local calendar day of Wazuh alerts (including the hosts' records, rule 100520) into the report data;
render_md/render_html format it. Nothing here reads files or runs commands."""
import html
import ipaddress
import json
from datetime import date, datetime, time as dtime, timedelta

from . import review_rules as rr

RECORD_RULE = "100520"
RECORD_EVERY = 600                              # the hosts' record timer (10 minutes)
SURICATA_RULES = {"86601", "100510", "100511"}
YARA_MATCH, YARA_OTHER = "100501", {"100500", "100502"}
LEVEL_FLOOR = 7
DAY = 86400
# Items an existing monitor check already alerts on: shown in the report, never alerted again (spec §6).
SCANS = (("yara_recent", 300, "73-yara-scan"), ("yara_full", 7 * DAY, "73-yara-scan"),
         ("suricata_stats", 60, "74-suricata"), ("aide_check", DAY, "61-aide-stale"))
KANIDM_CERTS = "/etc/pki/kanidm/"


def day_bounds(day, tz):
    start = datetime.combine(day, dtime(0), tzinfo=tz)
    end = datetime.combine(day + timedelta(days=1), dtime(0), tzinfo=tz)
    return start.timestamp(), end.timestamp()


def _when(a):
    t = a.get("timestamp", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(t, fmt).timestamp()
        except ValueError:
            pass
    return None


def _short(name):
    return (name or "?").split(".")[0]


def _ip(s):
    try:
        return ipaddress.ip_address(str(s))
    except ValueError:
        return None


def _num_or_none(x):
    return x is None or (isinstance(x, (int, float)) and not isinstance(x, bool))


def _valid(b):
    """A version-1 record with the field types the report relies on (final review I3); anything else is skipped."""
    try:
        if not isinstance(b, dict) or b.get("v") != 1 or not isinstance(b.get("host"), str):
            return False
        if not isinstance(b.get("time"), (int, float)) or not isinstance(b.get("versions", {}), dict):
            return False
        for c in b.get("certs", []):
            if not (isinstance(c["path"], str) and isinstance(c["not_before"], (int, float))
                    and isinstance(c["not_after"], (int, float))):
                return False
        for k in b.get("keys", []):
            if not (isinstance(k["file"], str) and _num_or_none(k.get("expires"))):
                return False
        sc = b.get("scans", {})
        if not isinstance(sc, dict) or not all(_num_or_none(sc.get(x)) for x in
                                                ("yara_recent", "yara_full", "suricata_stats", "aide_check")):
            return False
        s = b.get("sys", {})
        if not isinstance(s, dict):
            return False
        for dk in s.get("disk", []):
            if not (isinstance(dk["mount"], str) and isinstance(dk["used_pct"], int)):
                return False
        for part, keys in (("cpu", ("avg", "peak")), ("mem", ("avg_pct", "peak_pct"))):
            if part in s and not all(isinstance(s[part].get(x), (int, float)) for x in keys):
                return False
        return _num_or_none(b.get("security_since"))
    except (KeyError, TypeError, AttributeError):
        return False


def _records(alerts):
    """Each host's records, keyed by the Wazuh agent that DELIVERED them (final review I4: a client cannot speak for
    another host); malformed, future-version or mismatched records are counted, never fatal."""
    out, bad = {}, {}
    for a in alerts:
        if a.get("rule", {}).get("id") != RECORD_RULE:
            continue
        sender = _short((a.get("agent") or {}).get("name"))
        try:
            b = json.loads(a["data"]["chp_review"]["body"])
        except (KeyError, TypeError, ValueError):
            b = None
        if not _valid(b) or _short(b["host"]) != sender:
            bad[sender] = bad.get(sender, 0) + 1
            continue
        out.setdefault(sender, []).append(b)
    for v in out.values():
        v.sort(key=lambda b: b.get("time", 0))
    return out, bad


def _intrusions(alerts, site, ip_host):
    groups, routine = {}, {}
    net = site.get("SUBNET")
    for a in alerts:
        r, d = a.get("rule", {}), a.get("data") or {}
        rid, lvl, host = str(r.get("id", "")), int(r.get("level", 0) or 0), _short(a.get("agent", {}).get("name"))
        if rid == RECORD_RULE or rid in YARA_OTHER:
            continue
        al = d.get("alert") if isinstance(d.get("alert"), dict) else None
        if rid in SURICATA_RULES or (al and "suricata" in r.get("groups", [])):
            kind, src, target, sig = "suricata", d.get("src_ip"), d.get("dest_ip"), (al or {}).get("signature", "?")
        elif rid == YARA_MATCH:
            kind, src, target, sig = "yara", host, host, (d.get("chp_yara") or {}).get("rules", "?")
        elif lvl >= LEVEL_FLOOR:
            kind, src, target, sig = "wazuh", d.get("srcip"), host, r.get("description", "?")
        else:
            routine[host] = routine.get(host, 0) + 1
            continue
        when = _when(a)
        g = groups.setdefault((kind, src, target, sig), {"kind": kind, "source": src, "target": target, "signature": sig,
                                                          "count": 0, "first": when, "last": when, "level": lvl})
        g["count"] += 1
        g["first"], g["last"], g["level"] = min(g["first"], when), max(g["last"], when), max(g["level"], lvl)
    out = []
    for g in groups.values():
        if g["kind"] == "yara":
            g["inside"], g["source_host"] = True, g["source"]
        else:
            ip = _ip(g["source"])
            g["inside"] = (ip in net) if (ip is not None and net is not None) else None
            g["source_host"] = ip_host.get(str(ip)) if ip is not None else None
        out.append(g)
    out.sort(key=lambda g: (-g["level"], -g["count"], str(g["source"])))
    return out, routine


def _item(host, item, state, detail, owner=None, immediate=False, age=None):
    return {"host": host, "item": item, "state": state, "immediate": immediate, "detail": detail, "owner": owner,
            "source_age": age}


def _status(hosts, recs, end, tz=None):
    server = next((h for h in hosts if h.role == "server"), None)
    srv_repo = None
    if server is not None and recs.get(_short(server.hostname)):
        srv_repo = recs[_short(server.hostname)][-1].get("versions", {}).get("repo")
    out = []
    for h in hosts:
        name = _short(h.hostname)
        rs = recs.get(name)
        if not rs:
            out.append(_item(name, "record", rr.STALE, "no record from this host for the day"))
            continue
        b, at = rs[-1], rs[-1].get("time", 0)
        if h.role == "server":                  # owner 2026-11-07 (option C): the server is always on: strict at day end
            st, det = rr.fresh_state(at, RECORD_EVERY, end)
            det = f"{len(rs)} records; {det}"
        else:                                   # clients are often workstations switched off at night: lenient
            st, det = rr.OK, f"{len(rs)} records; last seen {datetime.fromtimestamp(at, tz).strftime('%H:%M')}"
        out.append(_item(name, "record", st, det, age=end - at))
        repo = b.get("versions", {}).get("repo")
        if h is server:
            out.append(_item(name, "repo", rr.OK if repo else rr.STALE, f"repo {repo}" if repo else "no repo found"))
        elif repo is None or srv_repo is None:
            out.append(_item(name, "repo", rr.STALE, "repo unknown"))
        elif repo == srv_repo:
            out.append(_item(name, "repo", rr.OK, f"same as {_short(server.hostname)}"))
        else:
            out.append(_item(name, "repo", rr.ATTENTION, f"repo {repo} differs from {_short(server.hostname)} ({srv_repo})"))
        for c in b.get("certs", []):
            st, imm, det = rr.cert_state(c["not_before"], c["not_after"], at)
            owner = "30-kanidm-cert" if c["path"].startswith(KANIDM_CERTS) else None
            out.append(_item(name, f"cert {c['path']}", st, det, owner, imm))
        for k in b.get("keys", []):
            st, det = rr.key_state(k.get("expires"), at)
            out.append(_item(name, f"key {k['file']}", st, det, immediate=st == rr.ATTENTION and k.get("expires") is not None
                             and k["expires"] - at <= 7 * DAY))
        sc = b.get("scans", {})
        since = b.get("security_since")
        for key, every, owner in SCANS:
            if key == "yara_full" and sc.get(key) is None and since is not None and at - since <= 8 * DAY:
                out.append(_item(name, key, rr.OK, "first weekly scan not due yet", owner))   # as monitor 73
                continue
            st, det = rr.fresh_state(sc.get(key), every, at)
            out.append(_item(name, key, st, det, owner))
        ok = sc.get("aide_ok")
        out.append(_item(name, "aide_ok", rr.OK if ok else (rr.STALE if ok is None else rr.ATTENTION),
                         {True: "accepted, no changes", False: "changes or mismatch to review"}.get(ok, "no result"),
                         "60-aide-result"))
        has_sys = "cpu" in (b.get("sys") or {})                 # final review I6: a dead sysstat is not invisible
        out.append(_item(name, "sysstat", rr.OK if has_sys else rr.STALE,
                         f"{b['sys'].get('samples', '?')} samples" if has_sys else "no sysstat figures in the last record"))
    return out


def _resources(hosts, recs):
    out = {}
    for h in hosts:
        rs = recs.get(_short(h.hostname))
        if not rs:
            out[_short(h.hostname)] = None
            continue
        sysd = dict(rs[-1].get("sys") or {})
        peak = {}
        for b in rs:
            for dk in (b.get("sys") or {}).get("disk", []):
                peak[dk["mount"]] = max(peak.get(dk["mount"], 0), dk["used_pct"])
        if peak:
            sysd["disk"] = [{"mount": m, "used_pct": p} for m, p in sorted(peak.items())]
        out[_short(h.hostname)] = sysd
    return out


def _trend(resources, previous):
    out = {}
    for host, now in resources.items():
        vals = [p["resources"][host]["cpu"]["avg"] for p in previous
                if (p.get("resources") or {}).get(host) and "cpu" in p["resources"][host]]
        if vals and now:
            out[host] = {"cpu_avg_prev": round(sum(vals) / len(vals), 1), "days": len(vals)}
    return out


def build(day, *, alerts, hosts, site, now, previous):
    from zoneinfo import ZoneInfo
    zone = ZoneInfo(site.get("TIMEZONE") or "UTC")
    start, end = day_bounds(day, zone)
    day_alerts = [a for a in alerts if (w := _when(a)) is not None and start <= w < end]
    recs, bad = _records(day_alerts)
    ip_host = {h.ip: _short(h.hostname) for h in hosts}
    intrusions, routine = _intrusions(day_alerts, site, ip_host)
    status = _status(hosts, recs, end, zone)
    resources = _resources(hosts, recs)
    feeders = ("record", "suricata_stats", "yara_recent")
    stale = sorted({s["host"] for s in status if s["item"] in feeders and s["state"] == rr.STALE})
    return {"day": day.isoformat(), "built": now, "intrusions": intrusions, "routine_counts": routine,
            "status": status, "resources": resources, "trend": _trend(resources, previous),
            "attention": [s for s in status if s["state"] != rr.OK and s["owner"] is None],
            "intrusion_sources_stale": stale,
            "sources": {"alerts": len(day_alerts), "records": {h: len(v) for h, v in recs.items()}, "bad_records": bad}}


def _t(epoch):
    return "-" if epoch is None else datetime.fromtimestamp(epoch).strftime("%H:%M")


def _cell(x):
    """One table cell: untrusted alert text (signatures, descriptions, user names) must not break the signed report's
    layout or a terminal: control characters (incl. ESC) become spaces, backticks are dropped (final review)."""
    s = "".join(" " if (ord(ch) < 32 or ord(ch) == 127) else ch for ch in str(x))
    return s.replace("`", "")


def _rows(d):
    intr = [[i["kind"], str(i["source"]), "inside" if i["inside"] else ("outside" if i["inside"] is False else "?"),
             i["source_host"] or "", str(i["target"]), str(i["signature"]), str(i["count"]), _t(i["first"]), _t(i["last"])]
            for i in d["intrusions"]]
    stat = [[s["host"], s["item"], s["state"], s["detail"], s["owner"] or ""] for s in d["status"]]
    res = []
    for h, r in d["resources"].items():
        if not r:
            res.append([h, "no data", "", "", ""])
            continue
        disk = ", ".join(f"{x['mount']} {x['used_pct']}%" for x in r.get("disk", []))
        res.append([h, f"{r.get('cpu', {}).get('avg', '-')} / {r.get('cpu', {}).get('peak', '-')}",
                    f"{r.get('mem', {}).get('avg_pct', '-')} / {r.get('mem', {}).get('peak_pct', '-')}", disk,
                    f"{r.get('net', {}).get('rx_kbs_avg', '-')} / {r.get('net', {}).get('tx_kbs_avg', '-')}"])
    clean = lambda rows: [[_cell(c) for c in r] for r in rows]
    return clean(intr), clean(stat), clean(res)


def _empty(d, i):
    if i == 0 and d.get("intrusion_sources_stale"):
        return ("No alerts recorded, but this section is incomplete: sources STALE on "
                + ", ".join(d["intrusion_sources_stale"]) + ".")
    return "None for this day."


SECTIONS = (("1. Intrusions", ["kind", "source", "inside/outside", "site host", "target", "signature", "count", "first",
                                "last"]),
            ("2. Security status", ["host", "item", "state", "detail", "watched by"]),
            ("3. Resources", ["host", "CPU % avg / peak", "memory % avg / peak", "disk peak", "net kB/s rx / tx"]))


def render_md(d):
    out = [f"# Daily security review {d['day']}", "",
           f"Built {datetime.fromtimestamp(d['built']).strftime('%Y-%m-%d %H:%M')}. "
           f"Needs attention: {len(d['attention'])}. Sources: {d['sources']['alerts']} alerts, "
           f"records {d['sources']['records'] or 'none'}.", ""]
    for i, ((title, head), rows) in enumerate(zip(SECTIONS, _rows(d))):
        out += [f"## {title}", ""]
        if i == 0 and rows and d.get("intrusion_sources_stale"):
            out += ["Incomplete: sources STALE on " + ", ".join(d["intrusion_sources_stale"]) + ".", ""]
        if not rows:
            out += [_empty(d, i), ""]
            continue
        out += ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        out += ["| " + " | ".join(c.replace("|", "\\|") for c in r) + " |" for r in rows] + [""]
    if d["routine_counts"]:
        out += ["Routine events below level 7: " + ", ".join(f"{h} {n}" for h, n in sorted(d["routine_counts"].items())), ""]
    return "\n".join(out)


def render_html(d):
    e = html.escape
    out = ["<!doctype html><html><head><meta charset=\"utf-8\">",
           f"<title>Daily security review {e(d['day'])}</title>",
           "<style>body{font-family:sans-serif;margin:1.5em}table{border-collapse:collapse}td,th{border:1px solid #999;"
           "padding:2px 6px}</style></head><body>", f"<h1>Daily security review {e(d['day'])}</h1>",
           f"<p>Needs attention: {len(d['attention'])}.</p>"]
    for i, ((title, head), rows) in enumerate(zip(SECTIONS, _rows(d))):
        out.append(f"<h2>{e(title)}</h2>")
        if i == 0 and rows and d.get("intrusion_sources_stale"):
            out.append("<p>Incomplete: sources STALE on " + e(", ".join(d["intrusion_sources_stale"])) + ".</p>")
        if not rows:
            out.append(f"<p>{e(_empty(d, i))}</p>")
            continue
        out.append("<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>")
        out += ["<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in rows]
        out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out)
