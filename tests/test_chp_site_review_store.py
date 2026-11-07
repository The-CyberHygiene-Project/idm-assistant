import hashlib
import json
from datetime import date, timedelta

import pytest

from chp_site import review_store as st
from chp_site.sitefile import SiteError

TODAY = date(2026, 11, 8)


def day_files(day):
    return {"day": day.isoformat(), "resources": {}}, f"# review {day}\n", f"<html>{day}</html>"


def test_day_is_written_0700_0600_and_frozen(tmp_path):
    d = st.write_day(date(2026, 11, 7), *day_files(date(2026, 11, 7)), root=tmp_path)
    assert d == tmp_path / "var/lib/chp/review/2026-11-07"
    assert oct(d.stat().st_mode & 0o777) == "0o700"
    assert {p.name: oct(p.stat().st_mode & 0o777) for p in d.iterdir()} == \
        {"report.md": "0o600", "report.html": "0o600", "data.json": "0o600"}
    assert st.report_sha256(d) == hashlib.sha256(b"# review 2026-11-07\n").hexdigest()
    with pytest.raises(SiteError, match="frozen"):
        st.write_day(date(2026, 11, 7), *day_files(date(2026, 11, 7)), root=tmp_path)


def test_first_build_makes_only_yesterday(tmp_path):
    assert st.missing_days(root=tmp_path, today=TODAY) == [date(2026, 11, 7)]


def test_catch_up_builds_each_missing_day_once(tmp_path):
    st.write_day(date(2026, 11, 3), *day_files(date(2026, 11, 3)), root=tmp_path)
    made = []
    def make(day):
        made.append(day); return day_files(day)
    assert st.build_missing(root=tmp_path, today=TODAY, make=make) == [date(2026, 11, d) for d in (4, 5, 6, 7)]
    assert made == [date(2026, 11, d) for d in (4, 5, 6, 7)]
    assert st.build_missing(root=tmp_path, today=TODAY, make=make) == []        # nothing twice


def test_catch_up_goes_back_at_most_31_days(tmp_path):
    st.write_day(date(2026, 8, 1), *day_files(date(2026, 8, 1)), root=tmp_path)
    days = st.missing_days(root=tmp_path, today=TODAY)
    assert len(days) == 31 and days[-1] == date(2026, 11, 7)


def test_prune_keeps_365_days_and_the_ledger(tmp_path):
    for d in (TODAY - timedelta(days=366), TODAY - timedelta(days=365), TODAY - timedelta(days=1)):
        st.write_day(d, *day_files(d), root=tmp_path)
    rd = tmp_path / "var/lib/chp/review"
    (rd / "ledger.jsonl").write_text("{}\n"); (rd / "stick-heads.json").write_text("[]")
    gone = st.prune(root=tmp_path, today=TODAY)
    assert gone == [(TODAY - timedelta(days=366)).isoformat()]
    assert sorted(p.name for p in rd.iterdir()) == sorted(
        [(TODAY - timedelta(days=365)).isoformat(), (TODAY - timedelta(days=1)).isoformat(), "ledger.jsonl", "stick-heads.json"])


def test_previous_days_feed_the_trend(tmp_path):
    for n in (1, 2, 3):
        d = TODAY - timedelta(days=n)
        st.write_day(d, {"day": d.isoformat(), "resources": {"h": {"cpu": {"avg": n}}}}, "x", "x", root=tmp_path)
    prev = st.previous(root=tmp_path, day=TODAY, n=7)
    assert [p["day"] for p in prev] == ["2026-11-07", "2026-11-06", "2026-11-05"]


def test_show_prints_latest_or_given_date(tmp_path):
    for d in (date(2026, 11, 6), date(2026, 11, 7)):
        st.write_day(d, *day_files(d), root=tmp_path)
    assert st.show(root=tmp_path) == "# review 2026-11-07\n"
    assert st.show(root=tmp_path, day=date(2026, 11, 6)) == "# review 2026-11-06\n"
    with pytest.raises(SiteError, match="no review for 2026-11-01"):
        st.show(root=tmp_path, day=date(2026, 11, 1))


def test_show_with_no_reports_says_so(tmp_path):
    with pytest.raises(SiteError, match="no review has been built yet"):
        st.show(root=tmp_path)


def test_nightly_builds_renders_and_prunes(tmp_path):
    import ipaddress
    from chp_site.hosts import Host
    site = {"SUBNET": ipaddress.IPv4Network("192.0.2.0/24"), "TIMEZONE": "America/Denver"}
    hosts = [Host("aa:01", "srv1", "192.0.2.10", "server", "vda")]
    old = TODAY - timedelta(days=400)
    st.write_day(old, *day_files(old), root=tmp_path)
    st.write_day(TODAY - timedelta(days=3), *day_files(TODAY - timedelta(days=3)), root=tmp_path)
    built = st.nightly(root=tmp_path, today=TODAY, site=site, hosts=hosts, alerts=[], now=0)
    assert built == [TODAY - timedelta(days=2), TODAY - timedelta(days=1)]
    y = tmp_path / "var/lib/chp/review" / (TODAY - timedelta(days=1)).isoformat()
    assert "Daily security review" in (y / "report.md").read_text() and "<html>" in (y / "report.html").read_text()
    assert json.loads((y / "data.json").read_text())["status"][0]["state"] == "STALE"     # no records: never clean
    assert not (tmp_path / "var/lib/chp/review" / old.isoformat()).exists()


def test_cli_show_and_build(monkeypatch, capsys, tmp_path):
    from chp_site import cli
    seen = {}
    monkeypatch.setattr(st, "show", lambda **kw: "# shown\n")
    monkeypatch.setattr(st, "nightly", lambda **kw: seen.update(kw) or [date(2026, 11, 7)])
    monkeypatch.setattr(cli, "_load", lambda site: ({"SUBNET": None, "TIMEZONE": "UTC"}, []))
    monkeypatch.setattr("chp_site.wazuh_alerts.load_alerts", lambda base, since: [{"x": 1}])
    assert cli.main(["review"]) == 0 and capsys.readouterr().out == "# shown\n"
    assert cli.main(["review", "build"]) == 0 and "built 2026-11-07" in capsys.readouterr().out
    assert seen["alerts"] == [{"x": 1}]


def test_now_lists_only_immediate_unowned_items(tmp_path):
    import ipaddress, time as _t
    from chp_site.hosts import Host
    from chp_site import review_report as rr
    site = {"SUBNET": ipaddress.IPv4Network("192.0.2.0/24"), "TIMEZONE": "UTC"}
    hosts = [Host("aa:01", "srv1", "192.0.2.10", "server", "vda")]
    now = _t.time()
    body = {"v": 1, "host": "srv1", "time": now - 60, "versions": {"repo": "a"},
            "certs": [{"path": "/etc/step-ca/certs/root_ca.crt", "not_before": now - 3645 * 86400, "not_after": now + 3 * 86400},
                      {"path": "/etc/pki/kanidm/chain.pem", "not_before": now - 23 * 3600, "not_after": now + 600}],
            "keys": [], "scans": {}, "sys": {}}
    a = [{"timestamp": _t.strftime("%Y-%m-%dT%H:%M:%S.000+0000", _t.gmtime(now - 60)), "rule": {"id": "100520", "level": 3},
          "agent": {"name": "srv1"}, "data": {"chp_review": {"body": __import__("json").dumps(body)}}}]
    items = st.immediate(site=site, hosts=hosts, alerts=a, now=now)
    assert [(i["host"], i["item"]) for i in items] == [("srv1", "cert /etc/step-ca/certs/root_ca.crt")]   # Kanidm: monitor 30


def _mon(tmp_path, *, now, today, verify=(), immediate=(), tz="UTC"):
    return st.monitor_lines(root=tmp_path, today=today, now=now, tz=tz, verify_problems=list(verify),
                            immediate_items=list(immediate))


def test_monitor_ok_when_all_is_well(tmp_path):
    import os, time as _t
    d = st.write_day(TODAY - timedelta(days=1), {"day": "x", "attention": []}, "x", "x", root=tmp_path)
    (tmp_path / "var/lib/chp/review/ledger.jsonl").write_text(
        json.dumps({"date": (TODAY - timedelta(days=1)).isoformat()}) + "\n")
    lines = _mon(tmp_path, now=_t.time(), today=TODAY)
    assert len(lines) == 1 and lines[0].startswith("OK")


def test_monitor_alerts_when_yesterdays_review_is_missing_after_1am(tmp_path):
    from datetime import datetime, timezone
    st.write_day(TODAY - timedelta(days=2), {"attention": []}, "x", "x", root=tmp_path)
    at = lambda h: datetime(TODAY.year, TODAY.month, TODAY.day, h, 30, tzinfo=timezone.utc).timestamp()
    assert not any("not built" in x for x in _mon(tmp_path, now=at(0), today=TODAY))          # the 00:20 build may not have run
    assert any("not built" in x and str(TODAY - timedelta(days=1)) in x for x in _mon(tmp_path, now=at(2), today=TODAY))


def test_monitor_alerts_after_2_days_without_a_sign_off(tmp_path):        # owner: 2 days; weekends count
    import os, time as _t
    d = st.write_day(TODAY - timedelta(days=1), {"attention": []}, "x", "x", root=tmp_path)
    now = _t.time()
    os.utime(d, (now - 2 * 86400 + 60, now - 2 * 86400 + 60))
    assert not any("sign-off" in x for x in _mon(tmp_path, now=now, today=TODAY))
    os.utime(d, (now - 2 * 86400 - 60, now - 2 * 86400 - 60))
    assert any(x.startswith("ALERT") and "sign-off" in x for x in _mon(tmp_path, now=now, today=TODAY))


def test_monitor_alerts_each_attention_item_once_per_day(tmp_path):
    import time as _t
    att = [{"host": "srv1", "item": "repo", "detail": "differs from srv1"}]
    st.write_day(TODAY - timedelta(days=1), {"attention": att}, "x", "x", root=tmp_path)
    first = _mon(tmp_path, now=_t.time(), today=TODAY)
    assert any("srv1: repo: differs from srv1" in x for x in first)
    assert not any("srv1: repo" in x for x in _mon(tmp_path, now=_t.time(), today=TODAY))   # once only


def test_monitor_alerts_on_a_ledger_problem_and_immediate_items(tmp_path):
    import time as _t
    st.write_day(TODAY - timedelta(days=1), {"attention": []}, "x", "x", root=tmp_path)
    lines = _mon(tmp_path, now=_t.time(), today=TODAY, verify=["entry 2 does not follow entry 1"],
                 immediate=[{"host": "srv1", "item": "cert /etc/step-ca/certs/root_ca.crt", "detail": "3 days left"}])
    assert any("ledger check failed: entry 2" in x for x in lines)
    assert any("srv1: cert /etc/step-ca/certs/root_ca.crt: 3 days left" in x for x in lines)
