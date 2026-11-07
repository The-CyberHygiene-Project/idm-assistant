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
