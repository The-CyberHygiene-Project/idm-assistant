import ipaddress
import json
from datetime import date, datetime
from zoneinfo import ZoneInfo

from chp_site import review_report as rr
from chp_site.hosts import Host

TZ = ZoneInfo("America/Denver")
DAY = date(2026, 11, 6)
START, END = rr.day_bounds(DAY, TZ)
SITE = {"SUBNET": ipaddress.IPv4Network("192.0.2.0/24"), "TIMEZONE": "America/Denver"}
HOSTS = [Host("aa:01", "srv1", "192.0.2.10", "server", "vda"), Host("aa:02", "ws1", "192.0.2.21", "client", "vda")]
D = 86400


def ts(epoch):
    return datetime.fromtimestamp(epoch, TZ).strftime("%Y-%m-%dT%H:%M:%S.000%z")


def alert(rid, level, host, at, data=None, desc="x", groups=()):
    ag = {"id": "000" if host == "srv1" else "001", "name": "srv1.lab.test" if host == "srv1" else host}
    return {"timestamp": ts(at), "rule": {"id": rid, "level": level, "description": desc, "groups": list(groups)},
            "agent": ag, "data": data or {}}


def record(host, at, **over):
    b = {"v": 1, "host": host + ".lab.test", "time": at,
         "versions": {"chp-site": "0.12.0-1", "chp-security": "0.4.0-1", "repo": "abc123abc123"},
         "certs": [{"path": "/etc/pki/kanidm/chain.pem", "not_before": at - 3600, "not_after": at + 23 * 3600},
                   {"path": "/etc/step-ca/certs/root_ca.crt", "not_before": at - D, "not_after": at + 3000 * D}],
         "keys": [{"file": "/etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH", "fpr": "AB", "expires": at + 200 * D}],
         "scans": {"yara_recent": at - 60, "yara_full": at - 2 * D, "suricata_stats": at - 30, "aide_check": at - 3600,
                   "aide_ok": True},
         "sys": {"cpu": {"avg": 3.2, "peak": 10.0}, "mem": {"avg_pct": 20.3, "peak_pct": 20.3},
                 "net": {"rx_kbs_avg": 6.2, "tx_kbs_avg": 80.4}, "samples": 144, "disk": [{"mount": "/", "used_pct": 40}]}}
    for k, v in over.items():
        b[k] = v
    return alert("100520", 3, host, at, {"chp_review": {"v": "1", "host": b["host"], "body": json.dumps(b)}})


def healthy(extra=()):
    a = []
    for t in range(int(START) + 600, int(END), 600):                 # a record every 10 minutes from both hosts
        a += [record("srv1", t), record("ws1", t)]
    return a + list(extra)


def build(alerts, previous=()):
    return rr.build(DAY, alerts=alerts, hosts=HOSTS, site=SITE, now=END + 1200, previous=list(previous))


def suri(src, dst, sid, sev, at, host="ws1"):
    return alert("100510" if sev == 1 else "86601", 12 if sev == 1 else 3, host, at,
                 {"src_ip": src, "dest_ip": dst, "alert": {"signature_id": str(sid), "signature": f"sig {sid}",
                                                         "severity": str(sev)}}, groups=("suricata",))


def test_intrusions_grouped_by_source_inside_outside_and_named():
    d = build(healthy([suri("192.0.2.21", "192.0.2.10", 2017025, 1, START + 100),
                       suri("192.0.2.21", "192.0.2.10", 2017025, 1, START + 200),
                       suri("203.0.113.9", "192.0.2.10", 2001219, 1, START + 300)]))
    by = {(i["source"], i["signature"]): i for i in d["intrusions"]}
    inside = by[("192.0.2.21", "sig 2017025")]
    assert inside["inside"] is True and inside["source_host"] == "ws1" and inside["count"] == 2
    assert inside["first"] == START + 100 and inside["last"] == START + 200 and inside["target"] == "192.0.2.10"
    out = by[("203.0.113.9", "sig 2001219")]
    assert out["inside"] is False and out["source_host"] is None


def test_level_floor_7_and_routine_counts():
    d = build(healthy([alert("5712", 10, "ws1", START + 50, {"srcip": "203.0.113.5"}, "sshd brute force"),
                       alert("5503", 5, "ws1", START + 60), alert("5503", 5, "ws1", START + 70)]))
    assert [i["signature"] for i in d["intrusions"]] == ["sshd brute force"]
    assert d["routine_counts"] == {"ws1": 2}                      # host records (100520) are not routine events


def test_yara_source_is_the_host_it_was_found_on():
    d = build(healthy([alert("100501", 12, "ws1", START + 99, {"chp_yara": {"event": "match", "file": "/tmp/x",
                                                                            "rules": "SUSP_Just_EICAR"}},
                             "YARA match", groups=("yara",))]))
    y = [i for i in d["intrusions"] if i["kind"] == "yara"][0]
    assert y["source"] == "ws1" and y["source_host"] == "ws1" and y["inside"] is True and y["signature"] == "SUSP_Just_EICAR"


def test_every_host_every_item_has_a_state():
    d = build(healthy())
    hosts = {s["host"] for s in d["status"]}
    assert hosts == {"srv1", "ws1"}
    for h in hosts:
        items = {s["item"] for s in d["status"] if s["host"] == h}
        assert {"record", "repo", "cert /etc/pki/kanidm/chain.pem", "cert /etc/step-ca/certs/root_ca.crt",
                "key /etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH", "yara_recent", "yara_full", "suricata_stats",
                "aide_check", "aide_ok"} <= items
    assert {s["state"] for s in d["status"]} == {"OK"} and d["attention"] == []


def test_alerts_are_assigned_by_local_day_across_dst():          # Review Focus 2: 2026-11-01 is 25 h long in Denver
    s, e = rr.day_bounds(date(2026, 11, 1), TZ)
    assert e - s == 25 * 3600
    late = datetime(2026, 11, 1, 23, 30, tzinfo=TZ).timestamp()
    a = [suri("203.0.113.9", "192.0.2.10", 1, 1, late)]
    d = rr.build(date(2026, 11, 1), alerts=a, hosts=HOSTS, site=SITE, now=e + 60, previous=[])
    assert [i["count"] for i in d["intrusions"]] == [1]
    d2 = rr.build(date(2026, 11, 2), alerts=a, hosts=HOSTS, site=SITE, now=e + 90000, previous=[])
    assert d2["intrusions"] == []


def test_first_day_has_no_trend_and_is_stale_not_clean():       # Review Focus 1
    d = build([])
    assert d["intrusions"] == [] and d["resources"] == {"srv1": None, "ws1": None}
    assert {s["state"] for s in d["status"] if s["item"] == "record"} == {"STALE"}
    assert d["trend"] == {} and d["attention"]                       # a dead feeder is surfaced, never clean


def test_silent_host_is_stale_others_ok():                      # Review Focus 3
    a = [x for x in healthy() if x["agent"]["name"] != "ws1"]
    d = build(a)
    ws = {s["item"]: s["state"] for s in d["status"] if s["host"] == "ws1"}
    srv = {s["item"]: s["state"] for s in d["status"] if s["host"] == "srv1"}
    assert ws == {"record": "STALE"} and set(srv.values()) == {"OK"}


def test_existing_monitor_items_are_shown_not_alerted():
    late = END - 600
    a = healthy([record("srv1", late, certs=[{"path": "/etc/pki/kanidm/chain.pem", "not_before": late - 23 * 3600,
                                                "not_after": late + 3600},
                                               {"path": "/etc/step-ca/certs/root_ca.crt", "not_before": late - 3645 * D,
                                                "not_after": late + 5 * D}])])        # a 10-year CA, 5 days left
    d = build(a)
    st = {s["item"]: s for s in d["status"] if s["host"] == "srv1"}
    assert st["cert /etc/pki/kanidm/chain.pem"]["state"] == "ATTENTION" and st["cert /etc/pki/kanidm/chain.pem"]["owner"]
    att = {(x["host"], x["item"]) for x in d["attention"]}
    assert ("srv1", "cert /etc/pki/kanidm/chain.pem") not in att        # monitor 30 already alerts
    assert ("srv1", "cert /etc/step-ca/certs/root_ca.crt") in att      # new: no monitor watches the CA
    assert [x for x in d["attention"] if x["item"] == "cert /etc/step-ca/certs/root_ca.crt"][0]["immediate"] is True


def test_repo_differing_from_the_server_is_attention():
    late = END - 600
    v = {"chp-site": "0.11.0-4", "chp-security": "0.3.0-3", "repo": "000000000000"}
    d = build(healthy([record("ws1", late, versions=v)]))
    st = {s["item"]: s for s in d["status"] if s["host"] == "ws1"}
    assert st["repo"]["state"] == "ATTENTION" and "differs from srv1" in st["repo"]["detail"]


def test_resources_and_trend_against_previous_days():
    prev = [{"resources": {"srv1": {"cpu": {"avg": 2.0}}, "ws1": {"cpu": {"avg": 1.0}}}}] * 3
    d = build(healthy(), previous=prev)
    assert d["resources"]["ws1"]["cpu"]["avg"] == 3.2 and d["resources"]["ws1"]["disk"] == [{"mount": "/", "used_pct": 40}]
    assert d["trend"]["ws1"]["cpu_avg_prev"] == 1.0


def test_markdown_and_html_render_every_section():
    d = build(healthy([suri("203.0.113.9", "192.0.2.10", 2001219, 1, START + 300)]))
    md, html = rr.render_md(d), rr.render_html(d)
    for s in ("Intrusions", "Security status", "Resources", "203.0.113.9", "outside", "2026-11-06"):
        assert s in md and s in html, s


def test_html_has_no_external_references():
    h = rr.render_html(build(healthy([suri("203.0.113.9", "<script>x</script>", 1, 1, START + 5)])))
    assert "<script" not in h and "http://" not in h and "https://" not in h and "src=" not in h
    assert "&lt;script&gt;" in h                                   # alert text is escaped


def test_weekly_scan_not_due_in_the_first_8_days():                 # as monitor 73 (lab finding, R1 Task 11)
    late = END - 600
    sc = {"yara_recent": late - 60, "yara_full": None, "suricata_stats": late - 30, "aide_check": late - 3600, "aide_ok": True}
    d = build(healthy([record("ws1", late, scans=sc, security_since=late - 2 * D)]))
    st = {s["item"]: s for s in d["status"] if s["host"] == "ws1"}
    assert st["yara_full"]["state"] == "OK" and "not due" in st["yara_full"]["detail"]
    d = build(healthy([record("ws1", late, scans=sc, security_since=late - 9 * D)]))
    assert {s["item"]: s for s in d["status"] if s["host"] == "ws1"}["yara_full"]["state"] == "STALE"


def test_bad_or_future_records_are_skipped_and_counted_not_fatal():      # final review I3
    late = END - 600
    bad = [record("ws1", late), record("ws1", late)]
    bad[0]["data"]["chp_review"]["body"] = json.dumps(["not", "a", "dict"])
    b = json.loads(bad[1]["data"]["chp_review"]["body"]); b["v"] = 2; b["certs"] = [{"path": 1}]
    bad[1]["data"]["chp_review"]["body"] = json.dumps(b)
    junk = record("ws1", late); jb = json.loads(junk["data"]["chp_review"]["body"])
    jb["certs"] = [{"path": "/x"}]; jb["sys"] = {"disk": [{"mount": "/", "used_pct": "lots"}]}
    junk["data"]["chp_review"]["body"] = json.dumps(jb)
    d = build(healthy(bad + [junk]))
    assert d["sources"]["bad_records"] == {"ws1": 3}
    assert {s["state"] for s in d["status"] if s["host"] == "srv1"} == {"OK"}


def test_a_client_cannot_report_for_another_host():                      # final review I4
    a = [x for x in healthy() if x["agent"]["name"] != "srv1.lab.test"]
    for t in range(int(START) + 600, int(END), 600):
        forged = record("srv1", t); forged["agent"] = {"id": "001", "name": "ws1"}       # ws1 claims to be srv1
        a.append(forged)
    d = build(a)
    assert {s["item"]: s["state"] for s in d["status"] if s["host"] == "srv1"} == {"record": "STALE"}
    assert d["sources"]["bad_records"]["ws1"] >= 1


def test_intrusions_marked_incomplete_when_their_sources_are_dead():     # final review I6
    md = rr.render_md(build([]))
    sect = md.split("## 1. Intrusions")[1].split("## 2.")[0]
    assert "None for this day" not in sect and "incomplete" in sect and "srv1" in sect
    healthy_md = rr.render_md(build(healthy()))
    assert "None for this day." in healthy_md.split("## 1. Intrusions")[1].split("## 2.")[0]


def test_dead_sysstat_is_a_stale_status_item():                          # final review I6
    late = END - 600
    d = build(healthy([record("ws1", late, sys={"disk": [{"mount": "/", "used_pct": 40}]})]))
    st = {s["item"]: s for s in d["status"] if s["host"] == "ws1"}
    assert st["sysstat"]["state"] == "STALE" and st["sysstat"]["owner"] is None
    assert {s["item"]: s for s in d["status"] if s["host"] == "srv1"}["sysstat"]["state"] == "OK"


def test_untrusted_alert_text_cannot_break_the_signed_markdown():        # final review (re-graded): injection
    evil = alert("5712", 10, "ws1", START + 50, {"srcip": "203.0.113.5"},
                 "sshd brute force user `x`\n## 2. Security status\n| fake | row |\x1b[31m")
    md = rr.render_md(build(healthy([evil])))
    assert [ln for ln in md.splitlines() if ln.startswith("## 2. Security status")] == ["## 2. Security status"]
    assert all(ln.startswith("|") or not ln.startswith("| fake") for ln in md.splitlines())   # no injected row
    assert "\x1b" not in md and "`" not in md


def test_a_client_switched_off_in_the_evening_is_ok_the_server_is_not():  # owner 2026-11-07: option C (final review I10)
    six = datetime(2026, 11, 6, 18, 0, tzinfo=TZ).timestamp()
    a = [x for x in healthy() if rr._when(x) <= six]                          # both hosts go quiet at 18:00
    d = build(a)
    st = {(s["host"], s["item"]): s for s in d["status"]}
    assert st[("ws1", "record")]["state"] == "OK" and "last seen 18:00" in st[("ws1", "record")]["detail"]
    assert st[("srv1", "record")]["state"] == "STALE"
    assert ("ws1", "record") not in {(x["host"], x["item"]) for x in d["attention"]}
