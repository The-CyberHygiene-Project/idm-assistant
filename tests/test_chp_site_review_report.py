import ipaddress
import pytest
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


def test_report_text_has_no_python_literals():                            # quiet day 2026-11-08 (display)
    noaddr = alert("80710", 10, "ws1", START + 50, desc="Auditd: Device enables promiscuous mode.")
    d = build(healthy([noaddr]))
    md, html = rr.render_md(d), rr.render_html(d)
    head = md.splitlines()[2]
    assert "{" not in head and "'" not in head, head
    assert "records srv1 " in head and "ws1 " in head, head
    row = [ln for ln in md.splitlines() if "promiscuous" in ln][0]
    assert "None" not in row and "| ? |" in row, row
    assert "None" not in html


@pytest.mark.parametrize("bad", ["\x9b", " ", " ", "\x80", "\x9f"])
def test_cell_replaces_c1_controls_and_line_separators(bad):                # final-fix item 8
    out = rr._cell(f"a{bad}b")
    assert out == "a b"


# ---- Task 7: NextCloud in the daily review ----
H = 3600


def docs(at, **over):
    d = {"svc": {"httpd": "active", "php-fpm": "active", "postgresql": "active", "nextcloud-cron.timer": "active"},
         "cert": {"nb": at - 30 * D, "na": at + 330 * D}, "bk": {"st": "OK", "at": at - 5 * H},
         "chk": {"at": at - 4 * H, "ok": True, "kinds": {}, "deg": False, "can": ["refused", "refused"]}, "cr": 0, "sa": 0}
    d.update(over)
    return d


def with_docs(**over):
    late = END - 600
    return healthy([record("srv1", late, documents=docs(late, **over))])


def nc(d):
    return {s["item"]: s for s in d["status"] if s["item"].startswith("nextcloud")}


def test_documents_status_rows_when_enabled():
    d = build(with_docs(cr=2, sa=1))
    rows = nc(d)
    assert set(rows) == {"nextcloud services", "nextcloud certificate", "nextcloud backup", "nextcloud nightly check",
                         "nextcloud share canary", "nextcloud refusals"}
    assert {r["state"] for r in rows.values()} == {"OK"} and rows["nextcloud refusals"]["detail"].startswith("2 contain")
    assert "nextcloud services" in rr.render_md(d)
    bad = nc(build(with_docs(svc={"httpd": "active", "php-fpm": "failed", "postgresql": "active",
                                  "nextcloud-cron.timer": "active"})))
    assert bad["nextcloud services"]["state"] == "ATTENTION" and "php-fpm" in bad["nextcloud services"]["detail"]
    d_deg = build(with_docs(chk={"at": END - 4 * H, "ok": True, "kinds": {}, "deg": True, "can": ["refused", "refused"]}))
    deg = nc(d_deg)
    m = deg["nextcloud database MD5"]
    assert m["state"] == "ATTENTION" and "known limitation, see POA&M" in m["detail"] and m["owner"]
    assert not [x for x in d_deg["attention"] if x["item"] == "nextcloud database MD5"]      # shown, not counted
    old = nc(build(with_docs(chk={"at": END - 40 * H, "ok": True, "kinds": {}, "deg": False, "can": ["refused", "refused"]})))
    assert old["nextcloud nightly check"]["state"] == "STALE"
    alerts = nc(build(with_docs(chk={"at": END - H, "ok": False, "kinds": {"untagged": 3}, "deg": False,
                                     "can": ["CREATED, deleted", "refused"]})))
    assert "untagged 3" in alerts["nextcloud nightly check"]["detail"] and alerts["nextcloud share canary"]["state"] == "ATTENTION"
    short = nc(build(healthy([record("srv1", END - 600, documents=docs(END - 600, cert={"nb": END - 3 * D, "na": END + 1 * H}))])))
    assert short["nextcloud certificate"]["state"] == "ATTENTION"


def test_no_documents_rows_when_off():
    d = build(healthy())
    assert nc(d) == {} and not [s for s in d["status"] if "nextcloud" in s["item"]]
    assert "nextcloud" not in rr.render_md(d).lower()


def test_backup_older_than_26h_is_attention():
    late = END - 600
    st = nc(build(healthy([record("srv1", late, documents=docs(late, bk={"st": "OK", "at": late - 27 * H}))])))["nextcloud backup"]
    assert st["state"] == "ATTENTION" and "26 h" in st["detail"]
    st = nc(build(healthy([record("srv1", late, documents=docs(late, bk={"st": "OK", "at": late - 25 * H}))])))["nextcloud backup"]
    assert st["state"] == "OK"
    st = nc(build(healthy([record("srv1", late, documents=docs(late, bk={"st": "FAILED", "at": late - H}))])))["nextcloud backup"]
    assert st["state"] == "ATTENTION" and "FAILED" in st["detail"]


def test_nextcloud_level12_in_intrusions():
    a = [alert("100601", 12, "srv1", START + 3600, {"remoteAddr": "192.0.2.50", "message": "x"},
               desc="NextCloud: share REFUSED on a no-share team folder (CUI/FCI/Archive): ShareAction", groups=("chp", "nextcloud")),
         alert("100611", 12, "srv1", START + 3700, {}, desc="NextCloud: copy/move OUT of a controlled team folder refused: `evil`\nx",
               groups=("chp", "nextcloud"))]
    d = build(healthy(a))
    kinds = {i["signature"][:30]: i for i in d["intrusions"] if i["kind"] == "nextcloud"}
    assert len(kinds) == 2
    first = [i for i in d["intrusions"] if i["source"] == "192.0.2.50"][0]
    assert first["inside"] is True and first["target"] == "srv1"
    md = rr.render_md(d)
    assert "`" not in md.split("## 1.")[1] and "evil" in md and "192.0.2.50" in md
    assert nc(d) == {}                                            # no documents rows without a documents block


def test_malformed_documents_block_is_skipped_not_fatal():
    late = END - 600
    d = build(healthy([record("srv1", late, documents={"svc": "bad"})]))
    assert d["sources"]["bad_records"].get("srv1") == 1


def test_nextcloud_text_goes_through_cell():
    late = END - 600
    d = build(healthy([record("srv1", late, documents=docs(late, chk={"at": late - H, "ok": False,
              "kinds": {"x`\nx": 1}, "deg": False, "can": ["a`\nb", "refused"]}))]))
    md = rr.render_md(d)
    assert "`" not in md and "x\nx" not in md


def test_old_records_render_byte_for_byte_as_before(monkeypatch):
    import os, time
    from pathlib import Path
    monkeypatch.setenv("TZ", "America/Denver")
    time.tzset()
    try:
        a = healthy([suri("203.0.113.9", "192.0.2.21", 1, 1, START + 4000)])
        out = rr.render_md(build(a))
    finally:
        monkeypatch.undo()
        time.tzset()
    assert out == (Path(__file__).parent / "fixtures" / "review_no_documents.md").read_text()
    assert "nextcloud" not in out.lower()


def test_record_lacking_chk_ok_is_skipped_not_a_crash():
    late = END - 600
    bad = docs(late)
    del bad["chk"]["ok"]
    d = build(healthy([record("srv1", late, documents=bad)]))
    assert d["sources"]["bad_records"].get("srv1") == 1


def test_old_check_makes_canary_and_degraded_stale_and_future_times_attention():
    old = nc(build(with_docs(chk={"at": END - 40 * H, "ok": True, "kinds": {}, "deg": True, "can": ["refused", "refused"]})))
    assert old["nextcloud share canary"]["state"] == "STALE" and old["nextcloud database MD5"]["state"] == "STALE"
    late = END - 600
    fut = nc(build(healthy([record("srv1", late, documents=docs(
        late, bk={"st": "OK", "at": late + 3600}, chk={"at": late + 3600, "ok": True, "kinds": {}, "deg": False,
                                                       "can": ["refused", "refused"]}))])))
    assert fut["nextcloud backup"]["state"] == "ATTENTION" and fut["nextcloud nightly check"]["state"] == "ATTENTION"


def test_only_listed_nextcloud_rules_are_nextcloud_intrusions():
    a = [alert("100699", 12, "srv1", START + 3600, {"remoteAddr": "192.0.2.50"}, desc="other", groups=("nextcloud",)),
         alert("100609", 12, "srv1", START + 3700, {"remoteAddr": "192.0.2.51"}, desc="canary enabled")]
    d = build(healthy(a))
    assert {i["source"]: i["kind"] for i in d["intrusions"] if i["target"] == "srv1"} == {None: "wazuh", "192.0.2.51": "nextcloud"}


def test_nextcloud_rule_set_comes_from_the_defined_rules():
    from chp_site import wazuh as w
    assert "100620" in rr.NC_RULES and "100608" in rr.NC_RULES and "100630" not in rr.NC_RULES
    assert rr.NC_RULES == {i for i in w.NEXTCLOUD_RULE_IDS}


def test_egress_100620_is_a_nextcloud_intrusion():
    a = alert("100620", 12, "srv1", START + 3600, {}, desc="NextCloud egress block tripped")
    d = build(healthy([a]))
    assert [i["kind"] for i in d["intrusions"]] == ["nextcloud"]
    a = alert("100630", 12, "srv1", START + 3600, {}, desc="Kanidm totp")
    assert [i["kind"] for i in build(healthy([a]))["intrusions"]] == ["wazuh"]


# ---- Plan 3 Task 9: the controlled-document workflow's rows (read from the document ledger itself, carry 11) ----
import calendar as _cal
import time as _time


def _iso(epoch):
    return _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(epoch))


def led(kind, at, user="alice", seq=1, **f):
    e = {"seq": seq, "ts": _iso(at), "kind": kind, "user": user, "auth": "bearer", "kanidm_sub": "s", "session_id": "x",
         "request_id": f"{seq:032x}", "doc": "100/CUI_SSP.docx", "file_id": 44, "path": "CUI/Compliance/CUI_SSP_v1.1.docx",
         "sha256": "a" * 64, "cycle": 1, "prev": "0" * 64}
    e.update(f)
    return e


def build_docs(entries, signed=(), error=None, alerts=None):
    dl = {"entries": entries} if error is None else {"error": error}
    return rr.build(DAY, alerts=healthy() if alerts is None else alerts, hosts=HOSTS, site=SITE, now=END + 1200,
                    previous=[], doc_ledger=dl, signed=list(signed))


def doc_rows(d):
    return [s for s in d["status"] if s["item"].startswith("document")]


def test_review_shows_publications():
    ents = [led("checkout", START + 100, seq=1), led("approve", START + 200, user="bob", seq=2),
            led("publish", START + 300, seq=3, cr="CR-2026-0007"),
            led("publish", START - 600, seq=4, cr="CR-2026-0006", path="CUI/Compliance/CUI_Old_v2.0.docx"),  # day before
            led("publish", END + 60, seq=5, cr="CR-2026-0008")]                                             # day after
    d = build_docs(ents)
    rows = doc_rows(d)
    pub = [r for r in rows if r["item"].startswith("document published")]
    assert [r["item"] for r in pub] == ["document published CR-2026-0007"]
    r = pub[0]
    assert r["state"] == "OK" and r["host"] == "srv1" and r["owner"]
    assert "CUI/Compliance/CUI_SSP_v1.1.docx" in r["detail"] and "alice" in r["detail"] and "approved by bob" in r["detail"]
    assert not [a for a in d["attention"] if a["item"].startswith("document")]
    md = rr.render_md(d)
    assert "document published CR-2026-0007" in md and "CR-2026-0006" not in md and "CR-2026-0008" not in md
    none = doc_rows(build_docs([led("checkout", START + 100)]))
    assert [(r["item"], r["state"], r["detail"]) for r in none] == [("document publications", "OK", "none this day")]


def test_review_shows_overrides_since_last():
    from datetime import timedelta
    day = lambda n: rr.day_bounds(DAY - timedelta(days=n), TZ)[0] + 3600     # 01:00 local, n days before DAY
    ents = [led("override", day(5), user="dana", seq=1, reason="before the last sign-off"),
            led("override", day(2), user="dana", seq=2, reason="one-person site, two days ago"),
            led("override", START + 500, user="dana", seq=3, reason="one-person site, today"),
            led("publish", START + 600, seq=4, cr="CR-2026-0009", sha256="a" * 64)]
    signed = [(DAY - timedelta(days=3)).isoformat(), (DAY - timedelta(days=9)).isoformat()]
    d = build_docs(ents, signed=signed)
    ov = [r for r in doc_rows(d) if r["item"].startswith("document override")]
    assert len(ov) == 2 and all(r["state"] == "ATTENTION" and r["owner"] is None for r in ov)
    assert "two days ago" in ov[0]["detail"] and "not yet signed off" in ov[0]["detail"]
    assert "today" in ov[1]["detail"] and "dana" in ov[1]["detail"]
    assert all("before the last sign-off" not in r["detail"] for r in ov)
    # flagged "Needs attention" (the sign-off clears them: the next review starts after the signed day)
    att = [a for a in d["attention"] if a["item"].startswith("document override")]
    assert len(att) == 2
    assert f"Needs attention: {len(d['attention'])}" in rr.render_md(d)
    # the publication that the override allowed says so
    pub = next(r for r in doc_rows(d) if r["item"] == "document published CR-2026-0009")
    assert "ISSO override by dana" in pub["detail"]
    # once DAY-1 is signed, only today's override is still waiting
    d2 = build_docs(ents, signed=signed + [(DAY - timedelta(days=1)).isoformat()])
    assert [r["detail"] for r in doc_rows(d2) if r["item"].startswith("document override")] == [ov[1]["detail"]]
    # never signed at all: every override up to the end of the day is shown
    assert len([r for r in doc_rows(build_docs(ents)) if r["item"].startswith("document override")]) == 3


def test_review_document_ledger_that_does_not_verify():
    d = build_docs([], error="ledger x: entry 4 does not follow entry 3")
    r = doc_rows(d)
    assert [(x["item"], x["state"], x["owner"]) for x in r] == [("document ledger", "ATTENTION", "82-docs-ledger")]
    assert "entry 4" in r[0]["detail"]


def test_review_has_no_document_rows_without_the_ledger():
    d = build(healthy())
    assert not doc_rows(d)


def test_review_document_text_goes_through_cell():
    d = build_docs([led("override", START + 5, user="dana", reason="x`|\nboom"),
                    led("publish", START + 6, seq=2, cr="CR-1`\n", path="a|b`c")])
    md = rr.render_md(d)
    assert "`" not in md and "x`|\nboom" not in md
