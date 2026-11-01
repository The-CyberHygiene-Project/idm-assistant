import json

import pytest

from chp_site import wazuh_alerts as wa


def alert(rid="5712", level=10, host="ws1", desc="sshd brute force", ts="2026-10-27T10:00:00.000-0600"):
    return {"timestamp": ts, "rule": {"id": rid, "level": level, "description": desc}, "agent": {"name": host}}


def test_high_alert_is_sent_once_then_grouped():
    f = wa.Forwarder(level=10)
    assert f.feed(alert(), now=0) == ["ws1 rule 5712 level 10: sshd brute force"]
    assert f.feed(alert(), now=60) == [] and f.feed(alert(), now=120) == []
    assert f.flush(now=901) == ["ws1 rule 5712 level 10: sshd brute force (2 more in the last 15 min)"]
    assert f.flush(now=2000) == []


def test_a_new_window_sends_again():
    f = wa.Forwarder(level=10)
    f.feed(alert(), now=0)
    assert f.feed(alert(), now=1000) == ["ws1 rule 5712 level 10: sshd brute force"]


def test_low_alerts_are_not_sent_but_medium_counted_for_the_daily_line():
    f = wa.Forwarder(level=10)
    assert f.feed(alert(level=3), now=0) == []
    assert f.feed(alert(level=8, host="ws1"), now=1) == [] and f.feed(alert(level=7, host="ws2"), now=2) == []
    assert f.daily(now=10) is None                         # first day not over yet
    assert f.daily(now=86401) == "2 medium alerts (levels 7-9) on 2 hosts in the last 24 h; run chp-site alerts"
    assert f.daily(now=86402) is None


def test_lifecycle_alerts_are_sent_whatever_their_level():
    f = wa.Forwarder(level=10)
    assert f.feed(alert(rid="506", level=3, desc="Wazuh agent stopped."), now=0) == [
        "ws1 rule 506 level 3: Wazuh agent stopped."]


def test_threshold_is_respected():
    assert wa.Forwarder(level=12).feed(alert(level=10), now=0) == []


def test_line_survives_missing_fields():
    assert wa.line({}) == "? rule ? level ?: ?"


def test_follow_reads_new_lines_survives_restart_and_rotation(tmp_path):
    log, state = tmp_path / "alerts.json", tmp_path / "state"
    log.write_text(json.dumps(alert(rid="1")) + "\n" + json.dumps(alert(rid="2")) + "\n")
    got = [a for a in wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__) if a is not None]
    assert [a["rule"]["id"] for a in got] == ["1", "2"]
    with log.open("a") as fh:
        fh.write("not json\n" + json.dumps(alert(rid="3")) + "\n")
    got = [a for a in wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__) if a is not None]
    assert [a["rule"]["id"] for a in got] == ["3"]                 # restart: no repeats; bad line skipped
    log.unlink(); log.write_text(json.dumps(alert(rid="4")) + "\n")  # rotation: new inode, start at 0
    got = [a for a in wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__) if a is not None]
    assert [a["rule"]["id"] for a in got] == ["4"]


def test_summarize_by_host_and_rule():
    al = [alert(level=10, ts="2026-10-27T10:00:00.000-0600"), alert(level=10, ts="2026-10-27T10:05:00.000-0600"),
          alert(rid="5902", level=8, host="srv1", desc="New user added", ts="2026-10-27T11:00:00.000-0600"),
          alert(level=3, host="ws2", ts="2026-10-27T11:00:00.000-0600")]
    out = wa.summarize(al, since_epoch=0, min_level=7)
    assert "ws1" in out and "5712" in out and "2" in out and "srv1" in out and "5902" in out and "ws2" not in out


@pytest.mark.parametrize("s,n", [("24h", 86400), ("7d", 604800), ("90m", 5400)])
def test_parse_since(s, n):
    assert wa.parse_since(s) == n


def test_parse_since_rejects_garbage():
    with pytest.raises(ValueError):
        wa.parse_since("soon")


def test_follow_yields_none_when_idle(tmp_path):
    # Task 3 refinement: an idle pass yields None so the forwarder can flush groups with no new alert
    log, state = tmp_path / "alerts.json", tmp_path / "state"
    log.write_text("")
    got = list(wa.follow(log, state, sleep=lambda s: None, stop=iter([False, False, True]).__next__))
    assert got and all(a is None for a in got)


def test_load_alerts_counts_hard_linked_files_once(tmp_path):
    # W1 Task 7 (lab): Wazuh writes logs/alerts/alerts.json as a hard link to logs/alerts/YYYY/Mon/ossec-alerts-DD.json;
    # reading both doubled every count in `chp-site alerts`
    import gzip, os, time
    day = tmp_path / "2026" / "Oct"; day.mkdir(parents=True)
    (day / "ossec-alerts-27.json").write_text(json.dumps(alert()) + "\n")
    os.link(day / "ossec-alerts-27.json", tmp_path / "alerts.json")
    with gzip.open(day / "ossec-alerts-26.json.gz", "wt") as fh:
        fh.write(json.dumps(alert(rid="5902", level=8)) + "\n")
    got = wa.load_alerts(tmp_path, since_epoch=time.time() - 7 * 86400)
    assert sorted(a["rule"]["id"] for a in got) == ["5712", "5902"]


# ---- final-review fix pass (W1) ----
@pytest.mark.parametrize("bad", [[], "x", 7, {"rule": None}, {"rule": {"level": "high"}}, {"agent": None}])
def test_feed_never_raises_on_odd_alerts(bad):
    # final review I4: one odd line crashed the forwarder into a restart loop
    assert wa.Forwarder(level=10).feed(bad, now=0) == []


def test_follow_checkpoints_each_alert(tmp_path):
    # final review I5: a kill mid-pass re-sent the whole pass; the state now advances per alert
    log, state = tmp_path / "alerts.json", tmp_path / "state"
    log.write_text(json.dumps(alert(rid="1")) + "\n" + json.dumps(alert(rid="2")) + "\n")
    g = wa.follow(log, state, sleep=lambda s: None, stop=lambda: True)
    assert next(g)["rule"]["id"] == "1"
    g.close()                                        # killed after the first alert was handled
    got = [a for a in wa.follow(log, state, sleep=lambda s: None, stop=lambda: True) if a is not None]
    assert [a["rule"]["id"] for a in got] == ["2"]


def test_follow_drains_the_old_file_on_rotation(tmp_path):
    # final review I5: alerts written to the old file just before rotation were lost
    import os
    log, state = tmp_path / "alerts.json", tmp_path / "state"
    log.write_text(json.dumps(alert(rid="1")) + "\n")
    stops = iter([False, False, True])
    g = wa.follow(log, state, sleep=lambda s: None, stop=lambda: next(stops))
    assert next(g)["rule"]["id"] == "1"
    assert next(g) is None                            # idle pass
    with log.open("a") as fh:                         # late write to the old file, then rotation
        fh.write(json.dumps(alert(rid="2")) + "\n")
    os.rename(log, tmp_path / "old.json"); log.write_text(json.dumps(alert(rid="3")) + "\n")
    rest = [a["rule"]["id"] for a in g if a is not None]
    assert rest == ["2", "3"]
