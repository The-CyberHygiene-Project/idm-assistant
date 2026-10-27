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
    got = list(wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__))
    assert [a["rule"]["id"] for a in got] == ["1", "2"]
    with log.open("a") as fh:
        fh.write("not json\n" + json.dumps(alert(rid="3")) + "\n")
    got = list(wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__))
    assert [a["rule"]["id"] for a in got] == ["3"]                 # restart: no repeats; bad line skipped
    log.unlink(); log.write_text(json.dumps(alert(rid="4")) + "\n")  # rotation: new inode, start at 0
    got = list(wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__))
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
