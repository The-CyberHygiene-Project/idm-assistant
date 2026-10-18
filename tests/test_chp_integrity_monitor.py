"""chp-integrity monitor checks (spec §5.3): they only ever print OK/ALERT lines; they never repair."""
import os
import subprocess
from pathlib import Path

M = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-integrity" / "monitor.d"
NOW = 1760100000


def check(tmp_path, name, timer_active=True, db=True, baseline=None, last=None, pinned=None):
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(f"#!/bin/bash\nexit {0 if timer_active else 3}\n"); (b / "systemctl").chmod(0o755)
    st = tmp_path / "state"; st.mkdir(exist_ok=True)
    if db:
        (tmp_path / "aide.db.gz").write_bytes(b"db")
    for f, v in (("baseline", baseline), ("last-result", last), ("pinned", pinned)):
        if v is not None:
            (st / f).write_text(v)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_AIDE_STATE=str(st), CHP_AIDE_DB=str(tmp_path / "aide.db.gz"),
               CHP_NOW=str(NOW))
    r = subprocess.run(["bash", str(M / name)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def last(exit_="0", match="yes", epoch=NOW - 3600, a="0", r="0", c="0"):
    return f"TIME=t\nEPOCH={epoch}\nEXIT={exit_}\nADDED={a}\nREMOVED={r}\nCHANGED={c}\nDB_MATCH={match}\nREPORT=/var/log/aide/x.log\n"


def test_result_clean_is_ok(tmp_path):
    assert check(tmp_path, "60-aide-result.sh", last=last()).startswith("OK")


def test_result_changes_alert(tmp_path):
    out = check(tmp_path, "60-aide-result.sh", last=last("5", a="1", c="2"))
    assert "ALERT AIDE found changes: 1 added, 0 removed, 2 changed" in out and "chp-site aide-accept" in out


def test_result_error_and_mismatch_alert(tmp_path):
    out = check(tmp_path, "60-aide-result.sh", last=last("17", match="no"))
    assert "ALERT AIDE check failed (exit 17)" in out and "ALERT AIDE database does not match" in out


def test_result_no_database_alerts(tmp_path):
    assert "ALERT AIDE has no baseline database" in check(tmp_path, "60-aide-result.sh", db=False)


def test_result_unreadable_is_an_alert(tmp_path):     # Review Focus 4
    for bad in ("", "TIME=t\nEXIT=\n", "garbage without equals\n", "EXIT=5x\n"):
        d = tmp_path / str(abs(hash(bad))); d.mkdir()
        assert "ALERT AIDE last result is unreadable" in check(d, "60-aide-result.sh", last=bad)


def test_stale_ok_recent_and_alert_old(tmp_path):
    assert check(tmp_path, "61-aide-stale.sh", last=last(epoch=NOW - 3600)).startswith("OK")
    d = tmp_path / "old"; d.mkdir()
    assert "ALERT AIDE: no completed check for 27 h" in check(d, "61-aide-stale.sh", last=last(epoch=NOW - 27 * 3600))


def test_stale_uses_baseline_time_before_the_first_check(tmp_path):
    assert check(tmp_path, "61-aide-stale.sh", baseline=f"DB_SHA512=a\nBUILT_EPOCH={NOW - 600}\n").startswith("OK")


def test_stale_timer_inactive_alerts(tmp_path):
    assert "ALERT AIDE daily check timer is not active" in check(tmp_path, "61-aide-stale.sh", timer_active=False, last=last())


def test_stale_unreadable_time_alerts(tmp_path):
    assert "ALERT AIDE: no usable time" in check(tmp_path, "61-aide-stale.sh", last="EPOCH=soon\n")


def test_pin_states(tmp_path):
    assert check(tmp_path, "62-aide-pin.sh", baseline="DB_SHA512=aa\n", pinned="DB_SHA512=aa\n").startswith("OK")
    d = tmp_path / "x"; d.mkdir()
    assert "ALERT AIDE baseline not pinned to the site stick" in check(d, "62-aide-pin.sh", baseline="DB_SHA512=bb\n", pinned="DB_SHA512=aa\n")
    e = tmp_path / "y"; e.mkdir()
    assert check(e, "62-aide-pin.sh").startswith("OK")       # no baseline yet: 60 alerts, not 62
