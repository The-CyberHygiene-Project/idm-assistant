"""chp-base monitor.sh: runs /usr/lib/chp/monitor.d/* (CHP_MONITOR_DIR in tests), logs every ALERT, calls ALERT_HOOK."""
import os
import subprocess
from pathlib import Path

MON = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-base" / "monitor.sh"


def setup(tmp_path, checks, hook=True):
    d = tmp_path / "checks"; d.mkdir()
    for name, body, exe in checks:
        f = d / name; f.write_text("#!/bin/bash\n" + body + "\n"); f.chmod(0o755 if exe else 0o644)
    bin_ = tmp_path / "bin"; bin_.mkdir(); log = tmp_path / "calls"
    (bin_ / "logger").write_text(f'#!/bin/bash\necho "logger $*" >> {log}\n'); (bin_ / "logger").chmod(0o755)
    hookf = tmp_path / "hook.sh"
    hookf.write_text(f'#!/bin/bash\necho "hook $1" >> {log}\n'); hookf.chmod(0o755)
    (bin_ / "chp-site").write_text(f'#!/bin/bash\n[ "$1 $2" = "get ALERT_HOOK" ] && echo "{hookf if hook else ""}"\n')
    (bin_ / "chp-site").chmod(0o755)
    env = dict(os.environ, CHP_MONITOR_DIR=str(d), PATH=f"{bin_}:{os.environ['PATH']}")
    r = subprocess.run(["bash", str(MON)], env=env, capture_output=True, text=True)
    return r, (log.read_text() if log.exists() else "")


def test_all_ok_is_quiet(tmp_path):
    r, calls = setup(tmp_path, [("10-a", "echo OK a", True), ("20-b", "echo OK b", True)])
    assert r.returncode == 0 and calls == ""


def test_alert_is_logged_and_hooked(tmp_path):
    r, calls = setup(tmp_path, [("10-a", "echo OK a", True), ("20-b", "echo ALERT disk on fire", True)])
    assert r.returncode == 1
    assert "logger -p auth.warning -t chp-monitor disk on fire" in calls and "hook disk on fire" in calls


def test_no_hook_configured_still_logs(tmp_path):
    r, calls = setup(tmp_path, [("20-b", "echo ALERT x", True)], hook=False)
    assert r.returncode == 1 and "logger" in calls and "hook" not in calls


def test_non_executable_file_is_skipped(tmp_path):
    r, calls = setup(tmp_path, [("10-a", "echo ALERT should not run", False)])
    assert r.returncode == 0 and calls == ""


def test_a_failing_check_is_an_alert(tmp_path):
    r, calls = setup(tmp_path, [("30-broken", "exit 3", True)])
    assert r.returncode == 1 and "30-broken failed (exit 3)" in calls
