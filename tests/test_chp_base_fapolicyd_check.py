import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "appliance" / "rpm" / "chp-base" / "monitor.d" / "80-fapolicyd.sh"


def run(tmp_path, active="active", conf="permissive = 0\n", now=1_000_000_000, state_text=None, cli=True):
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(f"#!/bin/bash\necho {active}\n[ {active} = active ]\n"); (b / "systemctl").chmod(0o755)
    if cli:
        (b / "fapolicyd-cli").write_text("#!/bin/bash\nexit 0\n"); (b / "fapolicyd-cli").chmod(0o755)
    cf = tmp_path / "fapolicyd.conf"
    if conf is not None:
        cf.write_text(conf)
    sd = tmp_path / "state"; sd.mkdir(exist_ok=True)
    if state_text is not None:
        (sd / "80-fapolicyd.state").write_text(state_text)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_STATE_DIR=str(sd), CHP_NOW=str(now),
               CHP_FAPOLICYD_CONF=str(cf))
    r = subprocess.run(["bash", str(S)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def alerts(out):
    return [l for l in out.splitlines() if l.startswith("ALERT ")]


def test_80_active_enforcing_is_ok(tmp_path):
    out = run(tmp_path)
    assert out.startswith("OK") and len(out.splitlines()) == 1


def test_80_failed_and_inactive_alert(tmp_path):
    for i, s in enumerate(("failed", "inactive")):
        d = tmp_path / str(i); d.mkdir()
        a = alerts(run(d, active=s))
        assert len(a) == 1 and f"is {s}" in a[0]


def test_80_permissive_alerts(tmp_path):
    a = alerts(run(tmp_path, conf="# c\npermissive = 1\n"))
    assert len(a) == 1 and "permissive" in a[0]


def test_80_failed_and_permissive_alert_separately(tmp_path):
    assert len(alerts(run(tmp_path, active="failed", conf="permissive = 1\n"))) == 2


def test_80_once_per_state_change_then_repeats_after_24h(tmp_path):
    assert len(alerts(run(tmp_path, active="failed"))) == 1
    out = run(tmp_path, active="failed", now=1_000_000_000 + 3600)
    assert alerts(out) == [] and "still failing (alerted 2001-09-09T01:46:40Z)" in out and out.startswith("OK")
    assert len(alerts(run(tmp_path, active="failed", now=1_000_000_000 + 86400))) == 1


def test_80_recovery_forgets_state_so_next_failure_alerts(tmp_path):
    run(tmp_path, active="failed")
    assert run(tmp_path, now=1_000_000_100).startswith("OK fapolicyd active")
    assert len(alerts(run(tmp_path, active="failed", now=1_000_000_200))) == 1


def test_80_garbage_state_and_clock_step_count_as_due(tmp_path):
    assert len(alerts(run(tmp_path, active="failed", state_text="service failed notanumber\n"))) == 1
    d = tmp_path / "x"; d.mkdir()
    assert len(alerts(run(d, active="failed", state_text="service failed 2000000000\n"))) == 1


def test_80_not_installed_is_ok(tmp_path):
    out = run(tmp_path, active="inactive", conf=None, cli=False)
    assert out.startswith("OK") and "not installed" in out
