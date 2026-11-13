import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "appliance" / "rpm" / "chp-base" / "monitor.d" / "80-fapolicyd.sh"


def run(tmp_path, active="active", conf="permissive = 0\n", now=1_000_000_000, state_text=None, cli=True, runtime="false", pending=None, start=None):
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(f"#!/bin/bash\necho {active}\n[ {active} = active ]\n"); (b / "systemctl").chmod(0o755)
    if cli:
        (b / "fapolicyd-cli").write_text(
            "#!/bin/bash\n" + (f"echo 'Permissive: {runtime}'; echo 'Denied accesses: 0'\n" if runtime else "exit 1\n")); (b / "fapolicyd-cli").chmod(0o755)
    cf = tmp_path / "fapolicyd.conf"
    if conf is not None:
        cf.write_text(conf)
    sd = tmp_path / "state"; sd.mkdir(exist_ok=True)
    if state_text is not None:
        (sd / "80-fapolicyd.state").write_text(state_text)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_STATE_DIR=str(sd), CHP_NOW=str(now),
               CHP_FAPOLICYD_CONF=str(cf))
    if pending is not None:
        pf = tmp_path / "pending"; pf.write_text(""); os.utime(pf, (pending, pending))
        env["CHP_FSMARK_PENDING"] = str(pf)
    else:
        env["CHP_FSMARK_PENDING"] = str(tmp_path / "nopending")
    env["CHP_FAPOLICYD_START"] = str(start if start is not None else 0)
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
    a = alerts(run(tmp_path, conf="# c\npermissive = 1\n", runtime=""))
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


def test_80_runtime_permissive_with_conf_enforcing_alerts(tmp_path):
    a = alerts(run(tmp_path, conf="permissive = 0\n", runtime="true"))
    assert len(a) == 1 and "permissive" in a[0]


def test_80_runtime_enforcing_wins_over_conf_permissive(tmp_path):
    assert run(tmp_path, conf="permissive = 1\n", runtime="false").startswith("OK fapolicyd active")


def test_80_conf_fallback_when_runtime_unreadable(tmp_path):
    assert len(alerts(run(tmp_path, conf="permissive = 1\n", runtime=""))) == 1
    d = tmp_path / "y"; d.mkdir()
    assert run(d, conf="permissive = 0\n", runtime="").startswith("OK fapolicyd active")


def test_80_cannot_tell_alerts(tmp_path):
    a = alerts(run(tmp_path, conf=None, runtime=""))
    assert len(a) == 1 and "cannot determine fapolicyd mode" in a[0]


def test_80_activating_is_transient_ok(tmp_path):
    out = run(tmp_path, active="activating")
    assert alerts(out) == [] and "activating" in out and out.startswith("OK")


def test_80_missing_unit_is_an_alert_on_a_chp_host(tmp_path):
    a = alerts(run(tmp_path, active="inactive", conf=None, cli=False, runtime=""))
    assert len(a) == 1 and "fapolicyd.service is inactive" in a[0]


def test_80_stuck_activating_alerts_after_30_minutes_and_clears_when_active(tmp_path):
    t0 = 1_000_000_000
    assert alerts(run(tmp_path, active="activating", now=t0)) == []
    assert alerts(run(tmp_path, active="activating", now=t0 + 900)) == []
    a = alerts(run(tmp_path, active="activating", now=t0 + 1800))
    assert len(a) == 1 and "activating since 2001-09-09T01:46:40Z" in a[0]
    assert run(tmp_path, now=t0 + 1900).startswith("OK fapolicyd active")
    assert alerts(run(tmp_path, active="activating", now=t0 + 2000)) == []      # first-seen restarts


def test_80_case_insensitive_permissive(tmp_path):
    assert len(alerts(run(tmp_path, runtime="True"))) == 1
    d = tmp_path / "y"; d.mkdir()
    assert len(alerts(run(d, runtime="YES"))) == 1


def test_80_pending_restart_alerts_until_daemon_restarted(tmp_path):
    a = alerts(run(tmp_path, pending=2000, start=1000))
    assert len(a) == 1 and "restart pending since" in a[0] and "systemctl restart fapolicyd" in a[0]
    d = tmp_path / "z"; d.mkdir()
    assert run(d, pending=2000, start=3000).startswith("OK fapolicyd active")


def test_80_restart_in_the_same_second_counts_as_not_applied(tmp_path):
    # same rule as fapolicyd-fsmark (strictly later = applied), so the helper keeping the marker and check 80 agree
    a = alerts(run(tmp_path, pending=2000, start=2000))
    assert len(a) == 1 and "restart pending since" in a[0]


def _start_from_systemctl(tmp_path, show, date_out="3000"):
    """check 80 reading the daemon start itself: fake systemctl/date record TZ and args."""
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(f'#!/bin/bash\necho "TZ=$TZ $*" >> {tmp_path}/calls\n'
                                 f'if [ "$1" = show ]; then printf "%s\\n" "{show}"; else echo active; fi\nexit 0\n')
    (b / "date").write_text(f'#!/bin/bash\necho "date TZ=$TZ $*" >> {tmp_path}/calls\necho {date_out}\n')
    (b / "fapolicyd-cli").write_text("#!/bin/bash\necho 'Permissive: false'; echo 'Denied accesses: 0'\n")
    for x in b.iterdir():
        x.chmod(0o755)
    (tmp_path / "fapolicyd.conf").write_text("permissive = 0\n")
    pf = tmp_path / "pending"; pf.write_text(""); os.utime(pf, (2000, 2000))
    sd = tmp_path / "state"; sd.mkdir(exist_ok=True)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_STATE_DIR=str(sd), CHP_NOW="1000000000",
               CHP_FAPOLICYD_CONF=str(tmp_path / "fapolicyd.conf"), CHP_FSMARK_PENDING=str(pf))
    env.pop("CHP_FAPOLICYD_START", None)
    r = subprocess.run(["bash", str(S)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout, (tmp_path / "calls").read_text()


def test_80_reads_the_daemon_start_in_utc(tmp_path):
    out, calls = _start_from_systemctl(tmp_path, "Fri 2026-11-13 10:00:00 UTC")
    assert "TZ=UTC show fapolicyd -p ActiveEnterTimestamp --value" in calls
    assert "date TZ=UTC -d Fri 2026-11-13 10:00:00 UTC +%s" in calls
    assert out.startswith("OK fapolicyd active")                 # 3000 > 2000: applied


def test_80_never_started_daemon_counts_as_not_applied(tmp_path):
    out, calls = _start_from_systemctl(tmp_path, "n/a")
    assert "date TZ=UTC" not in calls and "restart pending since" in out
