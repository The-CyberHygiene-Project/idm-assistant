import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
B = ROOT / "appliance" / "rpm" / "chp-base"
S = B / "fapolicyd-fsmark.sh"
CONF = "# fapolicyd\npermissive = 0\nallow_filesystem_mark = 0\nintegrity = none\n"


def apply(tmp_path, flag, conf=CONF, runs=1, no_restart=False, start=None):
    (tmp_path / "flag").write_text(f"FSMARK={flag}\n" if flag is not None else "# nothing\n")
    (tmp_path / "fapolicyd.conf").write_text(conf)
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/calls\n'); (b / "systemctl").chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_FSMARK_CONF=str(tmp_path / "flag"),
               CHP_FAPOLICYD_CONF=str(tmp_path / "fapolicyd.conf"),
               CHP_FSMARK_PENDING=str(tmp_path / "pending"))
    if no_restart:
        env["CHP_NO_RESTART"] = "1"
    if start is not None:
        env["CHP_FAPOLICYD_START"] = str(start)
    for _ in range(runs):
        assert subprocess.run(["bash", str(S)], env=env, capture_output=True, text=True).returncode == 0
    calls = (tmp_path / "calls").read_text() if (tmp_path / "calls").exists() else ""
    return (tmp_path / "fapolicyd.conf").read_text(), calls


def test_shipped_flag_is_off_and_documented():
    t = (B / "fapolicyd-fsmark.conf").read_text()
    assert re.search(r"^FSMARK=0$", t, re.M) and "OFF" in t


def test_off_changes_nothing_even_if_someone_set_it_to_one():
    import tempfile
    d = Path(tempfile.mkdtemp())
    out, calls = apply(d, 0, conf=CONF.replace("mark = 0", "mark = 1"))
    assert out == CONF.replace("mark = 0", "mark = 1") and calls == ""


def test_on_sets_it_once_and_is_idempotent(tmp_path):
    out, calls = apply(tmp_path, 1, runs=2)
    assert out.count("allow_filesystem_mark") == 2 and "allow_filesystem_mark = 1" in out   # marker line + setting
    assert "allow_filesystem_mark = 0" not in out and "permissive = 0" in out and "integrity = none" in out
    assert calls.count("restart fapolicyd") == 1   # fake systemctl exits 0 = active; the second run changes nothing


def test_off_after_on_reverts_only_our_change(tmp_path):
    apply(tmp_path, 1)
    out, _ = apply(tmp_path, 0, conf=(tmp_path / "fapolicyd.conf").read_text())
    assert "allow_filesystem_mark = 0" in out and "chp-managed" not in out and "= 1" not in out


def test_missing_conf_is_a_noop(tmp_path):
    env = dict(os.environ, CHP_FSMARK_CONF=str(tmp_path / "f"), CHP_FAPOLICYD_CONF=str(tmp_path / "none"))
    assert subprocess.run(["bash", str(S)], env=env).returncode == 0


def test_rules_file_ships_empty_of_rules():
    rules = [l for l in (B / "66-chp-fsmark.rules").read_text().splitlines() if l.strip() and not l.startswith("#")]
    assert rules == []


def test_spec_ships_mechanism_check_80_and_bumps_release():
    s = (B / "chp-base.spec").read_text()
    assert "Release:        10.chp" in s
    for needle in ("80-fapolicyd.sh", "%{_libexecdir}/chp/fapolicyd-fsmark", "%config(noreplace) %{_sysconfdir}/chp/fapolicyd-fsmark.conf",
                   "%config(noreplace) %{_sysconfdir}/fapolicyd/rules.d/66-chp-fsmark.rules", "%posttrans"):
        assert needle in s
    br = (B / "build-rpm.sh").read_text()
    for f in ("80-fapolicyd.sh", "fapolicyd-fsmark.sh", "fapolicyd-fsmark.conf", "66-chp-fsmark.rules"):
        assert f in br


def test_no_proof_script_gates_on_fanotify_counts():
    bad = []
    for p in list((ROOT / "lab").glob("iso*/prove.sh")) + list((ROOT / "lab" / "docs-spike").glob("*.sh")) + list((ROOT / "lab" / "security").glob("prove-*.sh")) + [ROOT / "lab" / "host" / "iso1-install-test.sh"]:
        for n, l in enumerate(p.read_text().splitlines(), 1):
            if "FANOTIFY" in l and not ("lower bound" in l and "grep -c" not in l):
                bad.append(f"{p.name}:{n}")
    assert bad == []


def test_admin_set_value_is_not_taken_over(tmp_path):
    c = CONF.replace("mark = 0", "mark = 1")
    out, calls = apply(tmp_path, 1, conf=c)
    assert out == c and calls == "" and not (tmp_path / "pending").exists()


def test_in_transaction_no_restart_but_pending_marker(tmp_path):
    out, calls = apply(tmp_path, 1, no_restart=True)
    assert "allow_filesystem_mark = 1" in out and calls == "" and (tmp_path / "pending").exists()


def test_off_leaves_no_pending_marker(tmp_path):
    apply(tmp_path, 0, no_restart=True)
    assert not (tmp_path / "pending").exists()


def test_spec_posttrans_runs_helper_by_bash_without_restart_and_requires_fapolicyd():
    s = (B / "chp-base.spec").read_text()
    assert "CHP_NO_RESTART=1 /bin/bash %{_libexecdir}/chp/fapolicyd-fsmark" in s
    assert re.search(r"^Requires:\s+fapolicyd$", s, re.M)


def test_stale_pending_marker_is_cleared_once_daemon_restarted(tmp_path):
    (tmp_path / "pending").write_text("")
    os.utime(tmp_path / "pending", (1000, 1000))
    apply(tmp_path, 0, start=2000)
    assert not (tmp_path / "pending").exists()


def test_pending_marker_kept_while_daemon_older(tmp_path):
    (tmp_path / "pending").write_text("")
    os.utime(tmp_path / "pending", (1000, 1000))
    apply(tmp_path, 0, start=500)
    assert (tmp_path / "pending").exists()


def test_write_failure_is_clean(tmp_path):
    import pytest
    if os.geteuid() == 0:
        pytest.skip("root ignores read-only directories")
    d = tmp_path / "ro"; d.mkdir()
    (tmp_path / "flag").write_text("FSMARK=1\n"); (d / "fapolicyd.conf").write_text(CONF)
    d.chmod(0o500)
    try:
        env = dict(os.environ, CHP_FSMARK_CONF=str(tmp_path / "flag"), CHP_FAPOLICYD_CONF=str(d / "fapolicyd.conf"),
                   CHP_FSMARK_PENDING=str(tmp_path / "pending"), CHP_NO_RESTART="1")
        r = subprocess.run(["bash", str(S)], env=env, capture_output=True, text=True)
    finally:
        d.chmod(0o700)
    assert r.returncode == 0 and "could not write" in r.stderr
    assert (d / "fapolicyd.conf").read_text() == CONF and not (tmp_path / "pending").exists()
    assert list(d.glob(".fapolicyd.conf.chp.*")) == []


def test_rewrite_keeps_mode(tmp_path):
    (tmp_path / "fapolicyd.conf").write_text(CONF); (tmp_path / "fapolicyd.conf").chmod(0o640)
    apply(tmp_path, 1, conf=CONF)
    assert oct((tmp_path / "fapolicyd.conf").stat().st_mode & 0o777) == "0o640"


def _pending_run(tmp_path, systemctl_show, date_out="2000"):
    """Run with a pending marker (mtime 1000) and fake systemctl/date that record TZ and args."""
    (tmp_path / "pending").write_text("")
    os.utime(tmp_path / "pending", (1000, 1000))
    (tmp_path / "flag").write_text("FSMARK=0\n"); (tmp_path / "fapolicyd.conf").write_text(CONF)
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(f'#!/bin/bash\necho "TZ=$TZ $*" >> {tmp_path}/calls\n'
                                 f'[ "$1" = show ] && printf "%s\\n" "{systemctl_show}"\nexit 0\n')
    (b / "date").write_text(f'#!/bin/bash\necho "date TZ=$TZ $*" >> {tmp_path}/calls\necho {date_out}\n')
    for x in b.iterdir():
        x.chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_FSMARK_CONF=str(tmp_path / "flag"),
               CHP_FAPOLICYD_CONF=str(tmp_path / "fapolicyd.conf"), CHP_FSMARK_PENDING=str(tmp_path / "pending"))
    env.pop("CHP_FAPOLICYD_START", None)
    r = subprocess.run(["bash", str(S)], env=env, capture_output=True, text=True)
    assert r.returncode == 0 and r.stderr == "", r.stderr
    return (tmp_path / "calls").read_text()


def test_daemon_start_is_read_in_utc(tmp_path):
    calls = _pending_run(tmp_path, "Fri 2026-11-13 10:00:00 UTC")
    assert "TZ=UTC show fapolicyd -p ActiveEnterTimestamp --value" in calls
    assert "date TZ=UTC -d Fri 2026-11-13 10:00:00 UTC +%s" in calls
    assert not (tmp_path / "pending").exists()          # 2000 > 1000: restarted after the marker


def test_empty_or_never_started_daemon_keeps_the_marker(tmp_path):
    for n, show in enumerate(("", "n/a")):
        d = tmp_path / str(n); d.mkdir()
        calls = _pending_run(d, show)
        assert "date " not in calls and (d / "pending").exists(), show


def test_unparsable_start_keeps_the_marker(tmp_path):
    _pending_run(tmp_path, "garbage", date_out="")
    assert (tmp_path / "pending").exists()


def test_restart_in_the_same_second_as_the_marker_keeps_it(tmp_path):
    (tmp_path / "pending").write_text("")
    os.utime(tmp_path / "pending", (1000, 1000))
    apply(tmp_path, 0, start=1000)
    assert (tmp_path / "pending").exists()


def test_values_tested_separately_and_temp_file_trapped():
    s = S.read_text()
    assert 'isnum "$mt" && isnum "$st" && [ "$st" -gt "$mt" ]' in s and '"$mt$st"' not in s
    assert s.index("trap 'rm -f \"$tmp\" 2>/dev/null' EXIT") < s.index("rewrite() {")
    assert "Race:" in s
