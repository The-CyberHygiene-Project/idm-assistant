import os
import subprocess
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-base" / "monitor.d" / "76-disk-space.sh"
VGS = "grow with lvextend -r; 342 GB free in chp"


def run(tmp_path, mounts, conf=None, wazuh_target="/var", df_fail=False, vgs=True, now=1_000_000_000):
    """mounts: list of (target, fstype, pct). Fake df answers both the listing and the --output=target query."""
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    rows = "".join(f"echo '{t} {f} {p}%'\n" for t, f, p in mounts)
    (b / "df").write_text(
        "#!/bin/bash\n" + ("exit 1\n" if df_fail else
        'case "$*" in *--output=target\\ *|"--output=target "*) echo Mounted; echo ' + wazuh_target + '; exit 0;; esac\n'
        "echo 'Mounted Type Use%'\n" + rows))
    (b / "df").chmod(0o755)
    if vgs:
        (b / "vgs").write_text("#!/bin/bash\necho '  342.00g'\n"); (b / "vgs").chmod(0o755)
    else:
        (b / "vgs").write_text("#!/bin/bash\nexit 5\n"); (b / "vgs").chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_STATE_DIR=str(tmp_path / "state"),
               CHP_NOW=str(now), CHP_SECURITY_CONF=str(tmp_path / "security.conf"))
    if conf is not None:
        (tmp_path / "security.conf").write_text(conf)
    r = subprocess.run(["bash", str(S)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def alerts(out):
    return [l for l in out.splitlines() if l.startswith("ALERT ")]


def test_76_all_below_85_is_ok(tmp_path):
    out = run(tmp_path, [("/", "xfs", 40), ("/var", "xfs", 84)])
    assert out.startswith("OK") and len(out.splitlines()) == 1


def test_76_alerts_each_volume_at_or_above_85(tmp_path):
    a = alerts(run(tmp_path, [("/var/log", "xfs", 85), ("/var", "xfs", 91)]))
    assert len(a) == 2
    assert "/var/log" in a[0] and "85%" in a[0] and "342 GB free in chp" in a[0]
    assert "/var " in a[1] and "91%" in a[1] and VGS in a[1]


def test_76_skips_the_wazuh_file_system(tmp_path):
    m = [("/var", "xfs", 90)]
    assert alerts(run(tmp_path, m, conf="DATA_DIR=/var/ossec\n")) == []
    (tmp_path / "b").mkdir()
    assert len(alerts(run(tmp_path / "b", m, conf=None))) == 1


def test_76_df_failure_alerts_once_and_ignores_non_xfs(tmp_path):
    a = alerts(run(tmp_path, [], df_fail=True))
    assert len(a) == 1 and "cannot read disk use" in a[0]
    (tmp_path / "x").mkdir()
    assert alerts(run(tmp_path / "x", [("/mnt/iso", "iso9660", 100), ("/run", "tmpfs", 100)])) == []


def test_76_missing_vgs_omits_free_space(tmp_path):
    a = alerts(run(tmp_path, [("/var", "xfs", 90)], vgs=False))
    assert len(a) == 1 and "90%" in a[0] and "free in chp" not in a[0]


def test_76_second_run_is_silent(tmp_path):
    m = [("/var", "xfs", 90)]
    assert len(alerts(run(tmp_path, m))) == 1
    assert alerts(run(tmp_path, m, now=1_000_000_000 + 900)) == []


def test_76_repeats_after_24h(tmp_path):
    m = [("/var", "xfs", 90)]
    run(tmp_path, m)
    assert alerts(run(tmp_path, m, now=1_000_000_000 + 23 * 3600)) == []
    assert len(alerts(run(tmp_path, m, now=1_000_000_000 + 25 * 3600))) == 1


def test_76_clears_when_below(tmp_path):
    hi, lo = [("/var", "xfs", 90)], [("/var", "xfs", 50)]
    assert len(alerts(run(tmp_path, hi))) == 1
    assert alerts(run(tmp_path, lo, now=1_000_000_900)) == []
    assert len(alerts(run(tmp_path, hi, now=1_000_001_800))) == 1


def test_76_df_failure_is_also_deduplicated(tmp_path):
    assert len(alerts(run(tmp_path, [], df_fail=True))) == 1
    assert alerts(run(tmp_path, [], df_fail=True, now=1_000_000_900)) == []
