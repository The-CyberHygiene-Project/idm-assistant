"""chp-integrity aide-check / aide-baseline, run with a fake aide binary and fake logger (core 0.2.0 Plan A)."""
import hashlib
import os
import subprocess
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-integrity"
SUMMARY = "Summary:\n  Total number of entries:\t10\n  Added entries:\t\t1\n  Removed entries:\t\t0\n  Changed entries:\t\t2\n"


def setup(tmp_path, aide_body):
    b = tmp_path / "bin"; b.mkdir()
    (b / "aide").write_text("#!/bin/bash\n" + aide_body + "\n"); (b / "aide").chmod(0o755)
    (b / "logger").write_text(f'#!/bin/bash\necho "logger $*" >> {tmp_path}/calls\n'); (b / "logger").chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_AIDE_STATE=str(tmp_path / "state"),
               CHP_AIDE_DB=str(tmp_path / "aide.db.gz"), CHP_AIDE_NEWDB=str(tmp_path / "aide.db.new.gz"),
               CHP_AIDE_LOG=str(tmp_path / "log"), CHP_AIDE_BIN=str(b / "aide"), CHP_FIRSTBOOT_DIR=str(tmp_path / "fb"),
               CHP_AIDE_WAIT="2", CHP_AIDE_POLL="0")
    return env


def rec(p):
    return dict(l.split("=", 1) for l in Path(p).read_text().splitlines() if "=" in l)


def run(script, env):
    return subprocess.run(["bash", str(D / script)], env=env, capture_output=True, text=True)


def test_check_changes_are_counted_and_db_matches(tmp_path):
    env = setup(tmp_path, f'printf "{SUMMARY}"; exit 5')
    db = tmp_path / "aide.db.gz"; db.write_bytes(b"db"); (tmp_path / "state").mkdir()
    (tmp_path / "state" / "baseline").write_text(f"DB_SHA512={hashlib.sha512(b'db').hexdigest()}\n")
    r = run("aide-check.sh", env)
    assert r.returncode == 0, r.stderr
    last = rec(tmp_path / "state" / "last-result")
    assert last["EXIT"] == "5" and last["ADDED"] == "1" and last["REMOVED"] == "0" and last["CHANGED"] == "2"
    assert last["DB_MATCH"] == "yes" and Path(last["REPORT"]).exists() and last["EPOCH"].isdigit()
    assert oct((tmp_path / "state" / "last-result").stat().st_mode & 0o777) == "0o644"
    assert "chp-aide check: exit 5 added=1 removed=0 changed=2 db_match=yes" in (tmp_path / "calls").read_text()


def test_check_replaced_database_is_flagged(tmp_path):
    env = setup(tmp_path, "exit 0")
    (tmp_path / "aide.db.gz").write_bytes(b"swapped"); (tmp_path / "state").mkdir()
    (tmp_path / "state" / "baseline").write_text("DB_SHA512=" + "0" * 128 + "\n")
    run("aide-check.sh", env)
    assert rec(tmp_path / "state" / "last-result")["DB_MATCH"] == "no"


def test_check_aide_error_is_recorded(tmp_path):
    env = setup(tmp_path, 'echo "config error" >&2; exit 17')
    (tmp_path / "aide.db.gz").write_bytes(b"db")
    run("aide-check.sh", env)
    last = rec(tmp_path / "state" / "last-result")
    assert last["EXIT"] == "17" and last["ADDED"] == "0" and last["DB_MATCH"] == "no-baseline"


def test_baseline_builds_once_with_first_boot(tmp_path):
    env = setup(tmp_path, f'[ "$1" = --init ] && echo new > "{tmp_path}/aide.db.new.gz"; exit 0')
    env["CHP_ROLE"] = "client"; (tmp_path / "fb").mkdir(); (tmp_path / "fb" / "client.done").touch()
    r = run("aide-baseline.sh", env)
    assert r.returncode == 0, r.stderr
    b = rec(tmp_path / "state" / "baseline")
    assert b["BUILT_BY"] == "first-boot" and b["DB_SHA512"] == hashlib.sha512(b"new\n").hexdigest()
    assert oct((tmp_path / "state" / "baseline").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "aide.db.gz").stat().st_mode & 0o777) == "0o600"
    (tmp_path / "aide.db.gz").write_bytes(b"kept")
    assert run("aide-baseline.sh", env).returncode == 0 and (tmp_path / "aide.db.gz").read_bytes() == b"kept"


def test_baseline_on_an_existing_host_says_package_install(tmp_path):
    env = setup(tmp_path, f'echo new > "{tmp_path}/aide.db.new.gz"')
    env["CHP_ROLE"] = "server"; (tmp_path / "fb").mkdir(); (tmp_path / "fb" / "server.done").touch()
    (tmp_path / "state").mkdir(); (tmp_path / "state" / "installed-on-existing-host").touch()
    run("aide-baseline.sh", env)
    assert rec(tmp_path / "state" / "baseline")["BUILT_BY"] == "package-install"


def test_baseline_on_the_server_waits_for_server_done(tmp_path):     # Review Focus 5
    env = setup(tmp_path, f'echo new > "{tmp_path}/aide.db.new.gz"')
    env["CHP_ROLE"] = "server"; (tmp_path / "fb").mkdir(); (tmp_path / "fb" / "client.done").touch()
    r = run("aide-baseline.sh", env)
    assert r.returncode == 1 and not (tmp_path / "aide.db.gz").exists()
    assert "server first boot not finished" in (tmp_path / "calls").read_text()


def test_baseline_init_failure_builds_nothing(tmp_path):
    env = setup(tmp_path, "exit 17")
    env["CHP_ROLE"] = "client"; (tmp_path / "fb").mkdir(); (tmp_path / "fb" / "client.done").touch()
    assert run("aide-baseline.sh", env).returncode == 1
    assert not (tmp_path / "aide.db.gz").exists() and not (tmp_path / "state" / "baseline").exists()


def _fake_chp_site(tmp_path, body):
    p = tmp_path / "bin" / "chp-site"
    p.write_text(f'#!/bin/bash\necho "chp-site $*" >> {tmp_path}/calls\n{body}\n'); p.chmod(0o755)


def test_baseline_pins_the_stick_hash_before_aide_init(tmp_path):   # quiet check 2026-10-16
    env = setup(tmp_path, f'echo "aide $*" >> "{tmp_path}/calls"; echo new > "{tmp_path}/aide.db.new.gz"')
    _fake_chp_site(tmp_path, "exit 0")
    env["CHP_ROLE"] = "client"; (tmp_path / "fb").mkdir(); (tmp_path / "fb" / "client.done").touch()
    assert run("aide-baseline.sh", env).returncode == 0
    calls = [l for l in (tmp_path / "calls").read_text().splitlines() if l.startswith(("chp-site", "aide"))]
    assert calls == ["chp-site stick-pin-hash", "aide --init"]


def test_baseline_is_built_even_when_the_stick_hash_step_fails(tmp_path):
    env = setup(tmp_path, f'echo new > "{tmp_path}/aide.db.new.gz"')
    _fake_chp_site(tmp_path, "exit 3")
    env["CHP_ROLE"] = "client"; (tmp_path / "fb").mkdir(); (tmp_path / "fb" / "client.done").touch()
    assert run("aide-baseline.sh", env).returncode == 0 and (tmp_path / "aide.db.gz").exists()
    assert "stick-pin-hash failed" in (tmp_path / "calls").read_text()
