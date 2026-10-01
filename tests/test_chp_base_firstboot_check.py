"""chp-base monitor.d/05-firstboot.sh: alert on a failed first boot, a failed/skipped TPM binding, a leftover one-time key."""
import os
import subprocess
from pathlib import Path

CHECK = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-base" / "monitor.d" / "05-firstboot.sh"


def run(tmp_path, failed=(), files=(), uptime=3600, units=("chp-firstboot-common", "chp-server-firstboot")):
    import tempfile
    tmp_path = Path(tempfile.mkdtemp(dir=tmp_path))           # a fresh directory per call (tests call run() twice)
    fb = tmp_path / "fb"; fb.mkdir(); root = tmp_path / "root"; root.mkdir()
    for f in files:
        (fb / f).touch() if not f.startswith("/") else (root / Path(f).name).touch()
    bin_ = tmp_path / "bin"; bin_.mkdir()
    fl = " ".join(failed); un = " ".join(units)
    (bin_ / "systemctl").write_text(f'#!/bin/bash\ncase "$1" in\n is-failed) for u in {fl}; do [ "$3" = "$u" ] || [ "$2" = "$u" ] && exit 0; done; exit 1;;\n'
                                    f' cat) for u in {un}; do [ "$2" = "$u.service" ] && exit 0; done; exit 1;;\nesac\n')
    (bin_ / "systemctl").chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", CHP_FIRSTBOOT_DIR=str(fb), CHP_ROOT_DIR=str(root),
               CHP_UPTIME=str(uptime))
    return subprocess.run(["bash", str(CHECK)], env=env, capture_output=True, text=True).stdout


def test_all_done_is_ok(tmp_path):
    out = run(tmp_path, files=("common.done", "server.done"))
    assert "ALERT" not in out and "OK" in out


def test_failed_server_first_boot_alerts(tmp_path):
    assert "ALERT" in run(tmp_path, failed=("chp-server-firstboot",), files=("common.done",))


def test_first_boot_not_done_after_30_min_alerts(tmp_path):
    assert "ALERT" in run(tmp_path, files=("common.done",), uptime=3600)
    assert "ALERT" not in run(tmp_path, files=("common.done",), uptime=600)     # still running shortly after boot


def test_bind_failed_or_leftover_key_alerts(tmp_path):
    assert "TPM" in run(tmp_path, files=("common.done", "server.done", "common.bind-failed"))
    assert "one-time" in run(tmp_path, files=("common.done", "server.done", "/root/.chp-bind.key"))


def test_client_without_server_unit_needs_no_server_done(tmp_path):
    assert "ALERT" not in run(tmp_path, files=("common.done",), units=("chp-firstboot-common",))
