import os
import subprocess
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "appliance" / "release" / "check-key-expiry.sh"


def run(tmp_path, expires, now=1800000000):
    (tmp_path / "trusted-keys.txt").write_text("ABCD wazuh K\n")
    (tmp_path / "K").write_text("key")
    b = tmp_path / "bin"; b.mkdir()
    (b / "gpg").write_text(f"#!/bin/bash\necho 'pub:-:4096:1:X:1470009600:{expires}::-:'\necho 'fpr:::::::::ABCD:'\n")
    (b / "gpg").chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_NOW=str(now))
    return subprocess.run(["bash", str(S), str(tmp_path)], env=env, capture_output=True, text=True)


def test_far_expiry_passes(tmp_path):
    r = run(tmp_path, 1800000000 + 200 * 86400)
    assert r.returncode == 0 and "KEYS OK" in r.stdout


def test_expiry_within_90_days_refuses(tmp_path):
    r = run(tmp_path, 1800000000 + 30 * 86400)
    assert r.returncode == 1 and "expires in 30 days" in r.stdout


def test_expired_refuses(tmp_path):
    r = run(tmp_path, 1800000000 - 86400)
    assert r.returncode == 1 and "EXPIRED" in r.stdout


def test_no_expiry_passes(tmp_path):
    assert run(tmp_path, "").returncode == 0
