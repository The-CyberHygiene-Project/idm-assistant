import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "collector" / "idm-collect"


def _block():
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> redact-path"), lines.index("# <<< redact-path")
    return "\n".join(lines[i + 1:j])


def _redact_path(uid):
    sh = f'id() {{ echo {uid}; }}\nIDM_REDACT=/tmp/evil.sed\n{_block()}\necho "$REDACT"'
    return subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()


def test_root_always_uses_the_installed_rules():
    assert _redact_path(0) == "/usr/local/sbin/idm-collect.redact.sed"


def test_non_root_may_point_at_test_rules():
    assert _redact_path(1000) == "/tmp/evil.sed"
