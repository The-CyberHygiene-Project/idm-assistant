"""(All sample strings below are made up; none is real key or hash material.)
Final review I1 (2026-10-24): prove.sh's noleak filter must drop secret-shaped lines in any case and position, and the
aideinfo stage must not run arbitrary commands (AIDEINFO_CMD was a root-command channel)."""
import re
import subprocess
from pathlib import Path

PROVE = (Path(__file__).resolve().parents[1] / "lab" / "iso5" / "prove.sh").read_text()


def _noleak(lines):
    fn = re.search(r"^noleak\(\) \{.*\}$", PROVE, re.M).group(0)
    return subprocess.run(["bash", "-c", fn + "\nnoleak"], input="\n".join(lines) + "\n",
                          capture_output=True, text=True).stdout.splitlines()


DROP = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "  Zq3r8TuWx2NmKpL4vB7hYdC1sE9aFgJ0oRtUiXcVbM",            # short, indented PEM tail
    'password: "hunter2-not-real"',                           # lower case
    '{"posix_password": "x"}',
    "token eyJhbGciOiJFUzI1NiJ9xxxxxxxx.eyJzdWIiOiJsYWIwMSJ9yyyyyy.sig",
    "123- SHA512    : Qw7eRt5yUi3oPa1sDf9gHj2kLz4xCv6b",       # AIDE hash line from grep -n output
    "             Nm8bVc2xZl5kJh3gFd7sAp1oIu4yTr6e",           # AIDE hash continuation
    "ROOT_CONSOLE_PASSWORD=abc",
    "LUKS_PASSPHRASE=abc",
]
KEEP = [
    "f = ...   i.. ..  : /boot/efi/EFI/rocky/shimx64.efi",
    "Oct 20 03:50:42 iso5-srv systemd[1]: Finished CHP daily AIDE file integrity check (core 0.2.0).",
    "CHANGED=30",
    " Ctime     : 2026-10-18 17:00:33 -0600        | 2026-10-18 17:02:45 -0600",
]


def test_noleak_drops_every_secret_shape():
    assert _noleak(DROP) == []


def test_noleak_keeps_the_diagnostic_lines():
    assert _noleak(KEEP) == KEEP


def test_aideinfo_runs_no_arbitrary_command():
    assert "AIDEINFO_CMD" not in PROVE
