import subprocess
from pathlib import Path

import pytest

SCAN = Path(__file__).resolve().parents[1] / "lab" / "tools" / "secrets-scan.sh"
# One sample of every secret format this repo's lab scripts produce (all values fake).
LEAKS = {
    "enrol stdout": "TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    "otpauth uri": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256",
    "labNN.json totp": '{"totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}',
    "labNN.json password": '{"password": "Zx9_fakeFAKEfake-123456789"}',
    "labNN.json posix": '{"posix_password": "Zx9_fakeFAKEfake-123456789"}',
    "recover-account": 'new_password: "xjgG4abcdEFGH12345"',
    "reset token": "kanidm person credential use-reset-token pkc2r-5s5we-23ghh-hfg78",
    "api token (JWS)": "eyJhbGciOiJFUzI1NiJ9abcdefghijk.eyJzdWIiOiJ1bml4ZC1jbGllbnQyIn0abc.sig",
    "private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
}


@pytest.mark.parametrize("name", LEAKS)
def test_each_lab_secret_format_is_caught(tmp_path, name):
    f = tmp_path / "leak.txt"
    f.write_text(LEAKS[name] + "\n")
    assert subprocess.run(["bash", str(SCAN), str(f)], capture_output=True).returncode == 1, name


def test_published_example_secret_and_placeholders_pass(tmp_path):
    f = tmp_path / "ok.txt"
    f.write_text("secret=JBSWY3DPEHPK3PXP\nuse-reset-token <token>\n\"password\": \"...\"\n")
    assert subprocess.run(["bash", str(SCAN), str(f)], capture_output=True).returncode == 0
