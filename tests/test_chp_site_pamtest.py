import subprocess
import sys
from pathlib import Path

import pytest

from chp_site.pamtest import ECHO_OFF, ECHO_ON, ERROR_MSG, TEXT_INFO, answer

PKG = Path(__file__).resolve().parents[1] / "appliance" / "chp-site"


@pytest.mark.parametrize("prompt,style,want", [
    ("Verification code: ", ECHO_OFF, "123456"),
    ("Password: ", ECHO_OFF, "pw"),
    ("One-time code: ", ECHO_ON, "123456"),
    ("Login incorrect", ERROR_MSG, None),
    ("Welcome", TEXT_INFO, None),
])
def test_answer_picks_the_right_secret(prompt, style, want):
    assert answer(prompt, style, "pw", "123456") == want


def test_answer_without_a_code_never_sends_the_password_as_a_code():
    assert answer("Verification code: ", ECHO_OFF, "pw", None) == ""


def cli(*a, stdin=""):
    return subprocess.run([sys.executable, "-m", "chp_site.cli", "pam-test", *a], cwd=PKG, input=stdin,
                          capture_output=True, text=True)


@pytest.mark.parametrize("args", [("gdm password", "alice"), ("gdm-password", "Alice"), ("../etc", "alice")])
def test_bad_service_or_user_refused(args):
    r = cli(*args, stdin="pw\n")
    assert r.returncode == 2 and "not a valid" in r.stderr


def test_secrets_never_echoed(monkeypatch):
    from chp_site import cli as c, pamtest
    monkeypatch.setattr(pamtest, "authenticate", lambda *a, **k: (False, "Authentication failure", ["Verification code: ", "Password: "]))
    import io
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO("s3cretPW\n654321\n")); monkeypatch.setattr(sys, "stdout", out)
    assert c.main(["pam-test", "gdm-password", "alice"]) == 1
    o = out.getvalue()
    assert "PAM_FAIL Authentication failure" in o and "s3cretPW" not in o and "654321" not in o
    assert "prompts=Verification code:|Password:" in o
