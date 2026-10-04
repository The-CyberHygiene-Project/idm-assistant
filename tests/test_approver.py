"""diwai's review (DIWAI-CR-2026-10-07): a "yes" piped in from a script is not a person's approval.
Approval must be typed at a keyboard; the regression runner's test mode is unchanged."""
import io

from engine import cli


class Keyboard(io.StringIO):
    def isatty(self):
        return True


def test_typed_yes_at_a_keyboard_approves(monkeypatch):
    monkeypatch.delenv("IDM_TEST_APPROVE", raising=False)
    monkeypatch.setattr("sys.stdin", Keyboard("yes\n"))
    assert cli.approver()("Type yes to approve") is True


def test_piped_yes_is_refused_without_reading_it(monkeypatch, capsys):
    monkeypatch.delenv("IDM_TEST_APPROVE", raising=False)
    piped = io.StringIO("yes\n")
    monkeypatch.setattr("sys.stdin", piped)
    assert cli.approver()("Type yes to approve") is False
    assert piped.tell() == 0, "the piped answer must not even be read"
    assert "keyboard" in capsys.readouterr().out


def test_regression_test_mode_still_approves_without_a_keyboard(monkeypatch):
    monkeypatch.setenv("IDM_TEST_APPROVE", "1")
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    a = cli.approver()
    assert a("x") is True and a.test_mode
