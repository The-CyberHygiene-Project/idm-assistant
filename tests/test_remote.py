import shlex

import engine.remote as remote


def test_arguments_are_quoted_so_findings_text_cannot_inject_shell(monkeypatch):
    seen = {}

    class R:
        stdout = "{}"

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return R()

    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    remote.run("srv1", ["echo", "x; touch /tmp/pwned", "$(id)"])
    remote_cmd = seen["cmd"][-1]
    assert shlex.split(remote_cmd) == ["echo", "x; touch /tmp/pwned", "$(id)"]   # each stays ONE literal argument
    assert seen["cmd"][:3] == ["ssh", "-o", "BatchMode=yes"]


def test_ssh_never_reads_our_stdin_when_there_is_nothing_to_send(monkeypatch):
    seen = {}

    class R:
        stdout = "{}"

    monkeypatch.setattr(remote.subprocess, "run", lambda cmd, **kw: seen.update(kw) or R())
    remote.run("srv1", ["true"])                     # would otherwise swallow the operator's typed approval
    assert seen.get("stdin") is remote.subprocess.DEVNULL and seen.get("input") is None
