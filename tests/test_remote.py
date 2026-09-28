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


def test_push_stages_into_a_private_directory(monkeypatch):
    seen = {}
    monkeypatch.setattr(remote.subprocess, "run", lambda cmd, **kw: seen.setdefault("cmds", []).append((cmd, kw)))
    remote.push("srv1", "lab/srv1/", "idm-lab/srv1/")
    (mk, mkkw), (rs, rskw), (ch, chkw) = seen["cmds"]
    assert mk[-1] == "install -d -m 0700 idm-lab/srv1/" and mkkw["stdin"] is remote.subprocess.DEVNULL
    assert rs[:2] == ["rsync", "-a"] and "--chmod=Du=rwx,Dgo=,Fu=rw,Fgo=" in rs and rs[-1] == "srv1:idm-lab/srv1/"
    assert rskw["stdin"] is remote.subprocess.DEVNULL
    # macOS openrsync ignores --chmod and -a copies the source's 0755: tighten the whole tree afterwards.
    assert ch[-1] == "chmod -R go= idm-lab" and chkw["stdin"] is remote.subprocess.DEVNULL
