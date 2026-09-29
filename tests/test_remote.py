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


def test_collect_survives_nss_noise_before_the_report(monkeypatch):
    # live 2026-09-29 (C2): with unixd down, sudo's own NSS lookup (Kanidm module) logs an ERROR line to stdout
    # before idm-collect runs; the report must still be read, and the noise counted, not copied.
    class R:
        stdout = ("\x1b[2m2026-09-29T00:03:02Z\x1b[0m \x1b[31mERROR\x1b[0m Unix socket stream setup error\n"
                  '{"schema":"idm-report/1","host":"client2","role":"client","collected_at":"x","errors":["e1"]}\n')
    monkeypatch.setattr(remote.subprocess, "run", lambda cmd, **kw: R())
    rep = remote.collect("client2-diag")
    assert rep["host"] == "client2"
    assert rep["errors"] == ["e1", "collect: 1 non-report line(s) on stdout before the report (not copied)"]
    assert not any("socket" in e for e in rep["errors"])


def _collect_with(monkeypatch, stdout):
    class R:
        pass
    R.stdout = stdout
    monkeypatch.setattr(remote.subprocess, "run", lambda cmd, **kw: R())
    return remote.collect("client2-diag")


def test_a_json_log_line_is_not_mistaken_for_the_report(monkeypatch):
    import pytest
    with pytest.raises(ValueError):                         # collector died; only a JSON-shaped log line came out
        _collect_with(monkeypatch, '{"level":"error","msg":"nss: socket refused"}\n')


def test_the_report_must_be_the_last_line(monkeypatch):
    import pytest
    rep = '{"schema":"idm-report/1","host":"client2","role":"client","collected_at":"x","errors":[]}'
    with pytest.raises(ValueError):
        _collect_with(monkeypatch, rep + "\ntrailing noise\n")
