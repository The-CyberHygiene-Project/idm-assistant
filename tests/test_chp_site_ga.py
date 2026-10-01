import types

import pytest

from chp_site import ga
from chp_site.sitefile import SiteError


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, action, fields, after=False):
        self.calls.append((action, dict(fields), after))


def fake_ga(cmds):
    def run(argv, **kw):
        cmds.append(argv)
        if argv[0] == "google-authenticator":
            p = argv[argv.index("-s") + 1]
            open(p, "w").write("SECRETBASE32\n\" TOTP_AUTH\n12345678\n")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def env(tmp_path, local=("root", "chpadmin")):
    pw = tmp_path / "passwd"; pw.write_text("".join(f"{u}:x:0:0::/:/bin/bash\n" for u in local))
    return dict(tokdir=tmp_path / "ga", passwd=pw, resolves=lambda u: u in ("alice", "chpadmin", "root"),
                chown=lambda *a: None, tty=lambda: True)


def test_enrol_creates_a_root_0600_token_with_the_chosen_options(tmp_path):
    cmds, rec = [], Rec()
    p = ga.enrol("alice", "cli1.x.test", "x.test", run=fake_ga(cmds), rec=rec, **env(tmp_path))
    # 0400: what pam_google_authenticator itself writes when it updates the file (seen in Task 4), so one mode everywhere
    assert p == tmp_path / "ga" / "alice" and oct(p.stat().st_mode & 0o777) == "0o400"
    assert oct((tmp_path / "ga").stat().st_mode & 0o777) == "0o700"
    g = cmds[0]
    for opt in (["-t"], ["-d"], ["-f"], ["-r", "3"], ["-R", "30"], ["-w", "3"], ["-e", "5"], ["-l", "alice@cli1.x.test"],
                ["-i", "CHP x.test"], ["-Q", "UTF8"]):
        assert any(g[i:i + len(opt)] == opt for i in range(len(g))), opt
    assert ["restorecon", str(p)] in cmds
    assert [c[0] for c in rec.calls] == ["ga-enrol", "ga-enrol.done"] and rec.calls[0][1]["reset"] == "no"


@pytest.mark.parametrize("user,why", [("chpadmin", "local account"), ("root", "local account"),
                                      ("bob", "does not resolve"), ("Bad", "not a valid")])
def test_refusals_change_nothing(tmp_path, user, why):                      # Review Focus 3
    cmds, rec = [], Rec()
    with pytest.raises(SiteError, match=why):
        ga.enrol(user, "h.x.test", "x.test", run=fake_ga(cmds), rec=rec, **env(tmp_path))
    assert cmds == [] and rec.calls == [] and not (tmp_path / "ga").exists()


def test_existing_token_needs_reset(tmp_path):
    e = env(tmp_path); cmds, rec = [], Rec()
    ga.enrol("alice", "h.x.test", "x.test", run=fake_ga(cmds), rec=Rec(), **e)
    before = (tmp_path / "ga" / "alice").read_text()
    with pytest.raises(SiteError, match="--reset"):
        ga.enrol("alice", "h.x.test", "x.test", run=fake_ga(cmds), rec=rec, **e)
    assert (tmp_path / "ga" / "alice").read_text() == before and rec.calls == []
    ga.enrol("alice", "h.x.test", "x.test", reset=True, run=fake_ga(cmds), rec=rec, **e)
    assert [c[1]["reset"] for c in rec.calls] == ["yes", "yes"]
    assert not list((tmp_path / "ga").glob(".alice*"))                     # no temp file left


def test_failed_generator_keeps_the_old_token(tmp_path):
    e = env(tmp_path)
    ga.enrol("alice", "h.x.test", "x.test", run=fake_ga([]), rec=Rec(), **e)
    before = (tmp_path / "ga" / "alice").read_text()
    bad = lambda argv, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="boom")
    rec = Rec()
    with pytest.raises(SiteError, match="google-authenticator failed"):
        ga.enrol("alice", "h.x.test", "x.test", reset=True, run=bad, rec=rec, **e)
    assert (tmp_path / "ga" / "alice").read_text() == before and [c[0] for c in rec.calls] == ["ga-enrol"]


def test_interactive_enrolment_keeps_the_app_confirmation(tmp_path):       # Task 4 finding: GA 1.09 confirms a code
    cmds = []
    ga.enrol("alice", "h.x.test", "x.test", run=fake_ga(cmds), rec=Rec(), **env(tmp_path))
    assert "-C" not in cmds[0]


def test_no_confirm_for_scripted_use(tmp_path):
    cmds = []
    ga.enrol("alice", "h.x.test", "x.test", no_confirm=True, run=fake_ga(cmds), rec=Rec(),
             **{**env(tmp_path), "tty": lambda: False})
    assert "-C" in cmds[0]


def test_no_terminal_without_no_confirm_is_refused_before_anything(tmp_path):
    cmds, rec = [], Rec()
    with pytest.raises(SiteError, match="needs a terminal"):
        ga.enrol("alice", "h.x.test", "x.test", run=fake_ga(cmds), rec=rec, **{**env(tmp_path), "tty": lambda: False})
    assert cmds == [] and rec.calls == [] and not (tmp_path / "ga").exists()
