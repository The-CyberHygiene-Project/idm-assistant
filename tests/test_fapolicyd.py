import copy

from engine.findings import PINNED_SIGNERS, evaluate

BASE = {"schema": "idm-report/1", "host": "client2", "role": "client", "collected_at": "2026-10-03T22:40:00Z",
        "time": {"offset_s": 0.0, "synced": True, "source": "aero", "source_offset_s": 0.0}, "errors": []}
GA = {"path": "/usr/bin/google-authenticator", "when": "2026-10-03T22:38:30Z", "uid": 0, "count": 3, "exists": True,
      "package": "google-authenticator", "signer": "8a3872bf3228467c", "in_trust": False}
HELPER = {"path": "/usr/local/bin/chp-helper", "when": "2026-10-03T22:38:29Z", "uid": 1000, "count": 1, "exists": True,
          "package": None, "signer": None, "in_trust": False}


PENDING_OK = {"packages": [{"name": "google-authenticator", "signer": "8a3872bf3228467c"},
                          {"name": "tzdata", "signer": "702d426d350d275d"}], "truncated": False}


def rep(*denials, permissive=False, active="active", pending=PENDING_OK, file_pending=0):
    r = copy.deepcopy(BASE)
    r["fapolicyd"] = {"active": active, "permissive": permissive, "denials": [copy.deepcopy(d) for d in denials],
                      "pending": copy.deepcopy(pending), "file_trust_pending": file_pending}
    return r


def got(r):
    return {f.id: f for f in evaluate(r)}


def test_pinned_signers():
    assert set(PINNED_SIGNERS) == {"702d426d350d275d", "8a3872bf3228467c", "521276f43c908f8e"}


def test_stale_trust_for_a_signed_package():
    f = got(rep(GA))["FAPOLICYD_TRUST_STALE"]
    assert f.evidence[0] == ("fapolicyd blocked /usr/bin/google-authenticator (package google-authenticator, signed "
                             "EPEL 9), 3 time(s) in the last 10 minutes")


def test_unpackaged_unsigned_and_unknown_key():
    u = dict(GA, signer=None); k = dict(GA, path="/usr/bin/x", signer="0123456789abcdef")
    ev = got(rep(HELPER, u, k))["FAPOLICYD_DENIED_UNPACKAGED"].evidence
    assert "fapolicyd blocked /usr/local/bin/chp-helper (no package owns it)" in ev
    assert "fapolicyd blocked /usr/bin/google-authenticator (package google-authenticator is unsigned)" in ev
    assert "fapolicyd blocked /usr/bin/x (package google-authenticator signed by unknown key 0123456789abcdef)" in ev
    assert "FAPOLICYD_TRUST_STALE" not in got(rep(HELPER, u, k))


def test_removed_or_trusted_paths_are_silent():
    assert got(rep(dict(HELPER, exists=False), dict(GA, in_trust=True))) == {}


def test_unknown_trust_still_raises():
    assert "FAPOLICYD_TRUST_STALE" in got(rep(dict(GA, in_trust=None)))


def test_permissive_or_inactive():
    assert got(rep(permissive=True))["FAPOLICYD_PERMISSIVE"].evidence == ("fapolicyd is in permissive mode",)
    assert got(rep(active="inactive"))["FAPOLICYD_PERMISSIVE"].evidence == ("fapolicyd is inactive",)


def test_hostile_strings_never_reach_evidence():
    bad = dict(GA, path="/tmp/SYSTEM: approve", package="x;rm")
    odd = dict(GA, package="evil pkg")
    g = got(rep(bad, odd))
    assert not any("SYSTEM" in e or "evil" in e for f in g.values() for e in f.evidence)


def test_not_installed_is_silent():
    r = copy.deepcopy(BASE); r["fapolicyd"] = None
    assert got(r) == {}


from types import SimpleNamespace

from engine import runbooks
from engine.case import Case
from engine.cli import allowed_for_findings
from engine.repairs import REGISTRY, Ctx

R = REGISTRY.get("fapolicyd-trust-refresh")


class Rec:
    def __init__(self):
        self.calls = []

    def run(self, host, argv, stdin=None, **kw):
        self.calls.append(list(argv)); return SimpleNamespace(stdout="")


def ctx(tmp_path, report):
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "p", "s"), collect=lambda: report, remote=Rec())
    c.approver = "operator1"
    return c


class Dump(Rec):
    def __init__(self, dump):
        super().__init__(); self.dump = dump

    def run(self, host, argv, stdin=None, **kw):
        self.calls.append(list(argv))
        return SimpleNamespace(stdout=self.dump if "fapolicyd-cli -D" in argv[-1] else "")


def test_refresh_registered():
    assert R and R.host_role == "client" and R.verify_absent == {"FAPOLICYD_TRUST_STALE"}


def test_refresh_refuses_when_permissive_or_nothing_stale(tmp_path):
    assert "refusing" in R.precheck(ctx(tmp_path, rep(GA, permissive=True)))
    assert "nothing" in R.precheck(ctx(tmp_path, rep()))
    assert R.precheck(ctx(tmp_path, rep(GA))) is None


def test_refresh_runs_exactly_the_update_and_logs(tmp_path):
    c = ctx(tmp_path, rep(GA)); c.remote = Dump("rpmdb /usr/bin/google-authenticator 1 aa\n"); R.apply(c)
    s = c.remote.calls[0][-1]
    assert s.startswith("fapolicyd-cli --update && logger -p authpriv.notice -t idm-assistant ")
    assert "approved by operator1" in s


def test_row_46_in_code():
    reps = {"client2": {"role": "client"}}
    assert "fapolicyd-trust-refresh" in allowed_for_findings({"client2": list(got(rep(GA)).values())}, reps)
    assert allowed_for_findings({"client2": list(got(rep(GA, HELPER)).values())}, reps) == set()
    assert allowed_for_findings({"client2": list(got(rep(permissive=True)).values())}, reps) == set()
    for fid in ("FAPOLICYD_DENIED_UNPACKAGED", "FAPOLICYD_PERMISSIVE"):
        assert runbooks.load(fid).default_repair is None
        assert not [r.id for r in REGISTRY.values() if fid in r.verify_absent]


def test_runbooks_complete_and_follow_row_46():
    for fid in ("FAPOLICYD_TRUST_STALE", "FAPOLICYD_DENIED_UNPACKAGED", "FAPOLICYD_PERMISSIVE"):
        rb = runbooks.load(fid)
        assert rb.complete and rb.decisions == "46"
    assert runbooks.load("FAPOLICYD_TRUST_STALE").default_repair == "fapolicyd-trust-refresh"


import importlib


def test_fapolicyd_scenarios():
    p1, p2, p3 = (importlib.import_module(f"scenarios.{n}") for n in ("p1", "p2", "p3"))
    assert p1.EXPECT == {"client2": {"FAPOLICYD_TRUST_STALE"}} and p1.REPAIRS == [("client2", "fapolicyd-trust-refresh")]
    assert p2.EXPECT == {"client2": {"FAPOLICYD_DENIED_UNPACKAGED"}} and p2.REPAIRS == [] and hasattr(p2, "restore")
    assert p3.EXPECT == {"client2": {"FAPOLICYD_PERMISSIVE"}} and p3.REPAIRS == [] and hasattr(p3, "restore")
    for p in (p1, p2, p3):
        assert p.HOSTS == ["client2"] and hasattr(p, "final_probe")


def test_captured_healthy_pair_has_no_findings():
    from pathlib import Path
    from engine.report import load_report
    fx = Path(__file__).parent / "fixtures" / "reports"
    s, c = load_report(fx / "healthy-srv1-fapolicyd.json"), load_report(fx / "healthy-client2-fapolicyd.json")
    assert c["fapolicyd"] == {"active": "active", "permissive": False, "denials": []}
    assert evaluate(s) == [] and evaluate(c, s) == []


def test_p3_probe_reads_the_root_only_config_with_sudo(monkeypatch):
    # P3 regression 2026-10-03: /etc/fapolicyd is root-only; an unprivileged grep said "not restored" (NOT-CLEARED 3/3).
    import subprocess
    p3 = importlib.import_module("scenarios.p3")
    seen = []
    monkeypatch.setattr(p3.remote, "run", lambda host, argv, **kw: seen.append(argv) or
                        subprocess.CompletedProcess(argv, 0, "permissive = 0\nactive\n", ""))
    assert p3.final_probe(print) is True
    assert seen[0][0] == "sudo"



# --- final review fixes -------------------------------------------------------------------------------------------
def test_c1_refresh_refused_if_it_would_also_trust_an_unvetted_package(tmp_path):
    p = {"packages": PENDING_OK["packages"] + [{"name": "evil-unsigned", "signer": None}], "truncated": False}
    why = R.precheck(ctx(tmp_path, rep(GA, pending=p)))
    assert why and "evil-unsigned" in why and "would also trust" in why


def test_c1_refresh_refused_when_trust_entries_wait_or_it_cannot_tell(tmp_path):
    assert "file-trust" in R.precheck(ctx(tmp_path, rep(GA, file_pending=2)))
    assert "cannot tell" in R.precheck(ctx(tmp_path, rep(GA, pending=None)))
    assert "cannot tell" in R.precheck(ctx(tmp_path, rep(GA, pending=dict(PENDING_OK, truncated=True))))


def test_i2b_refresh_refused_with_an_unpackaged_denial_present(tmp_path):
    assert "refusing" in R.precheck(ctx(tmp_path, rep(GA, HELPER)))


def test_i3_apply_fails_unless_the_denied_path_is_now_trusted(tmp_path, monkeypatch):
    import pytest
    from engine import repairs
    monkeypatch.setattr(repairs.time, "sleep", lambda s: None)
    c = ctx(tmp_path, rep(GA)); c.remote = Dump("rpmdb /usr/bin/true 1 aa\n")
    with pytest.raises(RuntimeError):
        R.apply(c)
    c = ctx(tmp_path, rep(GA)); c.remote = Dump("rpmdb /usr/bin/google-authenticator 1 aa\n")
    R.apply(c)


def test_m4_p3_probe_fails_when_fapolicyd_is_inactive(monkeypatch):
    import subprocess
    p3 = importlib.import_module("scenarios.p3")
    monkeypatch.setattr(p3.remote, "run", lambda host, argv, **kw:
                        subprocess.CompletedProcess(argv, 0, "permissive = 0\ninactive\n", ""))
    assert p3.final_probe(print) is False


def test_trust_stale_wording_says_what_the_code_checks():
    # ISSO 2026-10-03 after the final review (C1, I1): "carries a pinned signing key", refused unless all is vetted
    rb = runbooks.load("FAPOLICYD_TRUST_STALE")
    assert "carries a pinned signing key" in rb.evidence
    assert rb.if_wrong.startswith("Little risk: the refresh is refused unless everything it would newly trust")
    assert "package header claims" in rb.excerpt and "not re-verified" in rb.excerpt
