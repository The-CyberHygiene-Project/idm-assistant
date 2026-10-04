import copy

from engine.findings import evaluate

BASE = {"schema": "idm-report/1", "host": "client2", "role": "client", "collected_at": "2026-10-04T13:20:00Z",
        "errors": [], "time": {"offset_s": 1e-8, "synced": True, "source": "192.168.100.1",
                                "source_offset_s": -50085.0, "source_state": "~"}}


def ids(**time):
    r = copy.deepcopy(BASE); r["time"].update(time)
    return {f.id: f for f in evaluate(r)}


def test_restored_clock_is_skew_even_while_synced():
    f = ids()["TOTP_TIME_SKEW"]
    assert ("chrony rejects its time source as too variable (-50085.0 s off): typical after restoring a snapshot or "
            "image (requirement row 18)") in f.evidence


def test_stale_sample_after_a_real_step_is_not_skew():
    assert "TOTP_TIME_SKEW" not in ids(source_state="*")


def test_unusable_source_is_not_the_restore_case():
    assert "TOTP_TIME_SKEW" not in ids(source_state="?")


def test_small_offset_with_tilde_is_not_skew():
    assert "TOTP_TIME_SKEW" not in ids(source_offset_s=-2.0)


def test_old_reports_without_the_field_behave_as_before():
    r = copy.deepcopy(BASE); del r["time"]["source_state"]
    assert "TOTP_TIME_SKEW" not in {f.id for f in evaluate(r)}


from types import SimpleNamespace

from engine import runbooks
from engine.case import Case
from engine.repairs import REGISTRY, Ctx

R = REGISTRY["time-resync"]


def test_apply_restarts_chronyd_before_stepping(tmp_path):
    calls = []
    remote = SimpleNamespace(run=lambda host, argv, **kw: calls.append(argv[-1]) or SimpleNamespace(stdout=""))
    R.apply(Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: BASE, remote=remote))
    s = calls[-1]
    assert s.index("systemctl restart chronyd") < s.index("chronyc makestep")


def test_verify_refuses_a_stale_synchronized():
    t = dict(BASE["time"]); assert R.verify_present({"time": t})                               # '~', far off
    assert R.verify_present({"time": dict(t, source_state="*", source_offset_s=0.2, offset_s=0.0)}) is None
    assert R.verify_present({"time": dict(t, source_state="*", source_offset_s=40.0, offset_s=0.0)})


def test_verify_unchanged_for_reports_without_the_field():
    assert R.verify_present({"time": {"offset_s": 0.1, "synced": True}}) is None


def test_runbook_wording_restarts_the_time_service():
    assert runbooks.load("TOTP_TIME_SKEW").repair.startswith("Restart the time service and set this workstation's clock")


def test_r1_and_procedure():
    import importlib
    from pathlib import Path
    r1 = importlib.import_module("scenarios.r1")
    assert r1.EXPECT == {"client2": {"TOTP_TIME_SKEW"}} and r1.REPAIRS == [("client2", "time-resync")]
    assert r1.HOSTS == ["client2"] and r1.USER == "lab04"
    root = Path(__file__).resolve().parents[1]
    text = (root / "runbooks" / "procedures" / "after-restore.md").read_text()
    for must in ("Restart chronyd before anything else", "requirement row 18", "TLS_CERT_EXPIRED", "row 19",
                 "ACCOUNT_LOCKED", "on the server too"):
        assert must in text, must
    assert "procedures/after-restore.md" in (root / "runbooks" / "README.md").read_text()


def test_captured_healthy_pair_has_no_findings():
    from pathlib import Path
    from engine.report import load_report
    fx = Path(__file__).parent / "fixtures" / "reports"
    s, c = load_report(fx / "healthy-srv1-restore.json"), load_report(fx / "healthy-client2-restore.json")
    assert c["time"]["source_state"] == "*" and isinstance(c["uptime_s"], int)
    assert evaluate(s) == [] and evaluate(c, s) == []


# --- final review fixes -------------------------------------------------------------------------------------------
def test_verify_ignores_an_unknown_source_state():
    # I1: refclock/peer-only hosts have no '^' line, so source_state is null; the old check decides
    assert R.verify_present({"time": {"offset_s": 0.1, "synced": True, "source_state": None,
                                      "source_offset_s": None}}) is None


def _pre(tmp_path, out):
    remote = SimpleNamespace(run=lambda host, argv, **kw: SimpleNamespace(stdout=out))
    return R.precheck(Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: BASE, remote=remote))


def test_precheck_refuses_a_config_that_will_not_parse(tmp_path):
    # I2: a restart with a broken chrony.conf would leave the host with no time service
    assert "configuration" in _pre(tmp_path, "BAD-CONFIG\n")
    assert _pre(tmp_path, "MS Name\n^~ 192.168.100.1 10 6 37 15 -50085s[-50085s] +/- 317us\n") is None


def test_apply_fails_loudly_and_waits_a_bounded_time(tmp_path):
    calls = []
    remote = SimpleNamespace(run=lambda host, argv, **kw: calls.append(argv[-1]) or SimpleNamespace(stdout=""))
    R.apply(Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: BASE, remote=remote))
    s = calls[-1]
    assert "systemctl restart chronyd || { systemctl start chronyd; exit 1; }" in s    # I2: a failed restart is a failure
    assert "chronyc waitsync 15 0.5 0 2" in s and "waitsync 30 0.5 " not in s              # M3: ~30 s, not ~5 min


def test_restored_clock_gets_no_just_started_note():
    # M4 (re-graded): '~' never clears by itself; telling the operator it often does is wrong advice
    r = copy.deepcopy(BASE); r["uptime_s"] = 60
    f = {x.id: x for x in evaluate(r)}["TOTP_TIME_SKEW"]
    assert not any("started" in e for e in f.evidence)
