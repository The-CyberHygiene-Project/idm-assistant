import json

import pytest

from engine.case import Case
from engine.repairs import Ctx, Repair, run_repair

HEALTHY = {"schema": "idm-report/1", "host": "srv1", "role": "server", "collected_at": "2026-09-28T20:00:00Z",
           "services": {"cert-renew-kanidm.timer": "active"}, "errors": []}
STOPPED = dict(HEALTHY, services={"cert-renew-kanidm.timer": "inactive"})


class FakeRepair(Repair):
    id = "fake-timer"
    host_role = "server"
    verify_absent = {"ACME_RENEWAL_STOPPED"}

    def __init__(self):
        self.calls = []

    def precheck(self, ctx):
        self.calls.append("precheck")

    def backup(self, ctx):
        self.calls.append("backup"); return {"was": "inactive"}

    def apply(self, ctx):
        self.calls.append("apply")

    def undo(self, ctx, backup):
        self.calls.append(("undo", backup["was"]))

    def describe(self, ctx):
        return "enable the renewal timer on srv1"


def ctx(tmp_path, reports, role="server"):
    seq = list(reports)
    collected = []

    def collect():                                  # repeats the last report once the sequence runs out
        collected.append(1); return seq[min(len(collected), len(seq)) - 1]
    c = Ctx(host="srv1", role=role, case=Case(tmp_path, "t", "symptom text"), collect=collect, sleep=lambda s: None)
    c.collected = collected
    return c


def test_unknown_repair_is_refused(tmp_path):
    assert run_repair("no-such-repair", ctx(tmp_path, []), approve=lambda p: True, registry={}) == "REFUSED"


def test_wrong_host_role_is_refused(tmp_path):
    r = FakeRepair()
    assert run_repair(r.id, ctx(tmp_path, [], role="client"), lambda p: True, registry={r.id: r}) == "REFUSED"
    assert r.calls == []


def test_without_approval_nothing_is_applied(tmp_path):
    r = FakeRepair(); c = ctx(tmp_path, [])
    assert run_repair(r.id, c, approve=lambda p: False, registry={r.id: r}) == "REFUSED"
    assert "apply" not in r.calls and "backup" not in r.calls
    assert json.loads((c.case.dir / "approval-fake-timer.json").read_text())["approved"] is False


def test_fault_still_present_after_apply_is_undone(tmp_path):
    r = FakeRepair(); c = ctx(tmp_path, [STOPPED])          # fresh report after apply still shows the fault
    assert run_repair(r.id, c, lambda p: True, registry={r.id: r}) == "FAILED-UNDONE"
    assert ("undo", "inactive") in r.calls


def test_success_records_the_whole_case(tmp_path):
    r = FakeRepair(); c = ctx(tmp_path, [HEALTHY])
    assert run_repair(r.id, c, lambda p: "enable the renewal timer on srv1" in p, registry={r.id: r}) == "OK"
    for f in ("symptom.txt", "approval-fake-timer.json", "repair.log", "report-after-fake-timer.json", "timings.json", "status.txt"):
        assert (c.case.dir / f).exists(), f
    t = json.loads((c.case.dir / "timings.json").read_text())
    assert {f"fake-timer:{s}" for s in ("precheck", "approval", "backup", "apply", "verify")} <= set(t)


def test_two_repairs_in_one_case_keep_separate_timings(tmp_path):
    a, b = FakeRepair(), FakeRepair(); b.id = "fake-other"
    c = ctx(tmp_path, [HEALTHY, HEALTHY])
    for r in (a, b):
        run_repair(r.id, c, lambda p: True, registry={a.id: a, b.id: b})
    t = json.loads((c.case.dir / "timings.json").read_text())
    assert "fake-timer:apply" in t and "fake-other:apply" in t
    assert (c.case.dir / "approval-fake-timer.json").exists() and (c.case.dir / "approval-fake-other.json").exists()


def test_failing_precheck_stops_before_approval(tmp_path):
    class P(FakeRepair):
        def precheck(self, ctx):
            return "step-ca unhealthy"
    r = P(); asked = []
    assert run_repair(r.id, ctx(tmp_path, []), lambda p: asked.append(p) or True, registry={r.id: r}) == "PRECHECK-FAILED"
    assert asked == [] and "apply" not in r.calls


def test_guided_repair_waits_for_the_user_between_apply_and_verify(tmp_path):
    order = []

    class Guided(FakeRepair):
        id = "guided"
        verify_absent = {"ACME_RENEWAL_STOPPED"}

        def apply(self, ctx):
            order.append("apply")

        def wait_for_user(self, ctx):
            order.append("user-completes")

    def collect():
        order.append("verify-collect"); return HEALTHY

    r = Guided()
    c = Ctx(host="srv1", role="server", case=Case(tmp_path, "g", "s"), collect=collect)
    assert run_repair(r.id, c, lambda p: True, registry={r.id: r}) == "OK"
    assert order == ["apply", "user-completes", "verify-collect"]


class TimerRepair(FakeRepair):
    def verify_present(self, report):
        st = (report.get("services") or {}).get("cert-renew-kanidm.timer")
        return None if st == "active" else f"timer is {st}"


def test_verify_fails_when_the_repaired_evidence_is_missing(tmp_path):
    r = TimerRepair(); c = ctx(tmp_path, [dict(HEALTHY, services={})])   # no finding, but no evidence either
    assert run_repair(r.id, c, lambda p: True, registry={r.id: r}) == "FAILED-UNDONE"
    assert ("undo", "inactive") in r.calls


def test_verify_fails_when_the_fresh_report_has_collection_errors(tmp_path):
    r = FakeRepair(); c = ctx(tmp_path, [dict(HEALTHY, errors=["tls: could not fetch the Kanidm certificate"])])
    assert run_repair(r.id, c, lambda p: True, registry={r.id: r}) == "FAILED-UNDONE"


def test_verify_retries_while_the_service_comes_back(tmp_path):
    r = TimerRepair(); c = ctx(tmp_path, [dict(HEALTHY, errors=["tls: handshake failed"]), HEALTHY])
    assert run_repair(r.id, c, lambda p: True, registry={r.id: r}) == "OK"
    assert len(c.collected) == 2 and not any(isinstance(x, tuple) for x in r.calls)


def test_exception_during_apply_is_undone_and_recorded(tmp_path):
    class Boom(FakeRepair):
        def apply(self, ctx):
            self.calls.append("apply"); raise RuntimeError("step-cli exited 1")
    r = Boom(); c = ctx(tmp_path, [HEALTHY])
    assert run_repair(r.id, c, lambda p: True, registry={r.id: r}) == "ERROR-UNDONE"
    assert ("undo", "inactive") in r.calls
    assert (c.case.dir / "status.txt").read_text() == "ERROR-UNDONE\n"
    assert "RuntimeError" in (c.case.dir / "repair.log").read_text()


def test_role_is_taken_from_the_report_and_the_host_must_match():
    from engine.repairs import target_role
    assert target_role(dict(HEALTHY, role="client", host="client2"), "client2") == "client"
    with pytest.raises(ValueError):
        target_role(HEALTHY, "client2")                     # a report from srv1 cannot authorise work on client2


def test_reset_token_repair_sends_every_command_to_the_case_host(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from engine import labsecrets, repairs
    hosts = []
    fake = SimpleNamespace(run=lambda h, argv, stdin=None, **k: hosts.append(h) or SimpleNamespace(
        stdout="kanidm person credential use-reset-token abcde-fghij-klmno-pqrst"))
    fake.push = lambda h, src, dest: hosts.append(h)
    monkeypatch.setattr(labsecrets, "read_json", lambda n: {"password": "x", "posix_password": None})
    monkeypatch.setattr(labsecrets, "write", lambda n, t: tmp_path / n)
    c = Ctx(host="srv9", role="server", case=Case(tmp_path, "h", "s"), collect=lambda: HEALTHY, remote=fake,
            params={"user": "lab08"})
    repairs.KanidmCredResetToken().apply(c)
    assert hosts and set(hosts) == {"srv9"}


def test_end_of_input_at_the_approval_prompt_counts_as_no(monkeypatch):
    from engine import cli

    def eof(prompt):
        raise EOFError
    monkeypatch.delenv("IDM_TEST_APPROVE", raising=False)
    monkeypatch.setattr("builtins.input", eof)
    assert cli.approver()("Repair x on srv1") is False


@pytest.mark.parametrize("bad", ["../x", "-D", "Lab08", "", "a b", "x" * 40])
def test_reset_token_repair_refuses_bad_user_names_before_anything_runs(tmp_path, bad):
    from engine import repairs
    touched = []
    c = Ctx(host="srv1", role="server", case=Case(tmp_path, "u", "s"), collect=lambda: touched.append(1) or HEALTHY,
            params={"user": bad})
    assert "user name" in repairs.KanidmCredResetToken().precheck(c) and touched == []


def test_approval_record_says_who_when_and_whether_test_mode(tmp_path):
    r = FakeRepair(); c = ctx(tmp_path, [HEALTHY])

    def approve(p):
        return True
    approve.who, approve.test_mode = "operator-x", False
    run_repair(r.id, c, approve, registry={r.id: r})
    a = json.loads((c.case.dir / "approval-fake-timer.json").read_text())
    assert a["by"] == "operator-x" and a["test_mode"] is False and a["at"].endswith("Z")


def test_verify_passes_the_peer_report_to_the_rules(tmp_path, monkeypatch):
    from engine import repairs
    seen = []
    monkeypatch.setattr(repairs, "evaluate", lambda rep, peer=None: seen.append(peer) or [])
    r = FakeRepair(); c = ctx(tmp_path, [HEALTHY]); c.peer = lambda: {"host": "srv1", "role": "server"}
    assert run_repair(r.id, c, lambda p: True, registry={r.id: r}) == "OK"
    assert seen == [{"host": "srv1", "role": "server"}]


class FakeRemote:
    def __init__(self, outputs):
        self.outputs, self.calls = outputs, []

    def run(self, host, argv, stdin=None, **kw):
        from types import SimpleNamespace
        self.calls.append((host, argv[-1]))
        out = next((v for k, v in self.outputs.items() if k in argv[-1]), "")
        return SimpleNamespace(stdout=out)


def test_nsswitch_restore_refuses_when_the_pinned_profile_or_features_are_missing(tmp_path):
    from engine import repairs
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "n", "s"), collect=lambda: HEALTHY,
            remote=FakeRemote({"authselect list-features": "with-faillock\n"}))        # without-nullok missing
    assert "without-nullok" in repairs.NsswitchRestore().precheck(c)


def test_nsswitch_restore_selects_exactly_the_pinned_profile(tmp_path):
    from engine import repairs
    fr = FakeRemote({})
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "n", "s"), collect=lambda: HEALTHY, remote=fr)
    repairs.NsswitchRestore().apply(c)
    cmd = fr.calls[-1][1]
    assert "authselect select custom/kanidm with-faillock without-nullok --force --backup=" in cmd


def test_nsswitch_restore_needs_positive_evidence():
    from engine import repairs
    good = {"nss": {"passwd": "kanidm files", "group": "kanidm files", "initgroups": "kanidm files"},
            "authselect": {"profile": "custom/kanidm", "valid": True}}
    assert repairs.NsswitchRestore().verify_present(good) is None
    assert repairs.NsswitchRestore().verify_present(dict(good, authselect={"profile": "custom/kanidm", "valid": False}))


def test_unixd_refresh_refuses_while_kanidm_is_unreachable(tmp_path):
    from engine import repairs
    down = dict(HEALTHY, role="client", host="client2", tls={},
                errors=["tls: could not fetch the Kanidm certificate (unreachable or handshake failed)"])
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: down)
    assert "unreachable" in repairs.UnixdRefresh().precheck(c)


def test_unixd_refresh_invalidates_then_refetches_the_user(tmp_path):
    from engine import repairs
    fr = FakeRemote({})
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: HEALTHY, remote=fr,
            params={"user": "lab03"})
    repairs.UnixdRefresh().apply(c)
    cmds = " ; ".join(x[1] for x in fr.calls)
    assert "kanidm-unix cache-invalidate" in cmds and "id -Gn lab03" in cmds


def test_unixd_refresh_verifies_against_the_server(tmp_path):
    from engine import repairs
    assert repairs.UnixdRefresh.verify_absent >= {"UNIXD_CACHE_STALE", "UNIXD_OFFLINE"}
