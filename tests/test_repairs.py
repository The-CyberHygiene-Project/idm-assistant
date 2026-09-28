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
    seq = iter(reports)
    return Ctx(host="srv1", role=role, case=Case(tmp_path, "t", "symptom text"), collect=lambda: next(seq))


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
