import json
from pathlib import Path

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


def test_time_resync_refuses_without_a_reachable_source(tmp_path):
    from engine import repairs
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "t", "s"), collect=lambda: HEALTHY,
            remote=FakeRemote({"chronyc -n sources": "^? 192.168.100.1 10 6 0 - +0ns[+0ns] +/- 0ns\n"}))
    assert "no reachable time source" in repairs.TimeResync().precheck(c)


def test_time_resync_steps_once_and_needs_a_synced_small_offset(tmp_path):
    from engine import repairs
    fr = FakeRemote({})
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "t", "s"), collect=lambda: HEALTHY, remote=fr)
    repairs.TimeResync().apply(c)
    assert "chronyc makestep" in fr.calls[-1][1]
    assert "chronyc burst" in fr.calls[-1][1]                  # fresh samples, so evidence is not stale
    bad = [{"time": {"offset_s": 598.9, "synced": True, "source_offset_s": 600.0}},
           {"time": {"offset_s": 0.0, "synced": False, "source_offset_s": 600.0}}]
    good = {"time": {"offset_s": 0.000000001, "synced": True, "source_offset_s": 600.0}}   # stale sample: fine
    assert all(repairs.TimeResync().verify_present(b) for b in bad)
    assert repairs.TimeResync().verify_present(good) is None


FIXROOT = (Path(__file__).parent / "fixtures" / "kanidm-lab-root.crt").read_text()


def test_fingerprint_matches_openssl():
    from engine import repairs
    assert repairs.fingerprint(FIXROOT) == repairs.PINNED_ROOT


def test_client_ca_trust_refuses_a_root_with_the_wrong_fingerprint(tmp_path):
    from engine import repairs
    lines = FIXROOT.splitlines()
    other = FIXROOT.replace(lines[5], lines[6])                    # a different (corrupt) body
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "c", "s"), collect=lambda: HEALTHY,
            remote=FakeRemote({"root_ca.crt": other}))
    assert "fingerprint" in repairs.ClientCaTrust().precheck(c)


def test_client_ca_trust_installs_via_stdin_and_restarts_unixd(tmp_path):
    from engine import repairs
    fr = FakeRemote({"root_ca.crt": FIXROOT})
    sent = []
    orig = fr.run
    fr.run = lambda host, argv, stdin=None, **kw: (sent.append((host, stdin)), orig(host, argv, stdin))[1]
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "c", "s"), collect=lambda: HEALTHY, remote=fr)
    repairs.ClientCaTrust().apply(c)
    assert ("srv1", None) in sent and ("client2", FIXROOT) in sent
    assert "update-ca-trust extract" in fr.calls[-1][1] and "systemctl restart kanidm-unixd" in fr.calls[-1][1]


def test_unixd_refresh_needs_the_user_lookup_when_a_user_was_asked_for():
    from engine import repairs
    assert repairs.UnixdRefresh().verify_present({"user": "lab03", "user_nss": None})
    assert repairs.UnixdRefresh().verify_present({"user": None, "user_nss": None}) is None


@pytest.mark.parametrize("current", [
    "Profile ID: custom/kanidm\nEnabled features:\n- with-faillock\n- without-nullok\n- with-mkhomedir\n",
    "Profile ID: sssd\nEnabled features:\n- with-faillock\n- without-nullok\n",
])
def test_nsswitch_restore_refuses_to_change_a_hosts_own_profile_or_features(tmp_path, current):
    from engine import repairs
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "n", "s"), collect=lambda: HEALTHY,
            remote=FakeRemote({"authselect list-features": "with-faillock\nwithout-nullok\n",
                               "authselect current": current}))
    assert "does not match" in repairs.NsswitchRestore().precheck(c)


def test_nsswitch_restore_accepts_the_pinned_profile_and_features(tmp_path):
    from engine import repairs
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "n", "s"), collect=lambda: HEALTHY,
            remote=FakeRemote({"authselect list-features": "with-faillock\nwithout-nullok\n",
                               "authselect current": "Profile ID: custom/kanidm\nEnabled features:\n"
                                                     "- with-faillock\n- without-nullok\n"}))
    assert repairs.NsswitchRestore().precheck(c) is None


def test_client_ca_trust_installs_only_the_verified_certificate(tmp_path):
    from engine import repairs
    extra = FIXROOT + FIXROOT.replace(FIXROOT.splitlines()[5], FIXROOT.splitlines()[6])   # a second, other cert
    fr = FakeRemote({"root_ca.crt": extra})
    sent = []
    orig = fr.run
    fr.run = lambda host, argv, stdin=None, **kw: (sent.append((host, stdin)), orig(host, argv, stdin))[1]
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "c", "s"), collect=lambda: HEALTHY, remote=fr)
    repairs.ClientCaTrust().apply(c)
    installed = [s for h, s in sent if h == "client2"][0]
    assert installed.count("BEGIN CERTIFICATE") == 1 and repairs.fingerprint(installed) == repairs.PINNED_ROOT


EXPIRED_SRV = dict(HEALTHY, host="srv1", role="server", time={"offset_s": 0.0, "synced": True, "source_offset_s": 0.0},
                   kanidm_user={"name": "lab06", "exists": True, "account_expire": "2026-09-01T00:00:00Z"})


class RecRemote:
    """Records (host, argv) of every run/push; returns canned stdout."""
    def __init__(self, out=""):
        self.calls, self.out = [], out

    def run(self, host, argv, stdin=None, **kw):
        from types import SimpleNamespace
        self.calls.append((host, list(argv))); return SimpleNamespace(stdout=self.out)

    def push(self, host, src, dest):
        self.calls.append((host, ["push", dest]))


@pytest.mark.parametrize("bad", ["../x", "-D", ""])
def test_account_unexpire_refuses_bad_names_before_anything(tmp_path, bad):
    from engine import repairs
    rr = RecRemote()
    c = Ctx(host="srv1", role="server", case=Case(tmp_path, "a", "s"), collect=lambda: EXPIRED_SRV, remote=rr,
            params={"user": bad})
    assert "user name" in repairs.AccountUnexpire().precheck(c) and rr.calls == []


def test_account_unexpire_warns_that_expiry_may_be_intentional(tmp_path):
    from engine import repairs
    c = Ctx(host="srv1", role="server", case=Case(tmp_path, "a", "s"), collect=lambda: EXPIRED_SRV,
            params={"user": "lab06"})
    assert "expiry may be intentional" in repairs.AccountUnexpire().describe(c)


def test_account_unexpire_clears_exactly_that_user_on_the_case_host(tmp_path, monkeypatch):
    from engine import labsecrets, repairs
    monkeypatch.setattr(labsecrets, "read_json", lambda n: {"password": "x"})
    rr = RecRemote()
    c = Ctx(host="srv9", role="server", case=Case(tmp_path, "a", "s"), collect=lambda: EXPIRED_SRV, remote=rr,
            params={"user": "lab06"})
    saved = repairs.AccountUnexpire().backup(c)
    repairs.AccountUnexpire().apply(c)
    assert saved == {"account_expire": "2026-09-01T00:00:00Z"}
    assert {h for h, _ in rr.calls} == {"srv9"}
    assert ["kanidm", "person", "validity", "expire-at", "lab06", "clear", "-D", "idm_admin"] in [a for _, a in rr.calls]
    repairs.AccountUnexpire().undo(c, saved)
    assert rr.calls[-1][1] == ["kanidm", "person", "validity", "expire-at", "lab06", "2026-09-01T00:00:00Z",
                               "-D", "idm_admin"]


def test_account_unexpire_verifies_the_expiry_is_gone():
    from engine import repairs
    assert repairs.AccountUnexpire().verify_present({"kanidm_user": {"exists": True, "account_expire": None}}) is None
    assert repairs.AccountUnexpire().verify_present({"kanidm_user": {"exists": True, "account_expire": "x"}})


def test_scenario_may_accept_a_declining_model():
    from engine.cli import model_agrees
    assert model_agrees({"valid": True, "repair_id": None}, ["account-unexpire"], may_decline=True)
    assert not model_agrees({"valid": True, "repair_id": None}, ["account-unexpire"], may_decline=False)
    assert model_agrees({"valid": True, "repair_id": "account-unexpire"}, ["account-unexpire"], may_decline=True)


def _mislabelled(paths):
    return dict(HEALTHY, host="client2", role="client",
                selinux={"relabel": [{"path": p, "have": "var_run_t", "want": "kanidm_unixd_var_run_t"} for p in paths]})


def test_restorecon_paths_match_the_collectors_fixed_list():
    from engine import repairs
    text = (Path(__file__).resolve().parents[1] / "collector" / "idm-collect").read_text()
    for p in repairs.SelinuxRestorecon.PATHS:
        assert p in text


@pytest.mark.parametrize("bad", ["/etc/shadow", "/run/kanidm-unixd-evil/x", "/run/kanidm-unixd/a b", "/etc/kanidm/../shadow"])
def test_restorecon_refuses_paths_outside_the_identity_list(tmp_path, bad):
    from engine import repairs
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: _mislabelled([bad]),
            remote=RecRemote())
    assert "outside" in repairs.SelinuxRestorecon().precheck(c)


def test_restorecon_touches_only_the_reported_paths_and_can_undo(tmp_path):
    from engine import repairs
    paths = ["/run/kanidm-unixd", "/run/kanidm-unixd/sock"]
    rr = RecRemote(out="system_u:object_r:var_run_t:s0 /run/kanidm-unixd\nsystem_u:object_r:var_run_t:s0 /run/kanidm-unixd/sock\n")
    c = Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: _mislabelled(paths), remote=rr)
    r = repairs.SelinuxRestorecon()
    assert r.precheck(c) is None
    saved = r.backup(c)
    assert saved["labels"] == {"/run/kanidm-unixd": "system_u:object_r:var_run_t:s0",
                               "/run/kanidm-unixd/sock": "system_u:object_r:var_run_t:s0"}
    r.apply(c)
    script = rr.calls[-1][1][-1]
    assert script == "restorecon -v -- /run/kanidm-unixd /run/kanidm-unixd/sock"
    r.undo(c, saved)
    assert "chcon system_u:object_r:var_run_t:s0 -- /run/kanidm-unixd/sock" in rr.calls[-1][1][-1]


def test_restorecon_verifies_no_label_differs():
    from engine import repairs
    assert repairs.SelinuxRestorecon().verify_present({"selinux": {"relabel": []}}) is None
    assert repairs.SelinuxRestorecon().verify_present(_mislabelled(["/run/kanidm-unixd"]))
