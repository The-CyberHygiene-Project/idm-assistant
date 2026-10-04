"""After a power outage (spike 2026-10-04): findings on a just-started host, or a workstation whose identity server just
started, say they often clear by themselves. Information only: nothing is blocked."""
import copy
from pathlib import Path

from engine.findings import JUST_BOOTED_S, evaluate

NOTE = "started {} s ago: this often clears by itself within a minute or two; check again before repairing"
CLIENT = {"schema": "idm-report/1", "host": "client2", "role": "client", "collected_at": "2026-10-04T15:00:00Z",
          "time": {"offset_s": 0.0, "synced": True, "source": "aero", "source_offset_s": 0.0}, "errors": [],
          "unixd": {"status": "offline"},
          "services": {"kanidm-unixd": "active", "kanidm-unixd-tasks": "inactive", "sshd": "active"}}
SERVER = {"schema": "idm-report/1", "host": "srv1", "role": "server", "collected_at": "2026-10-04T15:00:00Z",
          "time": {"offset_s": None, "synced": False, "source": "", "source_offset_s": None}, "errors": [],
          "services": {"kanidmd": "active", "step-ca": "active", "named": "active"}}


def run(client_up=None, server_up=None):
    c, s = copy.deepcopy(CLIENT), copy.deepcopy(SERVER)
    c["uptime_s"], s["uptime_s"] = client_up, server_up
    return {f.id: f for f in evaluate(c, s)}, {f.id: f for f in evaluate(s)}


def test_threshold_is_three_minutes():
    assert JUST_BOOTED_S == 180


def test_just_started_workstation_notes_its_transient_findings():
    cl, _ = run(client_up=40)
    assert ("this host " + NOTE.format(40)) in cl["UNIXD_OFFLINE"].evidence
    assert ("this host " + NOTE.format(40)) in cl["SERVICE_DOWN(kanidm-unixd-tasks)"].evidence


def test_workstation_notes_a_just_started_identity_server():
    cl, srv = run(client_up=900, server_up=25)
    assert ("the identity server (srv1) " + NOTE.format(25)) in cl["UNIXD_OFFLINE"].evidence
    assert ("this host " + NOTE.format(25)) in srv["TIME_UNVERIFIED"].evidence


def test_no_note_after_three_minutes_or_when_unknown():
    for up in (180, 3600, None):
        cl, srv = run(client_up=up, server_up=up)
        assert not any("started" in e for f in list(cl.values()) + list(srv.values()) for e in f.evidence), up


def test_only_findings_that_clear_by_themselves_get_the_note():
    c = copy.deepcopy(CLIENT); c["uptime_s"] = 30
    c["faillock"] = {"deny": 3, "unlock_time_s": 0, "failures": [
        {"when": f"2026-10-04T14:59:5{i}Z", "type": "RHOST", "source": "192.168.100.20", "valid": True} for i in range(3)]}
    lk = {f.id: f for f in evaluate(c)}["ACCOUNT_LOCKED"]
    assert not any("started" in e for e in lk.evidence)


def test_procedure_exists_and_is_linked():
    root = Path(__file__).resolve().parents[1]
    proc = root / "runbooks" / "procedures" / "after-power-outage.md"
    text = proc.read_text()
    for must in ("identity server first", "about a minute", "TIME_UNVERIFIED", "TLS_CERT_EXPIRED", "never logged in"):
        assert must in text, must
    assert "procedures/after-power-outage.md" in (root / "runbooks" / "README.md").read_text()
