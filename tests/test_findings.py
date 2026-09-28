import json
from pathlib import Path

import pytest

from engine.findings import evaluate
from engine.report import load_report

FIX = Path(__file__).parent / "fixtures" / "reports"


def ids(name):
    return [f.id for f in evaluate(load_report(FIX / f"{name}.json"))]


@pytest.mark.parametrize("name", ["healthy-srv1", "healthy-client2"])
def test_healthy_hosts_have_no_findings(name):
    assert ids(name) == []


def test_l1_posix_password_missing():
    assert ids("l1-srv1") == ["POSIX_PW_MISSING"]


def test_c1_on_server_reports_expiry_and_stopped_renewal():
    assert ids("c1-srv1") == ["ACME_RENEWAL_STOPPED", "TLS_CERT_EXPIRED(kanidm)"]


def test_c1_on_client_reports_expiry_and_offline_unixd():
    assert ids("c1-client2") == ["TLS_CERT_EXPIRED(kanidm)", "UNIXD_OFFLINE"]


def test_skewed_clock_is_blamed_not_the_certificate():
    got = ids("skew-client2")
    assert "TOTP_TIME_SKEW" in got and "TLS_CERT_EXPIRED(kanidm)" not in got


def test_missing_section_yields_no_claim_about_it():
    assert "TLS_CERT_EXPIRED(kanidm)" not in ids("tls-error-srv1")


def test_findings_carry_evidence_and_are_deterministic():
    r = load_report(FIX / "c1-srv1.json")
    a, b = evaluate(r), evaluate(r)
    assert a == b and all(f.evidence for f in a)


def test_load_report_rejects_wrong_schema(tmp_path):
    p = tmp_path / "x.json"; p.write_text(json.dumps({"schema": "other/9"}))
    with pytest.raises(ValueError):
        load_report(p)


@pytest.mark.parametrize("time", [{"offset_s": None, "synced": False, "source": ""},
                                  {"offset_s": 0.4, "synced": False, "source": "192.168.100.1"}])
def test_unverified_clock_blocks_the_expiry_verdict(time):
    r = dict(load_report(FIX / "c1-srv1.json"), time=time)
    got = [f.id for f in evaluate(r)]
    assert "TIME_UNVERIFIED" in got and "TLS_CERT_EXPIRED(kanidm)" not in got
