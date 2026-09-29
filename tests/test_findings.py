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


import copy  # noqa: E402


def pair():
    return load_report(FIX / "healthy-srv1-lab01.json"), load_report(FIX / "healthy-client2-lab01.json")


def cids(client, server=None):
    return [f.id for f in evaluate(client, server)]


def test_healthy_pair_has_no_findings_including_cross_host():
    s, c = pair()
    assert cids(s) == [] and cids(c, s) == []


def test_private_group_and_local_groups_are_not_stale():
    s, c = pair()
    c["user_nss"]["groups"] += ["wheel"]                     # local group, no @realm: not Kanidm's to judge
    assert cids(c, s) == []


def test_group_removed_on_server_but_cached_on_client_is_stale():
    s, c = pair()
    s["kanidm_user"]["memberof"].remove("lab_admins@idm.kanidm.lab.test")
    f = [x for x in evaluate(c, s) if x.id == "UNIXD_CACHE_STALE"]
    assert f and "lab_admins@idm.kanidm.lab.test" in f[0].evidence[0]


def test_no_cross_host_claim_without_both_sides():
    s, c = pair()
    c["user_nss"] = {"name": "lab01", "found": False}
    assert "UNIXD_CACHE_STALE" not in cids(c, s)
    assert "UNIXD_CACHE_STALE" not in cids(pair()[1], None)


@pytest.mark.parametrize("m,val", [("initgroups", "files"), ("passwd", "files kanidm systemd"), ("group", "")])
def test_kanidm_not_first_is_nss_order_wrong(m, val):
    c = pair()[1]; c["nss"][m] = val; c["authselect"]["valid"] = False
    f = [x for x in evaluate(c) if x.id == "NSS_ORDER_WRONG"][0]
    assert any(e.startswith(m) for e in f.evidence) and "MODIFIED" in f.evidence[-1]


def test_unreachable_kanidm_is_its_own_finding():
    c = pair()[1]; c["tls"] = {}
    c["errors"] = ["tls: could not fetch the Kanidm certificate (unreachable or handshake failed)"]
    assert "KANIDM_UNREACHABLE" in cids(c)


def test_untrusted_chain_is_reported_unless_the_clock_is_suspect():
    c = pair()[1]; c["tls"]["kanidm"]["verify"] = "untrusted"
    assert "TLS_CERT_UNTRUSTED(kanidm)" in cids(c)
    c["time"].update(synced=False, source_offset_s=600.0)        # the unsynchronised window after a jump
    assert "TLS_CERT_UNTRUSTED(kanidm)" not in cids(c)


def test_source_offset_reveals_skew_while_chrony_is_unsynchronised():
    c = pair()[1]; c["time"].update(offset_s=0.0, synced=False, source_offset_s=600.0)
    got = cids(c)
    assert "TOTP_TIME_SKEW" in got and "TIME_UNVERIFIED" in got


def test_stale_last_sample_after_a_step_is_not_skew_once_chrony_is_synced():
    # live 2026-09-28: after `chronyc makestep` tracking said 0.0 s / Normal while the last sample still read +600 s
    c = pair()[1]; c["time"].update(offset_s=0.000000001, synced=True, source_offset_s=600.0)
    assert "TOTP_TIME_SKEW" not in cids(c)


def test_synced_but_far_off_is_still_skew():
    c = pair()[1]; c["time"].update(offset_s=598.96, synced=True, source_offset_s=600.0)
    assert "TOTP_TIME_SKEW" in cids(c)
