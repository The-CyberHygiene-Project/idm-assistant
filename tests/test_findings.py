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


def test_unknown_server_membership_is_no_evidence_of_staleness():
    s, c = pair()
    s["kanidm_user"]["memberof"] = None                     # collector could not read it
    assert "UNIXD_CACHE_STALE" not in cids(c, s)


def test_reports_about_different_users_are_not_compared():
    s, c = pair()
    s["kanidm_user"]["memberof"] = []; s["kanidm_user"]["name"] = "lab02"
    assert "UNIXD_CACHE_STALE" not in cids(c, s)


def test_expired_account_is_found_and_suppressed_on_a_bad_clock():
    s = pair()[0]; s["kanidm_user"]["account_expire"] = "2026-09-01T00:00:00Z"
    assert "ACCOUNT_EXPIRED" in cids(s)
    s["time"].update(synced=False, offset_s=None)
    assert "ACCOUNT_EXPIRED" not in cids(s)


def test_not_yet_valid_account_is_found():
    s = pair()[0]; s["kanidm_user"]["valid_from"] = "2099-01-01T00:00:00Z"
    assert "ACCOUNT_NOT_YET_VALID" in cids(s)


def test_expired_issued_ssh_cert_is_found():
    s = pair()[0]
    s["ssh_ca"] = {"fingerprint": "SHA256:x", "issued": {"user": "lab01", "valid_from": "2026-09-01T00:00:00Z",
                                                          "valid_to": "2026-09-01T01:00:00Z", "principals": ["lab01"]}}
    assert "SSH_USER_CERT_EXPIRED" in cids(s)
    s["ssh_ca"]["issued"]["valid_to"] = "forever"
    assert "SSH_USER_CERT_EXPIRED" not in cids(s)


def test_expired_ssh_cert_is_suppressed_on_a_bad_clock():
    s = pair()[0]; s["time"]["offset_s"] = 600.0
    s["ssh_ca"] = {"fingerprint": "SHA256:x", "issued": {"user": "lab01", "valid_from": "2026-09-01T00:00:00Z",
                                                          "valid_to": "2026-09-01T01:00:00Z", "principals": ["lab01"]}}
    assert "SSH_USER_CERT_EXPIRED" not in cids(s)


def test_client_without_trusted_ca_is_found_and_so_is_a_foreign_ca():
    s, c = pair()
    s["ssh_ca"] = {"fingerprint": "SHA256:good", "issued": None}
    c["sshd"] = {"trusted_ca_path": "none", "trusted_ca_fingerprints": []}
    assert "SSH_CA_NOT_TRUSTED" in cids(c, s)
    assert "SSH_CA_NOT_TRUSTED" in cids(c)                  # single-host: nothing trusted at all
    c["sshd"] = {"trusted_ca_path": "/etc/ssh/trusted_user_ca_keys", "trusted_ca_fingerprints": ["SHA256:other"]}
    assert "SSH_CA_NOT_TRUSTED" in cids(c, s)
    c["sshd"]["trusted_ca_fingerprints"] = ["SHA256:good"]
    assert "SSH_CA_NOT_TRUSTED" not in cids(c, s)


def test_each_wrong_label_is_its_own_finding():
    c = pair()[1]
    c["selinux"]["relabel"] = [{"path": "/run/kanidm-unixd", "have": "var_run_t", "want": "kanidm_unixd_var_run_t"},
                               {"path": "/run/kanidm-unixd/sock", "have": "var_run_t", "want": "kanidm_unixd_var_run_t"}]
    got = cids(c)
    assert "SELINUX_LABEL_WRONG(/run/kanidm-unixd)" in got and "SELINUX_LABEL_WRONG(/run/kanidm-unixd/sock)" in got


def test_live_healthy_lab02_pair_with_plan7_sections_has_no_findings():
    s = load_report(FIX / "healthy-srv1-lab02.json"); c = load_report(FIX / "healthy-client2-lab02.json")
    assert s["ssh_ca"]["issued"] and c["sshd"]["trusted_ca_fingerprints"] and "relabel" in c["selinux"]
    assert cids(s) == [] and cids(c, s) == []


@pytest.mark.parametrize("vt", ["", None])
def test_unparsed_certificate_time_is_no_evidence_not_a_crash(vt):
    s = pair()[0]
    s["ssh_ca"] = {"fingerprint": "SHA256:x", "issued": {"user": "lab01", "valid_from": None, "valid_to": vt,
                                                          "principals": []}}
    assert "SSH_USER_CERT_EXPIRED" not in cids(s)
