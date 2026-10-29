from pathlib import Path

import pytest

from chp_site import wazuh as w
from chp_site.hosts import Host

FX = Path(__file__).parent / "fixtures" / "wazuh"
MGR = (FX / "manager-ossec.conf").read_text()
AGT = (FX / "agent-ossec.conf").read_text()


def hosts():
    return [Host("aa:aa:aa:aa:aa:01", "srv1", "192.0.2.10", "server", "vda"),
            Host("aa:aa:aa:aa:aa:02", "ws1", "192.0.2.21", "client", "vda"),
            Host("aa:aa:aa:aa:aa:03", "ws2", "192.0.2.22", "client", "vda")]


@pytest.mark.parametrize("path,want", [
    ("auth/disabled", "yes"), ("vulnerability-detection/enabled", "no"), ("indexer/enabled", "no"),
    ("syscheck/disabled", "yes"), ("sca/enabled", "no"), ("cluster/disabled", "yes"),
    ('wodle[@name="syscollector"]/disabled', "yes"), ('wodle[@name="cis-cat"]/disabled', "yes"),
    ('wodle[@name="osquery"]/disabled', "yes"), ("rootcheck/disabled", "no"),
    ("remote/connection", "secure"), ("remote/port", "1514"), ("remote/protocol", "tcp"),
    ("global/jsonout_output", "yes"), ("global/email_notification", "no"),
    ("global/agents_disconnection_time", "10m")])
def test_manager_settings(path, want):
    assert w.setting(w.parse_conf(w.harden_manager(MGR)), path) == want


def test_manager_has_no_active_response_and_keeps_the_log_collection():
    out = w.harden_manager(MGR)
    blocks = w.parse_conf(out)
    assert not [e for b in blocks for e in b.iter("active-response")]
    locs = [e.findtext("location") for b in blocks for e in b.iter("localfile")]
    assert "journald" in locs and "/var/log/audit/audit.log" in locs
    assert out.startswith("<!-- Managed by chp-security")


@pytest.mark.parametrize("path,want", [
    ("client/server/address", "192.0.2.10"), ("client/enrollment/enabled", "no"),
    ("active-response/disabled", "yes"), ("syscheck/disabled", "yes"), ("sca/enabled", "no"),
    ('wodle[@name="syscollector"]/disabled', "yes"), ("rootcheck/disabled", "no"),
    ("client/crypto_method", "aes")])
def test_agent_settings(path, want):
    assert w.setting(w.parse_conf(w.harden_agent(AGT, "192.0.2.10")), path) == want


def test_hardening_is_idempotent():
    once = w.harden_manager(MGR)
    assert w.harden_manager(once) == once
    a = w.harden_agent(AGT, "192.0.2.10")
    assert w.harden_agent(a, "192.0.2.10") == a


def test_agent_refuses_a_bad_server_ip():
    with pytest.raises(ValueError):
        w.harden_agent(AGT, "not-an-ip")


def test_client_keys_one_per_client_with_fixed_ip():
    keys = w.client_keys(hosts(), token_hex=lambda n: "ab" * n)
    assert keys == {"ws1": "001 ws1 192.0.2.21 " + "ab" * 32, "ws2": "002 ws2 192.0.2.22 " + "ab" * 32}


def test_data_dir_and_fstab():
    assert w.data_dir(True) == "/data/wazuh" and w.data_dir(False) == "/srv/wazuh"
    assert w.fstab_line("/srv/wazuh") == "/srv/wazuh /var/ossec none bind 0 0"


def test_rich_rules_only_clients_on_1514():
    assert w.rich_rules(hosts()) == [
        'rule family="ipv4" source address="192.0.2.21/32" port port="1514" protocol="tcp" accept',
        'rule family="ipv4" source address="192.0.2.22/32" port port="1514" protocol="tcp" accept']


def test_api_listens_on_loopback_and_shared_config_is_off():
    # W1 Task 6 (lab): Wazuh 4.14's API schema wants host as a LIST (default ["0.0.0.0", "::"]); a scalar stops apid
    assert 'host: ["127.0.0.1"]' in w.API_YAML and "0.0.0.0" not in w.API_YAML and "::" not in w.API_YAML
    assert w.LOCAL_INTERNAL_AGENT == "agent.remote_conf=0\n"


def test_pinned_fingerprint():
    assert w.WAZUH_FPR == "0DCFCA5547B19D2A6099506096B3EE5F29111145"


# ---- final-review fix pass (W1) ----
def test_manager_update_check_is_off():
    # final review I2: <global><update_check> would contact Wazuh's CTI service from a CUI host
    assert w.setting(w.parse_conf(w.harden_manager(MGR)), "global/update_check") == "no"


def test_agent_upgrade_module_is_off():
    # final review I3: WPK upgrades pushed from the manager bypass the signed repo; lab: with this the agent's
    # upgrade module never starts ("Module Agent Upgrade started" is absent)
    assert w.setting(w.parse_conf(w.harden_agent(AGT, "192.0.2.10")), "agent-upgrade/enabled") == "no"


def test_api_password_meets_wazuh_policy_and_is_random():
    pws = {w.api_password() for _ in range(20)}
    assert len(pws) == 20
    for p in pws:
        assert 32 <= len(p) <= 64 and any(c.islower() for c in p) and any(c.isupper() for c in p)
        assert any(c.isdigit() for c in p) and any(c in w.API_SYMBOLS for c in p)
