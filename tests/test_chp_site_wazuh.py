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
    blocks = w.parse_conf(out)                          # spec §10 (all hosts): YARA runs on a timer, not as a response
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


from chp_site import yara_scan as ys


def _blocks(text):
    return w.parse_conf(text)


def test_agent_keeps_file_monitoring_and_active_response_off():           # spec §10: clients scan on a timer
    b = _blocks(w.harden_agent(AGT, "192.0.2.10"))
    assert w.setting(b, "syscheck/disabled") == "yes" and w.setting(b, "active-response/disabled") == "yes"


def test_both_roles_read_the_yara_log_once():                               # still forwarded to the manager
    for out in (w.harden_manager(MGR), w.harden_agent(AGT, "192.0.2.10"),
                w.harden_manager(w.harden_manager(MGR))):                     # idempotent
        locs = [e.findtext("location") for x in _blocks(out) for e in x.findall("localfile")
                if e.findtext("location") == ys.LOG]
        assert len(locs) == 1


def test_yara_rules_levels():
    r = w.YARA_RULES
    assert 'level="12"' in r and "^match$" in r and 'level="7"' in r and "^error$" in r
    assert "<decoded_as>json</decoded_as>" in r


def test_no_host_turns_on_file_monitoring_or_responses():                     # spec §10 amendment 2 (all hosts)
    for out in (w.harden_manager(MGR), w.harden_agent(AGT, "192.0.2.10")):
        b = _blocks(out)
        assert w.setting(b, "syscheck/disabled") == "yes"
        assert not [e for x in b for e in x.findall("command") if e.findtext("name") == "chp-yara-scan"]


from chp_site import suricata_conf as _sc


def test_both_roles_read_eve_once():
    for out in (w.harden_manager(MGR), w.harden_agent(AGT, "192.0.2.10"), w.harden_manager(w.harden_manager(MGR))):
        locs = [e for x in w.parse_conf(out) for e in x.findall("localfile") if e.findtext("location") == _sc.EVE]
        assert len(locs) == 1 and locs[0].findtext("log_format") == "json"


def test_suricata_levels():
    r = w.SURICATA_RULES
    assert "<if_sid>86601</if_sid>" in r and '<field name="alert.severity">^1$</field>' in r
    assert 'level="12"' in r and 'level="7"' in r and '<field name="alert.severity">^2$</field>' in r


def test_only_alert_events_are_levelled():                                     # Review Focus 3
    assert "86600" not in w.SURICATA_RULES                                      # children of the alert rule only


def test_suricata_rule_ids_do_not_collide_with_yara():
    import re
    ids = lambda t: set(re.findall(r'rule id="(\d+)"', t))
    assert ids(w.SURICATA_RULES) == {"100510", "100511"} and not ids(w.SURICATA_RULES) & ids(w.YARA_RULES)


from chp_site import review_host as _rh


def test_both_roles_read_the_host_record_log_once():                       # R1 Task 1: the record travels as a JSON log
    for out in (w.harden_manager(MGR), w.harden_agent(AGT, "192.0.2.10"), w.harden_manager(w.harden_manager(MGR))):
        locs = [e for x in w.parse_conf(out) for e in x.findall("localfile") if e.findtext("location") == _rh.LOG]
        assert len(locs) == 1 and locs[0].findtext("log_format") == "json"
        assert not [e for x in w.parse_conf(out) for e in x.findall("localfile")
                    if "review" in (e.findtext("command") or "")]                # not full_command (matches rule 530)


def test_review_rule_stores_records_at_level_3():                          # manager log_alert_level is 3
    r = w.REVIEW_RULES
    assert 'rule id="100520" level="3"' in r and "<decoded_as>json</decoded_as>" in r
    assert '<field name="chp_review.host">' in r and "no_full_log" in r


def test_review_rule_only_from_the_record_log():                             # final review I4
    assert "<location>/var/log/chp-review.json</location>" in w.REVIEW_RULES


# ---------- NextCloud rules (ISO 0.7.0 Plan 2 Task 5) ----------
import re as _re

NC_LOG = "/var/log/nextcloud/audit.log"


def _flat(d, pre=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flat(v, f"{pre}{k}."))
        else:
            out[f"{pre}{k}"] = str(v)
    return out


def _rx(pattern, kind, text):
    if kind == "pcre2":
        return _re.search(pattern, text) is not None
    p = pattern.replace("\\.+", ".+").replace("\\S+", r"\S+").replace("\\d+", r"\d+")   # OS_Regex subset used here
    return _re.search(p, text) is not None


def _matches(rule, ev, fired):
    for c in rule:
        t = c.tag
        if t == "if_sid" and not set(c.text.split(",")) & fired:
            return False
        if t == "decoded_as" and ev.get("decoder") != c.text:
            return False
        if t == "location" and ev.get("location") != c.text:
            return False
        if t == "program_name" and not _rx(c.text, c.get("type"), ev.get("program_name", "")):
            return False
        if t == "match" and c.text not in ev.get("log", ""):
            return False
        if t == "regex" and not _rx(c.text, c.get("type"), ev.get("log", "")):
            return False
        if t == "field" and not _rx(c.text, c.get("type"), _flat(ev.get("json", {})).get(c.get("name"), "\0")):
            return False
    return True


def _level(xml, ev, now_ignored=()):
    """The level Wazuh would give (simplified): the first matching rule without if_sid (or a pre-fired stock rule),
    then repeatedly the first matching child of the current rule, in file order; an ignored child falls back."""
    import xml.etree.ElementTree as ET
    rules = [r for g in ET.fromstring("<x>" + _re.sub(r"<!--.*?-->", "", xml, flags=_re.S) + "</x>")
             for r in g.findall("rule")]
    cur, best = None, (None, None)
    pre = set(ev.get("pre_fired", ()))
    if pre:
        cur = next(iter(pre))
    else:
        for r in rules:
            if r.find("if_sid") is None and _matches(r, ev, set()):
                cur, best = r.get("id"), (r.get("id"), int(r.get("level")))
                break
    while cur is not None:
        nxt = next((r for r in rules if r.find("if_sid") is not None and r.get("id") not in now_ignored
                    and _matches(r, ev, {cur})), None)
        if nxt is None:
            break
        cur, best = nxt.get("id"), (nxt.get("id"), int(nxt.get("level")))
    return best


def _nc(message, user="lab01", app="admin_audit", data=None):
    return {"decoder": "json", "location": NC_LOG,
            "json": {"app": app, "user": user, "message": message, "data": data or {"app": app}}}


def _ft(event, **data):
    return {"decoder": "json", "location": NC_LOG,
            "json": {"app": "chp_foldertag", "message": f"{event}: x", "data": {"app": "chp_foldertag", "event": event, **data}}}


def test_wazuh_rules_levels():
    x = w.NEXTCLOUD_RULES
    cases = [
        (_nc("Interaction OCP\\Interaction\\Actions\\ShareAction from user lab01 on 47 to lab02 is restricted: "
             "Node is not shareable."), 12),                                                    # share attempt on CUI
        (_nc('The file "/CUI/plan.docx" with ID "47" has been shared via link with permissions "1" (Share ID: 3)'), 12),
        (_ft("chp.contain.refused", op="move", source_folder="1", target_folder="4"), 12),
        (_ft("chp.app.disabled", app_id="chp_foldertag", control="true"), 12),
        (_nc('App "chp_foldertag" disabled', user="--"), 12),
        (_ft("chp.tag.failed", op="create"), 12),
        ({"decoder": "kernel", "location": "journald", "program_name": "kernel",
          "log": "kernel: CHP-NC-EGRESS IN= OUT=enp1s0 SRC=192.168.100.30 DST=1.1.1.1 UID=48"}, 12),
        (_nc('Login failed: "lab02"', user="--"), 7),                                              # failed sign-in
        (_nc('File with id "47" deleted: "/lab01/files/CUI/plan.docx"'), 7),                      # CUI delete
        (_nc('File with id "48" deleted: "/lab01/files/FCI/x.pdf"'), 7),
        (_nc('File with id "47" accessed: "/lab01/files/CUI/plan.docx"'), 3),                     # CUI download
        (_ft("chp.folderop.refused", op="move"), 7),                                               # the first refusal
        ({"decoder": "kanidmd", "location": "journald", "program_name": "kanidmd",
          "log": "kanidmd: authentication failed: incorrect totp for lab03"}, 7),               # Kanidm failed TOTP
    ]
    for ev, want in cases:
        rid, lvl = _level(x, ev)
        assert lvl == want, (ev, rid, lvl)
    # after the first refusal fired, the once-rule is ignored: further refusals stay at level 3
    assert _level(x, _ft("chp.folderop.refused", op="move"), now_ignored=(w.FOLDEROP_FIRST_RULE,))[1] == 3
    # noise: a tag applied is not stored; an ordinary audit line is not an alert; deletes outside CUI/FCI are not 7
    assert (_level(x, _ft("chp.tag.applied", op="create"))[1] or 0) <= 3
    assert (_level(x, _nc('Login successful: "lab01"'))[1] or 0) < 3
    assert (_level(x, _nc('File with id "9" deleted: "/lab01/files/Operations/x"'))[1] or 0) < 7


def test_first_refusal_rule_fires_once_then_ignores():
    import xml.etree.ElementTree as ET
    g = ET.fromstring(w.NEXTCLOUD_RULES)
    r = next(x for x in g.findall("rule") if x.get("id") == w.FOLDEROP_FIRST_RULE)
    assert int(r.get("level")) >= 7 and int(r.get("ignore")) >= 86400
    assert r.findtext("if_sid") == "100615"


def test_failed_sign_in_also_hangs_off_the_generic_rule():         # spike: 2501 takes "Login failed" first
    rid, lvl = _level(w.NEXTCLOUD_RULES, {**_nc('Login failed: "lab02"', user="--"), "pre_fired": {"2501"}})
    assert lvl == 7


def test_egress_rule_only_from_the_kernel():                        # a forwarded alert text must not loop to level 12
    rid, lvl = _level(w.NEXTCLOUD_RULES, {"decoder": "x", "location": "journald", "program_name": "chp-wazuh",
                                          "log": "chp-wazuh: level 12 CHP-NC-EGRESS"})
    assert lvl is None or lvl < 12


def test_nextcloud_rule_ids_are_their_own_range():
    ids = set(_re.findall(r'rule id="(\d+)"', w.NEXTCLOUD_RULES))
    assert ids and all(100600 <= int(i) < 100700 for i in ids)
    for other in (w.YARA_RULES, w.SURICATA_RULES, w.REVIEW_RULES):
        assert not ids & set(_re.findall(r'rule id="(\d+)"', other))


def test_nextcloud_rules_parse_and_use_pcre2_for_alternation():
    import xml.etree.ElementTree as ET
    g = ET.fromstring(w.NEXTCLOUD_RULES)
    for f in g.iter("field"):
        if "|" in (f.text or ""):
            assert f.get("type") == "pcre2", f.text


def test_manager_reads_the_audit_log_once():
    for out in (w.documents_manager(MGR), w.documents_manager(w.documents_manager(MGR))):
        locs = [e for x in w.parse_conf(out) for e in x.findall("localfile") if e.findtext("location") == NC_LOG]
        assert len(locs) == 1 and locs[0].findtext("log_format") == "json"


def test_nightly_canary_refusal_is_not_a_level_12_page():
    """Plan 2 Task 6: the nightly canary's expected refusal is level 3 (the check itself alerts when the refusal
    fails); the same refusal for anyone else, and a share MADE by the canary, stay at 12."""
    msg = ("Interaction OCP\\Interaction\\Actions\\ShareAction from user chp-canary on 47 to "
           "OCP\\Interaction\\Contacts\\PublicLink is restricted: Node is not shareable.")
    assert _level(w.NEXTCLOUD_RULES, _nc(msg, user="chp-canary"))[1] == 3
    assert _level(w.NEXTCLOUD_RULES, _nc(msg.replace("chp-canary", "lab01"), user="lab01"))[1] == 12
    assert _level(w.NEXTCLOUD_RULES, _nc(msg, user="lab01"))[1] == 12          # the audit's user field decides
    made = 'The file "/CUI/CUI_chp-canary.txt" with ID "47" has been shared via link with permissions "1" (Share ID: 3)'
    assert _level(w.NEXTCLOUD_RULES, _nc(made, user="chp-canary"))[1] == 12
