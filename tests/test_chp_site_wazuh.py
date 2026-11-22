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


def _in_window(spec, hhmm):
    """Wazuh's <time>h:mm am - h:mm am</time> (same-day window only, as used here)."""
    if not hhmm:
        return False
    def mins(x):
        x = x.strip().lower()
        pm = x.endswith("pm")
        h, m = x.replace("am", "").replace("pm", "").strip().split(":")
        return (int(h) % 12 + (12 if pm else 0)) * 60 + int(m)
    a, b = spec.split(" - ")
    hh, mm = hhmm.split(":")
    return mins(a) <= int(hh) * 60 + int(mm) <= mins(b)


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
        if t == "user" and not _rx(c.text, c.get("type"), _flat(ev.get("json", {})).get("user", "\0")):
            return False                                     # static field: the JSON decoder fills it from "user"
        if t == "url" and not _rx(c.text, c.get("type"), _flat(ev.get("json", {})).get("url", "\0")):
            return False                                     # static field too (the audit line's request url)
        if t == "time" and not _in_window(c.text, ev.get("hhmm")):
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


def _nc(message, user="lab01", app="admin_audit", data=None, url="/remote.php/dav/files/lab01/x"):
    return {"decoder": "json", "location": NC_LOG,
            "json": {"app": app, "user": user, "url": url, "message": message, "data": data or {"app": app}}}


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
        ({"decoder": "iptables", "location": "journald", "program_name": "kernel", "pre_fired": {"4100"},
          "log": "kernel: CHP-NC-EGRESS IN= OUT=enp1s0 SRC=192.168.100.30 DST=1.1.1.1 UID=48"}, 12),
        (_nc('Login failed: "lab02"', user="--"), 7),                                              # failed sign-in
        (_nc('File with id "47" deleted: "/lab01/files/CUI/plan.docx"'), 7),                      # CUI delete
        (_nc('File with id "48" deleted: "/lab01/files/FCI/x.pdf"'), 7),
        (_nc('File with id "47" accessed: "/lab01/files/CUI/plan.docx"'), 3),                     # CUI download
        (_ft("chp.folderop.refused", op="move"), 7),                                               # the first refusal
        ({"decoder": "kanidmd", "location": "journald", "program_name": "kanidmd",
          "log": "kanidmd: [info]: Auth result: Denied: incorrect totp | event_tag_id: 10"}, 7),               # Kanidm failed TOTP
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
    x = w.NEXTCLOUD_RULES + w.canary_rules(47)
    assert _level(w.NEXTCLOUD_RULES, _nc(msg, user="chp-canary"))[1] == 12     # no canary rule yet: pages (loud)
    assert _level(x, _nc(msg, user="chp-canary"))[1] == 3
    assert _level(x, _nc(msg.replace("chp-canary", "lab01"), user="lab01"))[1] == 12
    assert _level(x, _nc(msg, user="lab01"))[1] == 12                         # the audit's user field decides
    # a hijacked canary account sharing REAL CUI (another file id) still pages at 12
    assert _level(x, _nc(msg.replace(" on 47 ", " on 470 "), user="chp-canary"))[1] == 12
    assert _level(x, _nc(msg.replace(" on 47 ", " on 4 "), user="chp-canary"))[1] == 12
    made = 'The file "/CUI/CUI_chp-canary.txt" with ID "47" has been shared via link with permissions "1" (Share ID: 3)'
    assert _level(x, _nc(made, user="chp-canary"))[1] == 12
    import xml.etree.ElementTree as ET
    ET.fromstring(w.canary_rules(47))
    assert w.CANARY_RULE not in _re.findall(r'rule id="(\d+)"', w.NEXTCLOUD_RULES)


def test_canary_account_enable_and_password_rules():
    """Enabled by the nightly run (occ, in its 03:05-03:45 window) = 3; by anyone else or at another time = 12;
    a password set or changed = always 12."""
    en = _nc('User enabled: "chp-canary"', user="--")
    assert _level(w.NEXTCLOUD_RULES, {**en, "hhmm": "03:12"})[1] == 3
    assert _level(w.NEXTCLOUD_RULES, {**en, "hhmm": "14:00"})[1] == 12
    assert _level(w.NEXTCLOUD_RULES, {**_nc('User enabled: "chp-canary"', user="ncadmin"), "hhmm": "03:12"})[1] == 12
    assert (_level(w.NEXTCLOUD_RULES, {**_nc('User enabled: "lab01"', user="--"), "hhmm": "14:00"})[1] or 0) < 7
    for m in ('Password of user "chp-canary" has been changed', 'Password set for user "chp-canary"'):
        assert _level(w.NEXTCLOUD_RULES, {**_nc(m, user="--"), "hhmm": "03:12"})[1] == 12, m


# ---------- Wazuh STATIC fields (Plan 2 Task 9 D1) ----------
# wazuh-analysisd refuses a rule set in which <field name="X"> names a STATIC field ("Field 'user' is static", lab log
# lab/docs-proof/PROOF-RECORD-PLAN2.md D1). The list: Wazuh 4.14 documentation (ruleset → decoders syntax, option
# <order>: the static fields srcip, dstip, srcport, dstport, protocol, action, srcuser, dstuser (alias user), id, url,
# data, extra_data, status, system_name; plus the pre-decoding fields hostname, program_name, timestamp, location,
# full_log/log, which rules also match with their own elements). Written from that documentation, not fetched; a
# longer list only bans more, so it errs safe. Dotted JSON names (data.event) are dynamic and allowed.
WAZUH_STATIC_FIELDS = frozenset("""srcip dstip srcport dstport protocol action id url data extra_data status
    system_name user srcuser dstuser hostname program_name timestamp location full_log log""".split())


def _all_wazuh_rule_xml():
    out = {n: v for n, v in vars(w).items() if isinstance(v, str) and "<rule " in v}
    out["canary_rules(47)"] = w.canary_rules(47)
    return out


def test_every_generated_rule_set_is_found():
    names = set(_all_wazuh_rule_xml())
    assert {"YARA_RULES", "SURICATA_RULES", "REVIEW_RULES", "NEXTCLOUD_RULES", "canary_rules(47)"} <= names


@pytest.mark.parametrize("name", sorted(_all_wazuh_rule_xml()))
def test_no_rule_uses_field_name_for_a_static_field(name):
    import xml.etree.ElementTree as ET
    xml = _all_wazuh_rule_xml()[name]
    root = ET.fromstring("<x>" + _re.sub(r"<!--.*?-->", "", xml, flags=_re.S) + "</x>")
    bad = [(r.get("id"), f.get("name")) for r in root.iter("rule") for f in r.findall("field")
           if f.get("name") in WAZUH_STATIC_FIELDS]
    assert not bad, f"{name}: <field name=...> on a Wazuh static field (use its own element, e.g. <user>): {bad}"
    assert not _re.search(r'<field\s+name="(%s)"' % "|".join(WAZUH_STATIC_FIELDS), xml), name   # raw text too


def test_canary_rules_match_the_audit_user_by_the_static_element():
    assert "<user>^--$</user>" in w.NEXTCLOUD_RULES and "<user>^chp-canary$</user>" in w.canary_rules(47)


# ---- Task 9d: D9 (egress rule hangs off Wazuh's firewall rule 4100) and the one-alert-per-wrong-TOTP rule ----
# the kernel line of the round-3 egress proof (lab/docs-proof/logs/51, as wazuh-logtest printed it)
EGRESS_LINE = ("Nov 14 10:39:09 iso5-srv.iso5.lab.test kernel: CHP-NC-EGRESS IN= OUT=enp1s0 SRC=192.168.100.50 "
               "DST=93.184.216.34 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=8687 DF PROTO=TCP SPT=40512 DPT=80 WINDOW=64240 "
               "RES=0x00 SYN URGP=0 UID=48 GID=48")


def _rule(rid):
    import xml.etree.ElementTree as ET
    g = ET.fromstring(_re.sub(r"<!--.*?-->", "", w.NEXTCLOUD_RULES, flags=_re.S))
    return next(r for r in g.findall("rule") if r.get("id") == rid)


def test_d9_egress_rule_is_a_child_of_the_firewall_rule_4100():
    # Wazuh's firewall decoder takes the kernel line and stock rule 4100 (level 0) matches first; a rule without
    # if_sid is never evaluated for it (lab round 3, D9: 100620 never fired). Proven with wazuh-logtest 4.14.7.
    r = _rule("100620")
    assert r.findtext("if_sid") == "4100"
    assert r.findtext("match") == "CHP-NC-EGRESS"
    assert int(r.get("level")) == 12
    ev = {"decoder": "iptables", "location": "journald", "program_name": "kernel", "log": EGRESS_LINE}
    assert _level(w.NEXTCLOUD_RULES, {**ev, "pre_fired": {"4100"}}) == ("100620", 12)
    # the same line seen by no 4100 (not the firewall decoder) is not ours to level
    assert _level(w.NEXTCLOUD_RULES, ev)[0] != "100620"


def test_d9_egress_rule_never_from_a_forwarded_alert_even_under_4100():
    rid, lvl = _level(w.NEXTCLOUD_RULES, {"decoder": "x", "location": "journald", "program_name": "chp-wazuh",
                                          "log": "chp-wazuh: level 12 CHP-NC-EGRESS", "pre_fired": {"4100"}})
    assert rid != "100620"


KANIDM_TOTP_LINES = [   # one wrong TOTP = these three kanidmd lines (lab/docs-proof/logs/50)
    "cace8f4f ERROR       ┝━ 🚨 [error]: Handler::PasswordMfa -> Result::Denied - TOTP Fail, password - | event_tag_id: 12",
    "cace8f4f INFO        ┝━ ｉ [info]: Credentials denied | event_tag_id: 10 | reason: incorrect totp",
    "cace8f4f INFO        ┕━ ｉ [info]: Auth result: Denied: incorrect totp | event_tag_id: 10",
]


def test_kanidm_wrong_totp_alerts_once_not_three_times():
    ev = lambda log: {"decoder": "kanidmd", "location": "journald", "program_name": "kanidmd", "log": log}
    hits = [_level(w.NEXTCLOUD_RULES, ev(x))[0] == w.KANIDM_TOTP_RULE for x in KANIDM_TOTP_LINES]
    assert hits == [False, False, True]
    assert _level(w.NEXTCLOUD_RULES, ev("[info]: Auth result: Continue (TOTP) | event_tag_id: 10"))[0] is None
    assert _level(w.NEXTCLOUD_RULES, ev("[info]: Auth result: Denied: incorrect totp"))[1] == 7


# ---------- Plan 3 Task 1: I1 (uploads stored, owner decision 2) and I2 (access granted inside NextCloud) ----------
# The message texts are NextCloud's own, from the lab: logs/72 (lab06's first sign-in), logs/42 and logs/53 (the canary).

def test_upload_rule_present():
    x = w.NEXTCLOUD_RULES
    import xml.etree.ElementTree as ET
    r = next(r for r in ET.fromstring(x).findall("rule") if r.get("id") == w.UPLOAD_RULE)
    assert r.get("level") == "3" and r.findtext("if_sid") == "100600"
    for m in ('File with id "166" created: "/lab06/files"', 'File with id "166" written to: "/lab06/files"',
              'File with id "102" written to: "/lab01/files/CUI/Sub-r1"',
              'File with id "159" created: "/chp-canary/files/CUI/CUI_chp-canary.txt"',
              'File with id "201" written to: "/lab01/files/Operations/copy-of-plan.docx"'):
        assert _level(x, _nc(m)) == (w.UPLOAD_RULE, 3), m          # stored (log_alert_level 3) like 100607 downloads
    assert _level(x, _nc('File with id "47" accessed: "/lab01/files/CUI/plan.docx"'))[0] == "100607"
    assert _level(x, _nc('File with id "47" deleted: "/lab01/files/CUI/plan.docx"'))[1] == 7


def test_breakglass_signin_pages():
    from chp_site import documents as D
    assert w.BREAKGLASS_USER == D.ADMIN
    x = w.NEXTCLOUD_RULES
    assert _level(x, _nc('Login successful: "ncadmin"', user="ncadmin")) == (w.BREAKGLASS_RULE, 12)
    assert (_level(x, _nc('Login successful: "lab01"'))[1] or 0) < 3
    assert (_level(x, _nc('Login successful: "ncadminx"', user="ncadminx"))[1] or 0) < 3


def test_account_and_group_changes_outside_oidc_page():
    x = w.NEXTCLOUD_RULES
    web = "/ocs/v2.php/cloud/users/mallory/groups"
    oidc = "/index.php/apps/user_oidc/code?state=abc&code=<REDACTED>"
    for m in ('User "mallory" added to group "cui-users"', 'User "lab02" added to group "admin"',
              'User created: "mallory"', 'User "lab01" removed from group "doc-reviewers"'):
        assert _level(x, {**_nc(m, user="ncadmin", url=web), "hhmm": "14:00"})[1] == 12, m
        assert _level(x, {**_nc(m, user="--", url="--"), "hhmm": "14:00"})[1] == 12, m        # occ on the server
        # Kanidm sign-in sync: stored; but adding admin or cui-users pages even then (Plan 3 Task 9, carry 2)
        priv = " added to group \"admin\"" in m or " added to group \"cui-users\"" in m
        assert _level(x, {**_nc(m, user="lab06", url=oidc), "hhmm": "14:00"})[1] == (12 if priv else 3), m
    # the real first-sign-in lines (logs/72) through the OIDC callback: stored, not paged
    for m in ('User "lab06" added to group "chp-users"', 'User created: "lab06"'):
        assert _level(x, {**_nc(m, user="lab06", url=oidc), "hhmm": "20:41"}) == (w.OIDC_PROVISION_RULE, 3)
    # the nightly check makes and re-adds the canary (logs/53, occ, user "--") in its window: 3; else 12
    for m in ('User created: "chp-canary"', 'User "chp-canary" added to group "cui-users"'):
        assert _level(x, {**_nc(m, user="--", url="--"), "hhmm": "03:10"})[1] == 3, m
        assert _level(x, {**_nc(m, user="--", url="--"), "hhmm": "14:00"})[1] == 12, m
        assert _level(x, {**_nc(m, user="ncadmin", url=web), "hhmm": "03:10"})[1] == 12, m
    assert _level(x, {**_nc('User "chp-canary" added to group "admin"', user="--", url="--"), "hhmm": "03:10"})[1] == 12


# ---------- Plan 3 Task 9: the document ledger's journal lines (ruling F4), and carries from Tasks 1 and 8 ----------
# doc_ledger.journal() writes one compact JSON object per line with logger -t chp-docs-ledger. Wazuh's stock JSON
# decoder does not take a JSON body behind a syslog header (wazuh-logtest 4.14.7 on aero: "No decoder matched"), so a
# decoder named after the program hands the body to JSON_Decoder (w.DOCS_DECODERS).

def _dl(event, **f):
    return {"decoder": w.DOCS_DECODER, "program_name": "chp-docs-ledger", "location": "journald",
            "json": {"event": event, **f}}


def _entry(kind, **f):
    e = {"seq": 3, "ts": "2026-11-19T10:00:00Z", "kind": kind, "user": "lab02", "auth": "bearer", "kanidm_sub": "s",
         "session_id": "x", "request_id": "0" * 32, "doc": "12/CUI_SSP.docx", "file_id": 44,
         "path": "CUI/Compliance/CUI_SSP_v1.1.docx", "sha256": "a" * 64, "cycle": 1, "prev": "b" * 64}
    e.update(f)
    return _dl("ledger", **e)


def test_docs_decoder_takes_the_json_body_of_the_ledgers_lines():
    import xml.etree.ElementTree as ET
    d = ET.fromstring("<x>" + _re.sub(r"<!--.*?-->", "", w.DOCS_DECODERS, flags=_re.S) + "</x>").find("decoder")
    assert d.get("name") == w.DOCS_DECODER == "chp-docs-ledger"
    assert d.findtext("program_name") == "^chp-docs-ledger$"
    assert d.findtext("plugin_decoder") == "JSON_Decoder"
    from chp_site import doc_ledger as dl
    assert dl.IDENT == "chp-docs-ledger"


def test_approval_rule_level_12():
    assert _level(w.NEXTCLOUD_RULES, _entry("approve")) == (w.DOC_APPROVE_RULE, 12)


def test_override_rule_level_12():
    assert _level(w.NEXTCLOUD_RULES, _entry("override", reason="one-person site")) == (w.DOC_OVERRIDE_RULE, 12)


def test_publication_rule_level_7():
    assert _level(w.NEXTCLOUD_RULES, _entry("publish", cr="CR-2026-0001")) == (w.DOC_PUBLISH_RULE, 7)


def test_ledger_rules_levels():
    x = w.NEXTCLOUD_RULES
    cases = [(_entry("checkout"), 3), (_entry("new"), 3), (_entry("resolve", resolves="1" * 32, reason="r"), 7),
             (_dl("quarantine", request_id="0" * 32, user=None, why="unknown kind"), 12),
             (_dl("appender-failed", message="chp-docs-ledger stopped"), 12),
             (_dl("ledger-broken", request_id="0" * 32, error="x"), 12),
             (_dl("publish-undo-failed", request_id="0" * 32, doc="12/x", failed=["unknown put 12/x"]), 12),
             (_dl("ledger-partial-line", request_id="0" * 32, error="x"), 12),
             (_dl("publish-started", request_id="0" * 32, user="lab01", doc="12/x", name="x", supersedes=None), 3),
             (_dl("publish-undone", request_id="0" * 32, doc="12/x"), 7),
             (_dl("head-write-failed", seq=4, error="x"), 7), (_dl("spool-unlink-failed", file="a.json", error="x"), 7),
             (_dl("result-write-failed", request_id="0" * 32, error="x"), 7),
             (_dl("refused", request_id="0" * 32, user="lab01", kind="approve", file_id=4, message="m"), 3),
             (_dl("retry", request_id="0" * 32, user="lab01", kind="approve", why="w"), 3)]
    for ev, want in cases:
        assert _level(x, ev)[1] == want, ev
    # a ledger line of a kind nobody defined is stored, never silently dropped
    assert _level(x, _entry("something-new"))[1] == 3
    # the same JSON from any other program is not the ledger's
    assert _level(x, {**_entry("approve"), "decoder": "json", "program_name": "logger"})[0] is None


def test_ledger_rule_ids_are_nextcloud_rows_in_the_review():
    ids = {w.DOC_APPROVE_RULE, w.DOC_OVERRIDE_RULE, w.DOC_PUBLISH_RULE, w.DOC_QUARANTINE_RULE, w.DOC_FAILURE_RULE,
           w.DOC_UNDO_FAILED_RULE, w.DOC_PARTIAL_RULE}
    assert ids <= w.NEXTCLOUD_RULE_IDS
    assert all(100600 <= int(i) < 100700 for i in ids)
    found = _re.findall(r'<rule id="(\d+)"', w.NEXTCLOUD_RULES)
    assert len(found) == len(set(found))                            # no id used twice


def test_ledger_rules_match_the_user_by_the_static_element():
    r = _rule(w.DOC_APPROVE_RULE)
    assert r.find("user") is None or r.findtext("user")              # never <field name="user">
    assert "$(dstuser)" in r.findtext("description")                 # logtest: the static user prints as dstuser


def test_oidc_callback_adding_admin_or_cui_users_pages():               # Task 1 review minor (carry 2)
    x = w.NEXTCLOUD_RULES
    oidc = "/index.php/apps/user_oidc/code?state=abc&code=<REDACTED>"
    for g in ("admin", "cui-users"):
        assert _level(x, {**_nc(f'User "lab06" added to group "{g}"', user="lab06", url=oidc), "hhmm": "14:00"}) \
            == (w.OIDC_PRIVILEGED_RULE, 12), g
    for m in ('User "lab06" added to group "chp-users"', 'User created: "lab06"',
              'User "lab06" removed from group "admin"', 'User "lab06" added to group "admins"'):
        assert _level(x, {**_nc(m, user="lab06", url=oidc), "hhmm": "14:00"}) == (w.OIDC_PROVISION_RULE, 3), m


def test_sweep_failures_reach_the_daily_summary():                       # Task 8 carry 3
    x = w.NEXTCLOUD_RULES
    ev = lambda log: {"decoder": "x", "location": "journald", "program_name": "chp-doc-sweep", "log": log}
    for log in ("could not sweep /home/lab01 (lab01): [Errno 13] Permission denied",
                "could not turn linger off for lab01 (loginctl exit 1: boom; still on)"):
        assert _level(x, ev(log)) == (w.DOC_SWEEP_FAILED_RULE, 7), log
    assert _level(x, ev("linger turned off for lab01 (ruling F3: no lingering user manager keeps sign-in tokens "
                        "after logout)"))[0] == w.DOC_SWEEP_RULE
    assert _level(x, {**ev("could not sweep /home/x (x): y"), "program_name": "logger"})[0] is None


def test_egress_render_failure_is_alerted():                             # Task 8 carry 3: stale addresses loaded
    x = w.NEXTCLOUD_RULES
    ev = {"decoder": "x", "location": "journald", "program_name": "chp-workstation-egress",
          "log": "EGRESS RENDER FAILED: site.conf: SERVER_IP missing; the last good address file is loaded"}
    assert _level(x, ev) == (w.WS_RENDER_RULE, 7)
    assert _level(x, {**ev, "program_name": "chp-wazuh"})[0] is None


def test_workstation_rules_are_not_nextcloud_rows():
    for r in (w.DOC_SWEEP_FAILED_RULE, w.WS_RENDER_RULE):
        assert r not in w.NEXTCLOUD_RULE_IDS


def test_no_ledger_line_ends_at_the_level_15_base():
    # the base is level 15 only to be tried before Wazuh's stock syslog rules (logtest 4.14.7: stock 1007 took an
    # ENOSPC error line ahead of a level-3 base; lab/docs-proof/logs/99); a line must always end in a child
    x = w.NEXTCLOUD_RULES
    assert _rule(w.DOC_BASE_RULE).get("level") == "15"
    for ev in (_dl("refused"), _dl("retry"), _dl("budget-reached"), _dl("quarantine-purged", count=2), _dl("x-new"),
               _entry("approve"), _entry("brand-new-kind"), _dl("ledger-partial-line", error="No space left on device")):
        rid, lvl = _level(x, ev)
        assert rid != w.DOC_BASE_RULE and lvl <= 12, ev
    assert _level(x, _dl("budget-reached")) == (w.DOC_OTHER_RULE, 3)
    # the catch-all is the last rule of the file (Wazuh tries a parent's children in order; it must come last)
    assert _re.findall(r'<rule id="(\d+)"', x)[-1] == w.DOC_OTHER_RULE



def test_unfinished_record_events_are_alerted():                         # Task 9 fix round 2 (c)
    x = w.NEXTCLOUD_RULES
    for stage in ("start", "undo-failed"):
        assert _level(x, _dl("unfinished-record-failed", request_id="0" * 32, stage=stage, error="EIO")) == \
            (w.DOC_RECORD_FAILED_RULE, 12)
    assert _level(x, _dl("unfinished-clear-failed", request_id="0" * 32, error="EACCES")) == (w.DOC_PROBLEM_RULE, 7)
    assert w.DOC_RECORD_FAILED_RULE in w.NEXTCLOUD_RULE_IDS


def test_fixwave_a_m8_purge_and_marker_clear_are_level_7():                     # final review A M-8
    x = w.NEXTCLOUD_RULES
    assert _level(x, _dl("quarantine-purged", count=2)) == (w.DOC_PURGED_RULE, 7)
    assert _level(x, _dl("start-marker-clear-failed", error="EACCES")) == (w.DOC_PROBLEM_RULE, 7)
    assert _re.findall(r'<rule id="(\d+)"', x)[-1] == w.DOC_OTHER_RULE


def test_fixwave_a_i1_a_shortened_override_line_still_pages():                  # final review A I-1
    import json as _json
    from chp_site import doc_ledger as dl
    e = {"seq": 3, "ts": "2026-11-19T10:00:00Z", "kind": "override", "user": "lab02", "auth": "bearer",
         "kanidm_sub": "s", "session_id": "x", "request_id": "0" * 32, "doc": "12/CUI_SSP.docx", "file_id": 44,
         "path": "CUI/Compliance/CUI_SSP_v1.1.docx", "sha256": "a" * 64, "cycle": 1, "prev": "b" * 64,
         "reason": "\x01" * 2000, "notes": "\x01" * 2000}
    line = dl._journal_line({"event": "ledger", **e})
    assert line is not None and len(line.encode()) <= dl.JOURNAL_MAX < dl.JOURNAL_SIZE
    rec = _json.loads(line)
    assert rec["kind"] == "override" and "2000 bytes, sha256" in rec["reason"] and "2000 bytes" in rec["notes"]
    assert _level(w.NEXTCLOUD_RULES, _dl(rec.pop("event"), **rec)) == (w.DOC_OVERRIDE_RULE, 12)
