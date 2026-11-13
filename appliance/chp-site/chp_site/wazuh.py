# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Wazuh hardening (security bundle spec §4): pure transforms of Wazuh's installed default ossec.conf, the agent keys,
the bind-mounted data directory and the firewall rules. Nothing here runs a command."""
import ipaddress
import re as _re
import secrets
import xml.etree.ElementTree as ET

from . import review_host as _rh
from . import suricata_conf as _sc
from . import yara_scan as _ys

WAZUH_FPR = "0DCFCA5547B19D2A6099506096B3EE5F29111145"
HEADER = "<!-- Managed by chp-security (security bundle spec §4); edits are replaced by chp-site security enable -->\n"
API_YAML = ('# Managed by chp-security: the Wazuh API listens on this host only (spec §4). Wazuh 4.14 wants a list.\n'
            'host: ["127.0.0.1"]\nport: 55000\n')
LOCAL_INTERNAL_AGENT = "agent.remote_conf=0\n"
API_SYMBOLS = "-_.,+=@#%^*"


YARA_RULES = """<!-- Managed by chp-security (YARA spec §5): YARA scan results from /var/log/chp-yara.json -->
<group name="chp,yara,">
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="chp_yara.event">\\.+</field>
    <description>CHP YARA: $(chp_yara.event)</description>
  </rule>
  <rule id="100501" level="12">
    <if_sid>100500</if_sid>
    <field name="chp_yara.event">^match$</field>
    <description>YARA match: $(chp_yara.rules) in $(chp_yara.file)</description>
    <group>malware,</group>
  </rule>
  <rule id="100502" level="7">
    <if_sid>100500</if_sid>
    <field name="chp_yara.event">^error$</field>
    <description>YARA scan error: $(chp_yara.detail)</description>
  </rule>
</group>
"""


SURICATA_RULES = """<!-- Managed by chp-security (Suricata spec §4): levels for Suricata alerts by severity -->
<group name="chp,suricata,ids,">
  <rule id="100510" level="12">
    <if_sid>86601</if_sid>
    <field name="alert.severity">^1$</field>
    <description>Suricata (high): $(alert.signature)</description>
  </rule>
  <rule id="100511" level="7">
    <if_sid>86601</if_sid>
    <field name="alert.severity">^2$</field>
    <description>Suricata (medium): $(alert.signature)</description>
  </rule>
</group>
"""
# Severity 3 keeps the stock level 3 of Wazuh rule 86601 (Suricata alert).


def _json_log(blocks, location):
    for b in blocks:
        for e in b.findall("localfile"):
            if e.findtext("location") == location:
                return
    lf = ET.SubElement(blocks[0], "localfile")
    ET.SubElement(lf, "log_format").text = "json"
    ET.SubElement(lf, "location").text = location


def _yara_log(blocks):
    _json_log(blocks, _ys.LOG)


REVIEW_RULES = """<!-- Managed by chp-security (review spec §3): each host's status record (/var/log/chp-review.json) -->
<group name="chp,review,">
  <rule id="100520" level="3">
    <decoded_as>json</decoded_as>
    <location>/var/log/chp-review.json</location>
    <field name="chp_review.host">\\.+</field>
    <description>CHP review host record: $(chp_review.host)</description>
    <options>no_full_log</options>
  </rule>
</group>
"""
# Level 3: the manager stores only alerts >= log_alert_level 3 (R1 spike); records never reach ALERT_HOOK (level < 10).


def _review_log(blocks):
    _json_log(blocks, _rh.LOG)                          # review spec §3: every host's record, as a JSON log (R1 spike)


def _eve_log(blocks):
    _json_log(blocks, _sc.EVE)                          # Suricata spec §4: every host watches its own traffic


def api_password():
    """A random API password meeting Wazuh's policy (8-64 chars; upper, lower, digit, symbol). Never stored."""
    import string
    pools = (string.ascii_lowercase, string.ascii_uppercase, string.digits, API_SYMBOLS)
    while True:
        pw = "".join(secrets.choice("".join(pools)) for _ in range(40))
        if all(any(c in pool for c in pw) for pool in pools):
            return pw

_MANAGER = [("auth", "disabled", "yes"), ("vulnerability-detection", "enabled", "no"), ("indexer", "enabled", "no"),
            ("syscheck", "disabled", "yes"), ("sca", "enabled", "no"), ("cluster", "disabled", "yes"),
            ("rootcheck", "disabled", "no"), ("remote", "connection", "secure"), ("remote", "port", "1514"),
            ("remote", "protocol", "tcp"), ("global", "jsonout_output", "yes"), ("global", "email_notification", "no"),
            ("global", "agents_disconnection_time", "10m"), ("global", "update_check", "no")]
_AGENT = [("active-response", "disabled", "yes"), ("syscheck", "disabled", "yes"), ("sca", "enabled", "no"),
          ("rootcheck", "disabled", "no"), ("agent-upgrade", "enabled", "no")]
_WODLES_OFF = ("syscollector", "cis-cat", "osquery")


def parse_conf(text):
    """The <ossec_config> blocks of an ossec.conf (it has several roots, so it is wrapped to parse)."""
    return list(ET.fromstring("<chp-root>" + text.replace(HEADER, "") + "</chp-root>"))


def setting(blocks, path):
    for b in blocks:
        e = b.find(path)
        if e is not None:
            return (e.text or "").strip()
    return None


def _first(blocks, tag):
    for b in blocks:
        e = b.find(tag)
        if e is not None:
            return e
    return ET.SubElement(blocks[0], tag)


def _set(blocks, tag, child, value):
    parent = _first(blocks, tag)
    c = parent.find(child)
    if c is None:
        c = ET.SubElement(parent, child)
    c.text = value


def _wodles_off(blocks):
    for name in _WODLES_OFF:
        found = [e for b in blocks for e in b.findall(f'wodle[@name="{name}"]')]
        if not found:
            found = [ET.SubElement(blocks[0], "wodle", {"name": name})]
        for e in found:
            d = e.find("disabled")
            if d is None:
                d = ET.SubElement(e, "disabled")
            d.text = "yes"


def _render(blocks):
    for b in blocks:
        b.tail = None                                   # the wrapper's whitespace would grow on every run
        ET.indent(b, space="  ")
    return HEADER + "\n".join(ET.tostring(b, encoding="unicode") for b in blocks) + "\n"


def harden_manager(text):
    blocks = parse_conf(text)
    for b in blocks:
        for e in list(b.findall("active-response")):
            b.remove(e)
    for tag, child, value in _MANAGER:
        _set(blocks, tag, child, value)
    _wodles_off(blocks)
    _yara_log(blocks)                                   # spec §10: YARA runs on a timer on every host
    _eve_log(blocks)
    _review_log(blocks)
    return _render(blocks)


def harden_agent(text, server_ip):
    ipaddress.IPv4Address(server_ip)                    # ValueError on anything else
    blocks = parse_conf(text)
    client = _first(blocks, "client")
    server = client.find("server") if client.find("server") is not None else ET.SubElement(client, "server")
    for child, value in (("address", server_ip), ("port", "1514"), ("protocol", "tcp")):
        c = server.find(child)
        if c is None:
            c = ET.SubElement(server, child)
        c.text = value
    enr = client.find("enrollment")
    if enr is None:
        enr = ET.SubElement(client, "enrollment")
    en = enr.find("enabled")
    if en is None:
        en = ET.SubElement(enr, "enabled")
    en.text = "no"
    for tag, child, value in _AGENT:
        _set(blocks, tag, child, value)
    _wodles_off(blocks)
    _yara_log(blocks)                                   # spec §10: clients scan on a timer; the agent forwards the log
    _eve_log(blocks)
    _review_log(blocks)
    return _render(blocks)


def client_keys(hosts, token_hex=secrets.token_hex):
    clients = [h for h in hosts if h.role == "client"]
    return {h.hostname: f"{n:03d} {h.hostname} {h.ip} {token_hex(32)}" for n, h in enumerate(clients, 1)}


def data_dir(data_is_mount):
    return "/data/wazuh" if data_is_mount else "/srv/wazuh"


def fstab_line(d):
    return f"{d} /var/ossec none bind 0 0"


def rich_rules(hosts):
    return [f'rule family="ipv4" source address="{h.ip}/32" port port="1514" protocol="tcp" accept'
            for h in hosts if h.role == "client"]


# ---------- NextCloud (ISO 0.7.0 Plan 2 Task 5; design §6, §12; owner decisions 2, 3, 7) ----------
NC_AUDIT = "/var/log/nextcloud/audit.log"
NC_RULES_FILE = "chp_nextcloud_rules.xml"
FOLDEROP_FIRST_RULE = "100616"
_CTRL = "(CUI|FCI|Archive)"                              # the controlled team folders (share off, contained)

# Decoder: Wazuh's built-in JSON decoder reads each audit line (`log_format json`); a custom decoder would add nothing.
# Nested keys arrive flattened (data.event). Every alternation is pcre2 (OS_Regex has none; a bad rule stops the
# manager, so enable runs wazuh-analysisd -t first). Level 0 = matched but not stored; 3 = stored, in the review;
# 7 = the daily summary; 12 = ALERT_HOOK at once.
NEXTCLOUD_RULES = f"""<!-- Managed by chp-site documents enable (ISO 0.7.0 design §6): NextCloud admin_audit + chp_foldertag -->
<group name="chp,nextcloud,">
  <rule id="100600" level="0">
    <decoded_as>json</decoded_as>
    <location>{NC_AUDIT}</location>
    <field name="app">^admin_audit$</field>
    <description>NextCloud audit: $(message)</description>
  </rule>
  <rule id="100601" level="12">
    <if_sid>100600</if_sid>
    <field name="message" type="pcre2">ShareAction from user \\S+ on \\d+ to \\S+ is restricted</field>
    <description>NextCloud: share REFUSED on a no-share team folder (CUI/FCI/Archive): $(message)</description>
    <group>chp_share_refused,</group>
  </rule>
  <!-- the share-canary account (chp-site documents check; local, disabled between runs, no known password). The
       nightly run enables it by occ (audit user field: two dashes) in its window: level 3. Enabled any other way or at any other
       time, or its password set/changed by anyone: 12. Its expected nightly share refusal is lowered to 3 by 100608
       in chp_nextcloud_rules_canary.xml, anchored to the canary FILE id (written by the check). -->
  <rule id="100609" level="12">
    <if_sid>100600</if_sid>
    <field name="message" type="pcre2">^User enabled: "chp-canary"</field>
    <description>NextCloud: the share-canary account chp-canary was ENABLED outside the nightly check: $(message)</description>
    <group>chp_canary_account,</group>
  </rule>
  <rule id="100618" level="3">
    <if_sid>100609</if_sid>
    <field name="user">^--$</field>
    <time>3:05 am - 3:45 am</time>
    <description>NextCloud: chp-canary enabled by the nightly check (occ, 03:05-03:45): $(message)</description>
  </rule>
  <rule id="100619" level="12">
    <if_sid>100600</if_sid>
    <field name="message" type="pcre2">(?i)password\\b[^"]*"chp-canary"</field>
    <description>NextCloud: the password of the share-canary account chp-canary was set or changed: $(message)</description>
    <group>chp_canary_account,</group>
  </rule>
  <rule id="100602" level="12">
    <if_sid>100600</if_sid>
    <field name="message" type="pcre2">^The (file|folder) "/{_CTRL}(/[^"]*)?" with ID "\\d+" has been shared</field>
    <description>NextCloud: a share was MADE on a controlled team folder (must never happen): $(message)</description>
    <group>chp_share_made,</group>
  </rule>
  <rule id="100603" level="12">
    <if_sid>100600</if_sid>
    <field name="message" type="pcre2">^App .(chp_foldertag|chp_ledger|admin_audit|groupfolders|files_accesscontrol|user_oidc|systemtags|workflowengine). disabled</field>
    <description>NextCloud: a CUI control app was switched OFF: $(message)</description>
  </rule>
  <rule id="100604" level="7">
    <if_sid>100600</if_sid>
    <field name="message">^Login failed: </field>
    <description>NextCloud: failed sign-in: $(message) from $(remoteAddr)</description>
    <group>authentication_failed,</group>
  </rule>
  <rule id="100606" level="7">
    <if_sid>100600</if_sid>
    <field name="message" type="pcre2">(deleted: |has been deleted).*/(files/)?{_CTRL}(/|"|$)</field>
    <description>NextCloud: deletion in a controlled team folder: $(message)</description>
  </rule>
  <rule id="100607" level="3">
    <if_sid>100600</if_sid>
    <field name="message" type="pcre2">accessed: ".*/(files/)?{_CTRL}/</field>
    <description>NextCloud: download from a controlled team folder (owner decision 2: audited): $(message)</description>
  </rule>
  <!-- a "Login failed" line is taken first by Wazuh's generic rule 2501 ("authentication failure") (spike) -->
  <rule id="100605" level="7">
    <if_sid>2501</if_sid>
    <location>{NC_AUDIT}</location>
    <field name="app">^admin_audit$</field>
    <field name="message">^Login failed: </field>
    <description>NextCloud: failed sign-in: $(message) from $(remoteAddr)</description>
    <group>authentication_failed,</group>
  </rule>

  <rule id="100610" level="0">
    <decoded_as>json</decoded_as>
    <location>{NC_AUDIT}</location>
    <field name="app">^chp_foldertag$</field>
    <description>chp_foldertag: $(message)</description>
  </rule>
  <rule id="100611" level="12">
    <if_sid>100610</if_sid>
    <field name="data.event">^chp.contain.refused$</field>
    <description>NextCloud: copy/move OUT of a controlled team folder refused: $(message)</description>
    <group>chp_contain_refused,</group>
  </rule>
  <rule id="100612" level="12">
    <if_sid>100610</if_sid>
    <field name="data.event">^chp.app.disabled$</field>
    <field name="data.control">^true$</field>
    <description>NextCloud: a CUI control app was switched OFF: $(message)</description>
  </rule>
  <rule id="100617" level="3">
    <if_sid>100610</if_sid>
    <field name="data.event">^chp.app.disabled$</field>
    <description>NextCloud: an app was switched off: $(message)</description>
  </rule>
  <rule id="100613" level="12">
    <if_sid>100610</if_sid>
    <field name="data.event">^chp.tag.failed$</field>
    <description>NextCloud: a CUI/FCI tag could NOT be applied: $(message)</description>
    <group>chp_tag_failed,</group>
  </rule>
  <rule id="100614" level="2">
    <if_sid>100610</if_sid>
    <field name="data.event">^chp.tag.applied$</field>
    <description>NextCloud: tag applied: $(message)</description>
  </rule>
  <!-- §12 DEGRADED (database MD5 unavailable): each refusal is level 3. The FIRST one is raised to 7 by 100616:
       Wazuh's rule option ignore="86400" makes the rule fire once and then fall back to its parent (100615) for a
       day, so the first refusal of each day (and the first after a manager restart) reaches the daily summary. -->
  <rule id="100615" level="3">
    <if_sid>100610</if_sid>
    <field name="data.event">^chp.folderop.refused$</field>
    <description>NextCloud: folder move/rename/delete refused (database MD5 unavailable): $(message)</description>
  </rule>
  <rule id="{FOLDEROP_FIRST_RULE}" level="7" ignore="86400">
    <if_sid>100615</if_sid>
    <description>NextCloud is DEGRADED: database MD5 unavailable, folder moves/renames/deletes are refused (first refusal): $(message)</description>
    <group>chp_degraded,</group>
  </rule>

  <rule id="100620" level="12">
    <program_name>^kernel$</program_name>
    <match>CHP-NC-EGRESS</match>
    <description>NextCloud egress block tripped (the apache user tried to leave the server)</description>
    <group>chp_egress,</group>
  </rule>
  <rule id="100630" level="7">
    <program_name>^kanidmd$</program_name>
    <regex type="pcre2">(?i)((incorrect|invalid|wrong)\\W+totp|totp\\W+(fail|denied|incorrect|invalid))</regex>
    <description>Kanidm: failed sign-in (authenticator code refused)</description>
    <group>authentication_failed,</group>
  </rule>
</group>
"""


CANARY_RULE = "100608"
KANIDM_TOTP_RULE = "100630"                      # in the same rules file, but Kanidm's, not NextCloud's
NEXTCLOUD_RULE_IDS = frozenset(_re.findall(r'<rule id="(\d+)"', NEXTCLOUD_RULES)) - {KANIDM_TOTP_RULE} | {CANARY_RULE}


def canary_rules(fileid):
    """chp_nextcloud_rules_canary.xml (written by chp-site documents check once the canary file exists): the canary's
    expected refusal on THAT file id is level 3; the same account sharing anything else stays at 100601 (12)."""
    return f"""<!-- Managed by chp-site documents check (ISO 0.7.0 Plan 2 Task 6): the nightly share canary -->
<group name="chp,nextcloud,">
  <rule id="{CANARY_RULE}" level="3">
    <if_sid>100601</if_sid>
    <field name="user">^chp-canary$</field>
    <field name="message" type="pcre2">ShareAction from user chp-canary on {int(fileid)} to \\S+ is restricted</field>
    <description>NextCloud: nightly share canary refused as expected (canary file {int(fileid)}): $(message)</description>
  </rule>
</group>
"""


def documents_manager(text):
    """The manager's ossec.conf with NextCloud's audit log read as JSON (once); everything else unchanged."""
    blocks = parse_conf(text)
    _json_log(blocks, NC_AUDIT)
    return _render(blocks)
