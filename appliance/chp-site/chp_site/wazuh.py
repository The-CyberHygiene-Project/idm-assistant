# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Wazuh hardening (security bundle spec §4): pure transforms of Wazuh's installed default ossec.conf, the agent keys,
the bind-mounted data directory and the firewall rules. Nothing here runs a command."""
import ipaddress
import secrets
import xml.etree.ElementTree as ET

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


def _syscheck(blocks):
    sc = _first(blocks, "syscheck")
    for tag in ("directories", "ignore"):
        for e in list(sc.findall(tag)):
            sc.remove(e)
    for child, value in (("frequency", "43200"), ("scan_on_start", "no")):
        c = sc.find(child) if sc.find(child) is not None else ET.SubElement(sc, child)
        c.text = value
    d = ET.SubElement(sc, "directories", {"realtime": "yes", "check_all": "yes"})
    d.text = ",".join(_ys.WATCHED)
    for p in _ys.NEVER:
        ET.SubElement(sc, "ignore").text = p


def _yara_log(blocks):
    for b in blocks:
        for e in b.findall("localfile"):
            if e.findtext("location") == _ys.LOG:
                return
    lf = ET.SubElement(blocks[0], "localfile")
    ET.SubElement(lf, "log_format").text = "json"
    ET.SubElement(lf, "location").text = _ys.LOG


def _yara_response(blocks):
    for b in blocks:
        for e in list(b.findall("command")):
            if e.findtext("name") == "chp-yara-scan":
                b.remove(e)
    c = ET.SubElement(blocks[0], "command")
    for k, v in (("name", "chp-yara-scan"), ("executable", "chp-yara-scan"), ("timeout_allowed", "no")):
        ET.SubElement(c, k).text = v
    ar = ET.SubElement(blocks[0], "active-response")
    for k, v in (("command", "chp-yara-scan"), ("location", "local"), ("rules_id", "550,554")):
        ET.SubElement(ar, k).text = v


def api_password():
    """A random API password meeting Wazuh's policy (8-64 chars; upper, lower, digit, symbol). Never stored."""
    import string
    pools = (string.ascii_lowercase, string.ascii_uppercase, string.digits, API_SYMBOLS)
    while True:
        pw = "".join(secrets.choice("".join(pools)) for _ in range(40))
        if all(any(c in pool for c in pw) for pool in pools):
            return pw

_MANAGER = [("auth", "disabled", "yes"), ("vulnerability-detection", "enabled", "no"), ("indexer", "enabled", "no"),
            ("syscheck", "disabled", "no"), ("sca", "enabled", "no"), ("cluster", "disabled", "yes"),
            ("rootcheck", "disabled", "no"), ("remote", "connection", "secure"), ("remote", "port", "1514"),
            ("remote", "protocol", "tcp"), ("global", "jsonout_output", "yes"), ("global", "email_notification", "no"),
            ("global", "agents_disconnection_time", "10m"), ("global", "update_check", "no")]
_AGENT = [("active-response", "disabled", "no"), ("syscheck", "disabled", "no"), ("sca", "enabled", "no"),
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
    _syscheck(blocks); _yara_log(blocks); _yara_response(blocks)
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
    _syscheck(blocks); _yara_log(blocks)
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
