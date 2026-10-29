# Security bundle Plan W1 (Wazuh): `chp-security` and 0.2.0-update4 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An existing 0.2.0 site can apply `0.2.0-update4` and run `chp-site security enable` on each host. Afterwards the server runs a hardened Wazuh manager, every client runs an agent, important alerts reach `ALERT_HOOK`, and the result is proven on the lab.

**Architecture:**
- Wazuh's own signed RPMs (key pinned) are configured by `chp-site` code and packaged with a CHP-signed `chp-security`.
- The hardening is done in testable Python, as XML transforms of Wazuh's installed default files. The alert forwarder and the summary command live in `chp-site`. The monitor checks are bash, like `chp-integrity`'s.
- Agent keys are made on the server and carried to clients on the site stick (`wazuh/<host>.key`), the way AIDE pins are.

**Tech Stack:** Python 3.9 standard library (`chp-site`), bash, RPM (noarch), systemd, firewalld, Wazuh 4.14.9.

**Spec:** `docs/superpowers/specs/2026-10-27-security-bundle-wazuh-design.md` (owner-approved 2026-10-27).

## Global Constraints

- **Wazuh 4.14.9 RPMs:** `wazuh-manager-4.14.9-1.x86_64.rpm` (sha256 `d258e605df92371944a5bd18b3adf007b25b4a2ccb551b4ad3fc624d55ad63ec`) and `wazuh-agent-4.14.9-1.x86_64.rpm` (sha256 `47596ab933d565c40f7263dda96a9e384495e8cb4a7a48b17694ab6daa145575`), from `https://packages.wazuh.com/4.x/yum/`. Both are signed by key `0DCFCA5547B19D2A6099506096B3EE5F29111145` (`https://packages.wazuh.com/key/GPG-KEY-WAZUH`), which expires 2027-05-15.
- `chp-site` stays Python 3.9 standard library only. Every new subcommand is added to `cli.py`'s parser and dispatch table, in the existing style.
- **Never repair, never block:** no Wazuh active response, no automatic firewall changes from alerts.
- **The settings in spec §4 are fixed:**
  - enrolment (authd) off; vulnerability detection, the indexer, syscheck, SCA, syscollector, cis-cat, osquery and the cluster all off;
  - active response off on agents and none configured on the manager;
  - `agent.remote_conf=0` on agents; rootcheck on.
- **Ruling (planning, recorded in the ledger):**
  - Wazuh's API daemon (`wazuh-apid`) is a core daemon and cannot be disabled cleanly, so the spec's fallback applies: it listens on `127.0.0.1` only, and the firewall never opens 55000.
  - Wazuh's defaults already collect `journald` and `audit.log`, and on Rocky 9 journald carries `/var/log/secure`'s events, so no separate `secure` entry is added (it would double-count).
  - The monitor timer runs every 15 minutes, so the forwarder (always running) also escalates Wazuh's agent lifecycle alerts (rule 504 disconnected, 505 removed, 506 stopped), whatever their level. That meets the spec's "agent down within 10 minutes". Monitor check 71 is the backstop.
- Commits end with the session attribution lines. Pushes and merges follow the owner's usual approval. YubiKey signing waits for the owner's "go".
- Test command: `cd ~/idm-assistant && .venv/bin/python -m pytest -q` (baseline on main: 890 passed).

## Review Focus

1. **A "hardened" setting silently does not apply:** Wazuh ignores an unknown or misplaced option. Every §4 setting must be checked on the live lab host (the manager's and agent's own `-t` config tests, and `ss` and the processes), not only in the generated text.
2. **Enabling twice, or after a failure, breaks a host:** `security enable` must be idempotent. A second run changes nothing, never duplicates `fstab` or firewall rules, and never makes new agent keys (which would orphan the clients).
3. **The bind mount is missing at boot:** if `/var/ossec` is not mounted, Wazuh must not start and write into `/var`. The unit gets `RequiresMountsFor=/var/ossec`.
4. **The forwarder floods or goes silent:** log rotation, a malformed line, the hook failing or hanging, and a restart mid-file must neither re-send old alerts nor lose new ones.
5. **Agent keys leak:** keys are written only to `client.keys` (0640 root:wazuh) and the site stick, never to logs, the audit record or command output.

---

### Task 1: Wazuh hardening library (`chp_site/wazuh.py`)

**Files:**
- Create: `appliance/chp-site/chp_site/wazuh.py`, `tests/fixtures/wazuh/manager-ossec.conf`, `tests/fixtures/wazuh/agent-ossec.conf`, `tests/fixtures/wazuh/README.md`
- Test: `tests/test_chp_site_wazuh.py`

**Interfaces:**
- Produces:
  - `WAZUH_FPR = "0DCFCA5547B19D2A6099506096B3EE5F29111145"`
  - `harden_manager(text: str) -> str`
  - `harden_agent(text: str, server_ip: str) -> str`
  - `API_YAML: str`
  - `LOCAL_INTERNAL_AGENT: str` (`"agent.remote_conf=0\n"`)
  - `client_keys(hosts, token_hex=secrets.token_hex) -> dict[str, str]` (hostname → `client.keys` line)
  - `data_dir(data_is_mount: bool) -> str`
  - `fstab_line(data_dir: str) -> str`
  - `rich_rules(hosts) -> list[str]`
  - `parse_conf(text) -> list[ET.Element]` (the `<ossec_config>` blocks)
  - `setting(blocks, path) -> str | None` (the first matching element's text; `path` like `"auth/disabled"` or `'wodle[@name="syscollector"]/disabled'`)

- [ ] **Step 1: Copy Wazuh's default files in as fixtures**

From the lab capture (`$SCRATCH/wz-defaults/`), keep only the XML. The agent capture also has an `=== internal` tail; drop it.

```bash
S=$SCRATCH/wz-defaults
mkdir -p tests/fixtures/wazuh
cp "$S/manager-ossec.conf" tests/fixtures/wazuh/manager-ossec.conf
sed '/^=== internal/,$d' "$S/agent-ossec.conf" > tests/fixtures/wazuh/agent-ossec.conf
printf '%s\n' "Wazuh 4.14.9's default /var/ossec/etc/ossec.conf for Rocky 9.8 (manager and agent), captured on the lab" \
  "2026-10-27 from the installed packages. Wazuh is GPLv2; these files are test fixtures only." > tests/fixtures/wazuh/README.md
```

If the scratch capture is gone, re-capture it: install each RPM on a golden lab host without starting it, `cat /var/ossec/etc/ossec.conf`, then reset the lab.

- [ ] **Step 2: Write the failing tests** (`tests/test_chp_site_wazuh.py`)

```python
from pathlib import Path

import pytest

from chp_site import wazuh as w
from chp_site.hosts import Host

FX = Path(__file__).parent / "fixtures" / "wazuh"
MGR = (FX / "manager-ossec.conf").read_text()
AGT = (FX / "agent-ossec.conf").read_text()


def hosts():
    return [Host("srv1", "aa:aa:aa:aa:aa:01", "192.0.2.10", "server"),
            Host("ws1", "aa:aa:aa:aa:aa:02", "192.0.2.21", "client"),
            Host("ws2", "aa:aa:aa:aa:aa:03", "192.0.2.22", "client")]


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
    assert "host: 127.0.0.1" in w.API_YAML and "0.0.0.0" not in w.API_YAML
    assert w.LOCAL_INTERNAL_AGENT == "agent.remote_conf=0\n"


def test_pinned_fingerprint():
    assert w.WAZUH_FPR == "0DCFCA5547B19D2A6099506096B3EE5F29111145"
```

Check the `Host` constructor before running: `grep -n "class Host\|Host = \|namedtuple" appliance/chp-site/chp_site/hosts.py`. If its fields are ordered differently, adjust `hosts()` and record a ledger ruling.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_chp_site_wazuh.py`
Expected: an ERROR at import (`chp_site.wazuh` missing). (Check how other `tests/test_chp_site_*.py` import `chp_site`, e.g. via `conftest.py` or `sys.path`, and follow it.)

- [ ] **Step 4: Implement `appliance/chp-site/chp_site/wazuh.py`**

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Wazuh hardening (security bundle spec §4): pure transforms of Wazuh's installed default ossec.conf, the agent keys,
the bind-mounted data directory and the firewall rules. Nothing here runs a command."""
import ipaddress
import secrets
import xml.etree.ElementTree as ET

WAZUH_FPR = "0DCFCA5547B19D2A6099506096B3EE5F29111145"
HEADER = "<!-- Managed by chp-security (security bundle spec §4); edits are replaced by chp-site security enable -->\n"
API_YAML = "# Managed by chp-security: the Wazuh API listens on this host only (spec §4).\nhost: 127.0.0.1\nport: 55000\n"
LOCAL_INTERNAL_AGENT = "agent.remote_conf=0\n"

_MANAGER = [("auth", "disabled", "yes"), ("vulnerability-detection", "enabled", "no"), ("indexer", "enabled", "no"),
            ("syscheck", "disabled", "yes"), ("sca", "enabled", "no"), ("cluster", "disabled", "yes"),
            ("rootcheck", "disabled", "no"), ("remote", "connection", "secure"), ("remote", "port", "1514"),
            ("remote", "protocol", "tcp"), ("global", "jsonout_output", "yes"), ("global", "email_notification", "no"),
            ("global", "agents_disconnection_time", "10m")]
_AGENT = [("active-response", "disabled", "yes"), ("syscheck", "disabled", "yes"), ("sca", "enabled", "no"),
          ("rootcheck", "disabled", "no")]
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
```

`ET.indent` is Python 3.9+, which is allowed. The leading `<!-- … -->` comment in Wazuh's file sits outside `<ossec_config>`. Wrapped in `<chp-root>`, the parser accepts it and drops it.

- [ ] **Step 5: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add appliance/chp-site/chp_site/wazuh.py tests/test_chp_site_wazuh.py tests/fixtures/wazuh
git commit -m "chp-site: Wazuh hardening library (spec §4): manager/agent ossec.conf transforms, agent keys, bind-mounted data dir, firewall rules"
```

---

### Task 2: Alert forwarder and summary (`chp_site/wazuh_alerts.py`)

**Files:**
- Create: `appliance/chp-site/chp_site/wazuh_alerts.py`
- Test: `tests/test_chp_site_wazuh_alerts.py`

**Interfaces:**
- Produces:
  - `LIFECYCLE = {"504", "505", "506"}`
  - `class Forwarder(level: int, window: int = 900)`:
    - `.feed(alert: dict, now: float) -> list[str]` (messages to send now);
    - `.flush(now) -> list[str]` (group summaries whose window ended);
    - `.daily(now) -> str | None` (the medium-alert summary line, at most once per 24 h);
  - `line(alert) -> str`, with the format `"<host> rule <id> level <n>: <description>"`;
  - `follow(path, state_path, sleep=time.sleep, stop=lambda: False)`, a generator of parsed alert dicts that survives rotation and restarts;
  - `summarize(alerts, since_epoch, min_level) -> str`;
  - `parse_since("24h"|"7d") -> int` seconds.

- [ ] **Step 1: Write the failing tests** (`tests/test_chp_site_wazuh_alerts.py`)

```python
import json

import pytest

from chp_site import wazuh_alerts as wa


def alert(rid="5712", level=10, host="ws1", desc="sshd brute force", ts="2026-10-27T10:00:00.000-0600"):
    return {"timestamp": ts, "rule": {"id": rid, "level": level, "description": desc}, "agent": {"name": host}}


def test_high_alert_is_sent_once_then_grouped():
    f = wa.Forwarder(level=10)
    assert f.feed(alert(), now=0) == ["ws1 rule 5712 level 10: sshd brute force"]
    assert f.feed(alert(), now=60) == [] and f.feed(alert(), now=120) == []
    assert f.flush(now=901) == ["ws1 rule 5712 level 10: sshd brute force (2 more in the last 15 min)"]
    assert f.flush(now=2000) == []


def test_a_new_window_sends_again():
    f = wa.Forwarder(level=10)
    f.feed(alert(), now=0)
    assert f.feed(alert(), now=1000) == ["ws1 rule 5712 level 10: sshd brute force"]


def test_low_alerts_are_not_sent_but_medium_counted_for_the_daily_line():
    f = wa.Forwarder(level=10)
    assert f.feed(alert(level=3), now=0) == []
    assert f.feed(alert(level=8, host="ws1"), now=1) == [] and f.feed(alert(level=7, host="ws2"), now=2) == []
    assert f.daily(now=10) is None                         # first day not over yet
    assert f.daily(now=86401) == "2 medium alerts (levels 7-9) on 2 hosts in the last 24 h; run chp-site alerts"
    assert f.daily(now=86402) is None


def test_lifecycle_alerts_are_sent_whatever_their_level():
    f = wa.Forwarder(level=10)
    assert f.feed(alert(rid="506", level=3, desc="Wazuh agent stopped."), now=0) == [
        "ws1 rule 506 level 3: Wazuh agent stopped."]


def test_threshold_is_respected():
    assert wa.Forwarder(level=12).feed(alert(level=10), now=0) == []


def test_line_survives_missing_fields():
    assert wa.line({}) == "? rule ? level ?: ?"


def test_follow_reads_new_lines_survives_restart_and_rotation(tmp_path):
    log, state = tmp_path / "alerts.json", tmp_path / "state"
    log.write_text(json.dumps(alert(rid="1")) + "\n" + json.dumps(alert(rid="2")) + "\n")
    got = list(wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__))
    assert [a["rule"]["id"] for a in got] == ["1", "2"]
    with log.open("a") as fh:
        fh.write("not json\n" + json.dumps(alert(rid="3")) + "\n")
    got = list(wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__))
    assert [a["rule"]["id"] for a in got] == ["3"]                 # restart: no repeats; bad line skipped
    log.unlink(); log.write_text(json.dumps(alert(rid="4")) + "\n")  # rotation: new inode, start at 0
    got = list(wa.follow(log, state, sleep=lambda s: None, stop=iter([False, True]).__next__))
    assert [a["rule"]["id"] for a in got] == ["4"]


def test_summarize_by_host_and_rule():
    al = [alert(level=10, ts="2026-10-27T10:00:00.000-0600"), alert(level=10, ts="2026-10-27T10:05:00.000-0600"),
          alert(rid="5902", level=8, host="srv1", desc="New user added", ts="2026-10-27T11:00:00.000-0600"),
          alert(level=3, host="ws2", ts="2026-10-27T11:00:00.000-0600")]
    out = wa.summarize(al, since_epoch=0, min_level=7)
    assert "ws1" in out and "5712" in out and "2" in out and "srv1" in out and "5902" in out and "ws2" not in out


@pytest.mark.parametrize("s,n", [("24h", 86400), ("7d", 604800), ("90m", 5400)])
def test_parse_since(s, n):
    assert wa.parse_since(s) == n


def test_parse_since_rejects_garbage():
    with pytest.raises(ValueError):
        wa.parse_since("soon")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_chp_site_wazuh_alerts.py`
Expected: an ERROR at import.

- [ ] **Step 3: Implement `appliance/chp-site/chp_site/wazuh_alerts.py`**

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Wazuh alerts to the site (security bundle spec §5): level >= threshold (and agent lifecycle) to the hook, repeats
grouped per host+rule for 15 minutes, a daily line for levels 7-9, and the chp-site alerts summary."""
import json
import os
import re
import time
from collections import Counter
from datetime import datetime

LIFECYCLE = {"504", "505", "506"}          # agent disconnected / removed / stopped (planning ruling: always sent)
DAY = 86400


def line(a):
    r, ag = a.get("rule", {}), a.get("agent", {})
    return f"{ag.get('name', '?')} rule {r.get('id', '?')} level {r.get('level', '?')}: {r.get('description', '?')}"


class Forwarder:
    def __init__(self, level, window=900):
        self.level, self.window = level, window
        self.groups = {}                    # (host, rule) -> [first_sent_epoch, repeats, text]
        self.medium, self.day_start = [], None

    def feed(self, a, now):
        if self.day_start is None:
            self.day_start = now
        r = a.get("rule", {})
        lvl = int(r.get("level", 0) or 0)
        rid = str(r.get("id", ""))
        if not (lvl >= self.level or rid in LIFECYCLE):
            if 7 <= lvl <= 9:
                self.medium.append(a.get("agent", {}).get("name", "?"))
            return []
        key = (a.get("agent", {}).get("name", "?"), rid)
        g = self.groups.get(key)
        if g and now - g[0] < self.window:
            g[1] += 1
            return []
        self.groups[key] = [now, 0, line(a)]
        return [line(a)]

    def flush(self, now):
        out = []
        for key, (t0, n, text) in list(self.groups.items()):
            if now - t0 >= self.window:
                if n:
                    out.append(f"{text} ({n} more in the last {self.window // 60} min)")
                del self.groups[key]
        return out

    def daily(self, now):
        if self.day_start is None or now - self.day_start < DAY:
            return None
        n, hosts = len(self.medium), len(set(self.medium))
        self.medium, self.day_start = [], now
        return (f"{n} medium alerts (levels 7-9) on {hosts} hosts in the last 24 h; run chp-site alerts") if n else None


def _read_state(p):
    try:
        ino, off = open(p).read().split()
        return int(ino), int(off)
    except (OSError, ValueError):
        return None, 0


def follow(path, state_path, sleep=time.sleep, stop=lambda: False):
    """Yield each new alert (a dict) appended to path; the (inode, offset) state survives restarts; a new inode
    (rotation) restarts at 0; lines that are not JSON are skipped."""
    ino, off = _read_state(state_path)
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if st.st_ino != ino or st.st_size < off:
                ino, off = st.st_ino, 0
            with open(path, "rb") as fh:
                fh.seek(off)
                for raw in fh:
                    if not raw.endswith(b"\n"):
                        break                       # a partly written line: read it next time
                    off += len(raw)
                    try:
                        yield json.loads(raw)
                    except ValueError:
                        pass
            tmp = f"{state_path}.tmp"
            with open(tmp, "w") as fh:
                fh.write(f"{ino} {off}\n")
            os.replace(tmp, state_path)
        if stop():
            return
        sleep(2)


def _epoch(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except (TypeError, ValueError):
        return 0.0


def summarize(alerts, since_epoch, min_level):
    c = Counter()
    for a in alerts:
        r = a.get("rule", {})
        if int(r.get("level", 0) or 0) >= min_level and _epoch(a.get("timestamp")) >= since_epoch:
            c[(a.get("agent", {}).get("name", "?"), str(r.get("id", "?")), int(r.get("level", 0)),
               r.get("description", "?"))] += 1
    if not c:
        return "no alerts at or above that level in that period"
    rows = [f"{'host':<16} {'rule':>6} {'level':>5} {'count':>5}  description"]
    for (h, rid, lvl, d), n in sorted(c.items(), key=lambda kv: (-kv[0][2], -kv[1])):
        rows.append(f"{h:<16} {rid:>6} {lvl:>5} {n:>5}  {d}")
    return "\n".join(rows)


def parse_since(s):
    m = re.fullmatch(r"(\d+)([mhd])", s or "")
    if not m:
        raise ValueError(f"--since: {s!r} is not like 90m, 24h or 7d")
    return int(m.group(1)) * {"m": 60, "h": 3600, "d": DAY}[m.group(2)]
```

- [ ] **Step 4: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass. If `test_follow…` stops early because the generator checks `stop()` only after a full read, that is intended: the test's `stop` returns `False` once, then `True`.

- [ ] **Step 5: Commit**

```bash
git add appliance/chp-site/chp_site/wazuh_alerts.py tests/test_chp_site_wazuh_alerts.py
git commit -m "chp-site: Wazuh alert forwarder logic (spec §5): threshold + lifecycle to the hook, 15-min grouping, daily medium line, restart/rotation-safe follower, summary"
```

---

### Task 3: `chp-site` commands: `security enable|status`, `alerts`, `wazuh-forward`

**Files:**
- Create: `appliance/chp-site/chp_site/security.py`
- Modify: `appliance/chp-site/chp_site/cli.py` (parser + dispatch + module docstring)
- Test: `tests/test_chp_site_security.py`

**Interfaces:**
- Consumes: Task 1 (`wazuh.*`) and Task 2 (`wazuh_alerts.*`); the existing `hosts.parse_hosts`, `sitefile.parse_site`, `usbstick.site_stick`, `audit.record`.
- Produces:
  - `security.enable(role, host, site, hosts, *, stick, run, root=Path("/"), data_is_mount=os.path.ismount("/data")) -> list[str]`, the steps done (for the summary). It is idempotent.
  - `security.status(root, run) -> str`.
  - `SECURITY_CONF = "etc/chp/security.conf"` (relative to `root`), with the keys `ROLE`, `ALERT_LEVEL` (default 10), `RETENTION_DAYS` (default 90) and `DATA_DIR`.
- The command layer passes `run=subprocess.run`. Tests pass a recorder `run` and a `tmp_path` `root`, so no real command runs.

What `enable` does, in order:

| # | Server | Client |
|---|---|---|
| 1 | Check `/etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH`'s fingerprint is `WAZUH_FPR` (`gpg --show-keys --with-colons`), then `rpm --import` it | same |
| 2 | Data dir (`/data/wazuh` or `/srv/wazuh`): create it 0750, add the `fstab_line` if absent, `mount /var/ossec` if not mounted | same |
| 3 | `dnf --enablerepo=chp install -y wazuh-manager chp-security` | `… wazuh-agent chp-security` |
| 4 | `ossec.conf` = `harden_manager(current)`; `api/configuration/api.yaml` = `API_YAML` | `ossec.conf` = `harden_agent(current, server_ip)`; `etc/local_internal_options.conf` gets `agent.remote_conf=0` (once) |
| 5 | `etc/client.keys`: **only if absent or empty**, write `client_keys(hosts)` lines, 0640 root:wazuh. Then write each client's line to the stick as `wazuh/<host>.key` (0600) | read `wazuh/<host>.key` from the stick (error if missing: "run security enable on the server first") and write it as `etc/client.keys` 0640 root:wazuh |
| 6 | firewalld: for each rule in `rich_rules(hosts)` not already listed, `--permanent --add-rich-rule`, then `--reload` | nothing (clients only connect out) |
| 7 | write `security.conf` (keeps an existing `ALERT_LEVEL`/`RETENTION_DAYS`) | same |
| 8 | `systemctl enable --now wazuh-manager chp-wazuh-alerts chp-wazuh-retention.timer`, then `systemctl restart wazuh-manager` | `systemctl enable --now wazuh-agent`, `systemctl restart wazuh-agent` |
| 9 | `audit.record("security enable", {"role": …, "host": …})`, which never includes a key | same |

- [ ] **Step 1: Write the failing tests** (`tests/test_chp_site_security.py`)

```python
from pathlib import Path

import pytest

from chp_site import security as sec
from chp_site import wazuh as w
from chp_site.hosts import Host
from chp_site.sitefile import SiteError

FX = Path(__file__).parent / "fixtures" / "wazuh"
FPR_COLONS = f"pub:-:4096:1:96B3EE5F29111145:1470009600:1810339200::-:\nfpr:::::::::{w.WAZUH_FPR}:\n"


class Run:
    def __init__(self, fpr=FPR_COLONS, rules=""):
        self.calls, self.fpr, self.rules = [], fpr, rules

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        out = self.fpr if argv[:2] == ["gpg", "--show-keys"] else (self.rules if "--list-rich-rules" in argv else "")
        return type("R", (), {"returncode": 0, "stdout": out, "stderr": ""})()


def hosts():
    return [Host("srv1", "aa:aa:aa:aa:aa:01", "192.0.2.10", "server"),
            Host("ws1", "aa:aa:aa:aa:aa:02", "192.0.2.21", "client")]


def root(tmp_path, role):
    r = tmp_path / "root"
    (r / "var/ossec/etc").mkdir(parents=True)
    (r / "var/ossec/api/configuration").mkdir(parents=True)
    (r / "etc/pki/rpm-gpg").mkdir(parents=True)
    (r / "etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH").write_text("key")
    (r / "etc/fstab").write_text("UUID=x / xfs defaults 0 0\n")
    (r / "var/ossec/etc/ossec.conf").write_text((FX / f"{'manager' if role == 'server' else 'agent'}-ossec.conf").read_text())
    return r


def enable(tmp_path, role, run=None, stick=None):
    r = root(tmp_path, role) if not (tmp_path / "root").exists() else tmp_path / "root"
    s = stick or (tmp_path / "stick"); s.mkdir(exist_ok=True)
    run = run or Run()
    done = sec.enable(role, "srv1" if role == "server" else "ws1", {"ALERT_HOOK": ""}, hosts(), stick=s, run=run,
                      root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None)
    return r, s, run, done


def test_server_enable_writes_hardened_config_keys_and_firewall(tmp_path):
    r, s, run, done = enable(tmp_path, "server")
    conf = (r / "var/ossec/etc/ossec.conf").read_text()
    assert w.setting(w.parse_conf(conf), "auth/disabled") == "yes"
    assert (r / "var/ossec/api/configuration/api.yaml").read_text() == w.API_YAML
    keys = (r / "var/ossec/etc/client.keys").read_text().split("\n")[0].split()
    assert keys[:3] == ["001", "ws1", "192.0.2.21"] and len(keys[3]) == 64
    assert (s / "wazuh/ws1.key").read_text().strip() == " ".join(keys)
    assert "/srv/wazuh /var/ossec none bind 0 0" in (r / "etc/fstab").read_text()
    assert any("--add-rich-rule" in " ".join(c) and "192.0.2.21/32" in " ".join(c) for c in run.calls)
    assert ["dnf", "--enablerepo=chp", "install", "-y", "wazuh-manager", "chp-security"] in run.calls
    assert "ROLE=server" in (r / "etc/chp/security.conf").read_text()


def test_second_enable_keeps_keys_and_adds_nothing_twice(tmp_path):
    r, s, run, _ = enable(tmp_path, "server")
    keys1 = (r / "var/ossec/etc/client.keys").read_text()
    rule = w.rich_rules(hosts())[0]
    r, s, run2, _ = enable(tmp_path, "server", run=Run(rules=rule + "\n"), stick=s)
    assert (r / "var/ossec/etc/client.keys").read_text() == keys1
    assert (r / "etc/fstab").read_text().count("/var/ossec") == 1
    assert not any("--add-rich-rule" in c for c in run2.calls)


def test_client_enable_reads_its_key_from_the_stick(tmp_path):
    s = tmp_path / "stick"; (s / "wazuh").mkdir(parents=True)
    (s / "wazuh/ws1.key").write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    r, _, run, _ = enable(tmp_path, "client", stick=s)
    assert (r / "var/ossec/etc/client.keys").read_text() == "001 ws1 192.0.2.21 " + "ab" * 32 + "\n"
    assert w.setting(w.parse_conf((r / "var/ossec/etc/ossec.conf").read_text()), "client/server/address") == "192.0.2.10"
    assert "agent.remote_conf=0" in (r / "var/ossec/etc/local_internal_options.conf").read_text()
    assert not any("firewall-cmd" in c for c in run.calls)


def test_client_without_its_key_on_the_stick_is_refused(tmp_path):
    with pytest.raises(SiteError, match="security enable on the server first"):
        enable(tmp_path, "client")


def test_wrong_key_fingerprint_refuses_before_any_change(tmp_path):
    bad = FPR_COLONS.replace(w.WAZUH_FPR, "0" * 40)
    with pytest.raises(SiteError, match="fingerprint"):
        enable(tmp_path, "server", run=Run(fpr=bad))
    assert not (tmp_path / "root/var/ossec/etc/client.keys").exists()


def test_keys_never_reach_the_audit_record(tmp_path):
    rec = []
    r = root(tmp_path, "server"); s = tmp_path / "stick"; s.mkdir()
    sec.enable("server", "srv1", {"ALERT_HOOK": ""}, hosts(), stick=s, run=Run(), root=r, data_is_mount=False,
               chown=lambda *a: None, record=lambda *a, **k: rec.append(a))
    key = (r / "var/ossec/etc/client.keys").read_text().split()[3]
    assert rec and key not in repr(rec)


def test_existing_alert_level_is_kept(tmp_path):
    r = root(tmp_path, "server"); (r / "etc/chp").mkdir(parents=True)
    (r / "etc/chp/security.conf").write_text("ROLE=server\nALERT_LEVEL=12\nRETENTION_DAYS=180\nDATA_DIR=/srv/wazuh\n")
    enable(tmp_path, "server")
    t = (r / "etc/chp/security.conf").read_text()
    assert "ALERT_LEVEL=12" in t and "RETENTION_DAYS=180" in t


def test_status_reports_role_and_services(tmp_path):
    r, _, _, _ = enable(tmp_path, "server")
    out = sec.status(r, Run())
    assert "role: server" in out and "wazuh-manager" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_chp_site_security.py`
Expected: an ERROR at import (`chp_site.security` missing).

- [ ] **Step 3: Implement `appliance/chp-site/chp_site/security.py`**

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site security enable|status (security bundle spec §3-§4): Wazuh manager on the server, agents on clients,
agent keys carried on the site stick (wazuh/<host>.key). Idempotent: a second run changes nothing it already did and
never makes new agent keys."""
import os
import shutil
from pathlib import Path

from . import wazuh as w
from .sitefile import SiteError

SECURITY_CONF = "etc/chp/security.conf"
KEYFILE = "etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH"
OSSEC = "var/ossec"


def _p(root, rel):
    return Path(root) / rel


def _check_key(root, run):
    k = _p(root, KEYFILE)
    if not k.exists():
        raise SiteError(f"/{KEYFILE} is missing: apply the update (chp-site 0.8.0) first")
    r = run(["gpg", "--show-keys", "--with-colons", str(k)], capture_output=True, text=True)
    fprs = [ln.split(":")[9] for ln in r.stdout.splitlines() if ln.startswith("fpr:")]
    if not fprs or fprs[0] != w.WAZUH_FPR:
        raise SiteError(f"Wazuh key fingerprint {fprs[0] if fprs else 'unreadable'} is not the pinned {w.WAZUH_FPR}")
    run(["rpm", "--import", str(k)], check=True)


def _data_dir(root, data_is_mount, run):
    d = w.data_dir(data_is_mount)
    _p(root, d.lstrip("/")).mkdir(parents=True, exist_ok=True, mode=0o750)
    _p(root, OSSEC).mkdir(parents=True, exist_ok=True)
    fstab = _p(root, "etc/fstab")
    text = fstab.read_text()
    if not any(ln.split()[1:2] == ["/var/ossec"] for ln in text.splitlines() if ln.strip() and not ln.startswith("#")):
        fstab.write_text(text + ("" if text.endswith("\n") else "\n") + w.fstab_line(d) + "\n")
    if run(["mountpoint", "-q", "/var/ossec"]).returncode != 0:
        run(["mount", "/var/ossec"], check=True)
    return d


def _write(path, text, mode, chown=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".chp-tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    if chown:
        chown(tmp)
    os.replace(tmp, path)


def _conf(root, role, d):
    p = _p(root, SECURITY_CONF)
    old = {}
    if p.exists():
        for ln in p.read_text().splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                old[k] = v
    text = (f"ROLE={role}\nALERT_LEVEL={old.get('ALERT_LEVEL', '10')}\n"
            f"RETENTION_DAYS={old.get('RETENTION_DAYS', '90')}\nDATA_DIR={d}\n")
    _write(p, text, 0o644)


def enable(role, host, site, hosts, *, stick, run, root=Path("/"), data_is_mount=None, chown=None, record=None):
    from . import audit
    if role not in ("server", "client"):
        raise SiteError(f"role must be server or client, not {role!r}")
    record = record or audit.record
    data_is_mount = os.path.ismount("/data") if data_is_mount is None else data_is_mount
    group_wazuh = chown or (lambda p: shutil.chown(p, "root", "wazuh"))
    done = []
    if role == "client":                                   # refuse before changing anything
        keyline = (Path(stick) / "wazuh" / f"{host}.key")
        if not keyline.exists():
            raise SiteError(f"no Wazuh key for {host} on the site stick (wazuh/{host}.key): "
                            "run chp-site security enable on the server first")
    _check_key(root, run); done.append("Wazuh signing key verified and imported")
    d = _data_dir(root, data_is_mount, run); done.append(f"data directory {d} bind-mounted at /var/ossec")
    pkg = "wazuh-manager" if role == "server" else "wazuh-agent"
    run(["dnf", "--enablerepo=chp", "install", "-y", pkg, "chp-security"], check=True); done.append(f"{pkg} installed")
    conf = _p(root, f"{OSSEC}/etc/ossec.conf")
    keys = _p(root, f"{OSSEC}/etc/client.keys")
    if role == "server":
        _write(conf, w.harden_manager(conf.read_text()), 0o640, group_wazuh)
        _write(_p(root, f"{OSSEC}/api/configuration/api.yaml"), w.API_YAML, 0o640, group_wazuh)
        if not keys.exists() or not keys.read_text().strip():
            lines = w.client_keys(hosts)
            _write(keys, "".join(v + "\n" for v in lines.values()), 0o640, group_wazuh)
            done.append(f"{len(lines)} agent keys made")
        mine = {ln.split()[1]: ln for ln in keys.read_text().splitlines() if ln.strip()}
        for h, ln in mine.items():
            kp = Path(stick) / "wazuh" / f"{h}.key"
            kp.parent.mkdir(parents=True, exist_ok=True)
            if not kp.exists() or kp.read_text().strip() != ln:
                kp.write_text(ln + "\n")
        done.append("agent keys on the site stick (wazuh/<host>.key)")
        have = run(["firewall-cmd", "--permanent", "--list-rich-rules"], capture_output=True, text=True).stdout
        new = [r for r in w.rich_rules(hosts) if r not in have.splitlines()]
        for r in new:
            run(["firewall-cmd", "-q", "--permanent", "--add-rich-rule", r], check=True)
        if new:
            run(["firewall-cmd", "-q", "--reload"], check=True)
        done.append(f"firewall: 1514/tcp from {len(w.rich_rules(hosts))} clients")
        units = ["wazuh-manager", "chp-wazuh-alerts", "chp-wazuh-retention.timer"]
    else:
        server = next(h for h in hosts if h.role == "server")
        _write(conf, w.harden_agent(conf.read_text(), server.ip), 0o640, group_wazuh)
        lio = _p(root, f"{OSSEC}/etc/local_internal_options.conf")
        cur = lio.read_text() if lio.exists() else ""
        if w.LOCAL_INTERNAL_AGENT.strip() not in cur:
            _write(lio, cur + w.LOCAL_INTERNAL_AGENT, 0o640, group_wazuh)
        _write(keys, (Path(stick) / "wazuh" / f"{host}.key").read_text(), 0o640, group_wazuh)
        units = ["wazuh-agent"]
    _conf(root, role, d)
    run(["systemctl", "enable", "--now", *units], check=True)
    run(["systemctl", "restart", units[0]], check=True); done.append(f"started: {', '.join(units)}")
    record("security enable", {"role": role, "host": host}, after=True)
    return done


def status(root, run):
    p = _p(root, SECURITY_CONF)
    if not p.exists():
        return "security add-on: not enabled on this host (chp-site security enable)"
    kv = dict(ln.split("=", 1) for ln in p.read_text().splitlines() if "=" in ln)
    units = ["wazuh-manager", "chp-wazuh-alerts"] if kv.get("ROLE") == "server" else ["wazuh-agent"]
    rows = [f"role: {kv.get('ROLE')}  alert level: {kv.get('ALERT_LEVEL')}  retention: {kv.get('RETENTION_DAYS')} days  "
            f"data: {kv.get('DATA_DIR')}"]
    for u in units:
        st = run(["systemctl", "is-active", u], capture_output=True, text=True).stdout.strip() or "unknown"
        rows.append(f"{u}: {st}")
    return "\n".join(rows)
```

Two adjustments when implementing:
- `run(...)` returning an object without `.stdout` for calls that don't capture is fine for the real `subprocess.run`, and the test `Run` always provides it.
- Server-side key distribution must also work when the server rewrites nothing, so it always mirrors `client.keys` to the stick. That is what the code does.

- [ ] **Step 4: Wire the commands into `cli.py`**

Add handlers next to `_docs`:

```python
def _host():  # already exists in cli.py; reuse it
    ...


def _security(a):
    import subprocess
    from . import security
    from .usbstick import site_stick
    if a.action == "status":
        print(security.status(Path("/"), subprocess.run))
        return 0
    site, hosts = _load(a.site)
    me = next((h for h in hosts if h.hostname == _host()), None)
    if me is None:
        raise SiteError(f"this host ({_host()}) is not in the hosts table")
    with site_stick(getattr(a, "stick", None)) as s:
        done = security.enable(me.role, me.hostname, site, hosts, stick=s, run=subprocess.run)
    print("\n".join(f"- {x}" for x in done))
    if me.role == "server":
        print("next: run `chp-site security enable` on each client, with the site stick")
    return 0


def _alerts(a):
    import gzip
    import json
    import time
    from . import wazuh_alerts as wa
    since = time.time() - wa.parse_since(a.since)
    base = Path("/var/ossec/logs/alerts")
    alerts = []
    for p in sorted(base.rglob("*.json*")):
        if p.stat().st_mtime < since - 86400:
            continue
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", errors="replace") as fh:
            for ln in fh:
                try:
                    alerts.append(json.loads(ln))
                except ValueError:
                    pass
    print(wa.summarize(alerts, since, a.level))
    return 0


def _wazuh_forward(a):
    import subprocess
    import time
    from . import wazuh_alerts as wa
    kv = dict(ln.split("=", 1) for ln in Path("/etc/chp/security.conf").read_text().splitlines() if "=" in ln)
    hook = subprocess.run(["chp-site", "get", "ALERT_HOOK"], capture_output=True, text=True).stdout.strip()
    f = wa.Forwarder(int(kv.get("ALERT_LEVEL", "10")))

    def send(msg):
        subprocess.run(["logger", "-p", "auth.warning", "-t", "chp-wazuh", msg], check=False)
        if hook and os.access(hook, os.X_OK):
            try:
                subprocess.run([hook, msg], check=False, timeout=30)
            except subprocess.TimeoutExpired:
                subprocess.run(["logger", "-p", "auth.warning", "-t", "chp-wazuh", f"ALERT_HOOK timed out: {hook}"])
    Path("/var/lib/chp/wazuh").mkdir(parents=True, exist_ok=True)
    for alert in wa.follow("/var/ossec/logs/alerts/alerts.json", "/var/lib/chp/wazuh/forward.state"):
        now = time.time()
        for m in f.feed(alert, now) + f.flush(now):
            send(m)
        d = f.daily(now)
        if d:
            send(d)
```

Then add to the parser in `main()`:

```python
    se = sub.add_parser("security", help="security add-on: enable Wazuh on this host (server first), or show status")
    se.add_argument("action", choices=("enable", "status")); se.add_argument("--stick"); se.add_argument("--site", default="/etc/chp")
    al = sub.add_parser("alerts", help="summarise Wazuh alerts by host and rule (server; root)")
    al.add_argument("--since", default="24h"); al.add_argument("--level", type=int, default=7)
    sub.add_parser("wazuh-forward", help="(service) send important Wazuh alerts to the log and ALERT_HOOK")
```

Add the dispatch entries: `"security": _security, "alerts": _alerts, "wazuh-forward": _wazuh_forward`.

Append ` | security | alerts | wazuh-forward` to the module docstring's command list.

**Ruling to record when implementing:** `_wazuh_forward` also flushes groups when no new alert arrives. The follower yields only on new lines, so add an idle flush: make `follow` yield `None` after each idle pass, and have `_wazuh_forward` skip `feed` for `None` while still running `flush` and `daily`. Add a test, `test_follow_yields_none_when_idle`, RED first. This is a deliberate refinement of Task 2's interface; Task 2's tests must stay green (filter out `None` in the existing follow tests).

- [ ] **Step 5: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass, including the existing `tests/test_chp_site_cli.py` (it may enumerate subcommands; update its expected list if so, and record a ledger ruling).

- [ ] **Step 6: Commit**

```bash
git add appliance/chp-site/chp_site/security.py appliance/chp-site/chp_site/cli.py appliance/chp-site/chp_site/wazuh_alerts.py tests/test_chp_site_security.py tests/test_chp_site_wazuh_alerts.py tests/test_chp_site_cli.py
git commit -m "chp-site: security enable|status, alerts, wazuh-forward (spec §3-§5); idempotent; agent keys via the site stick, never logged"
```

---

### Task 4: `chp-security` package: monitor checks, units, retention, AIDE additions

**Files:**
- Create: `appliance/rpm/chp-security/{chp-security.spec,build-rpm.sh,chp-wazuh-alerts.service,chp-wazuh-retention.service,chp-wazuh-retention.timer,wazuh-retention.sh,wazuh-manager.override.conf,wazuh-agent.override.conf}` and `appliance/rpm/chp-security/monitor.d/{70-wazuh-service.sh,71-wazuh-agents.sh,72-wazuh-disk.sh}`
- Modify: `appliance/rpm/chp-integrity/chp-additions.conf` (+ its spec: 0.1.6)
- Test: `tests/test_chp_security_monitor.py`, `tests/test_chp_security_static.py`

**Interfaces:**
- Consumes: `/etc/chp/security.conf` (Task 3), and `chp-site wazuh-forward` (Task 3).
- Produces: RPM `chp-security-0.1.0-1.chp.noarch`, which requires `chp-site >= 0.8.0` and `chp-base`.

- [ ] **Step 1: Write the failing tests**

`tests/test_chp_security_monitor.py` (the same harness style as `tests/test_chp_integrity_monitor.py`):

```python
import os
import subprocess
from pathlib import Path

M = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-security" / "monitor.d"


def run(tmp_path, name, conf="ROLE=server\nALERT_LEVEL=10\nRETENTION_DAYS=90\nDATA_DIR=/srv/wazuh\n",
        active="", agents="", dfpct="40"):
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(
        "#!/bin/bash\n" + f'case " {active} " in *" $3 "*) exit 0;; esac\nexit 3\n'); (b / "systemctl").chmod(0o755)
    (b / "agent_control").write_text(f"#!/bin/bash\ncat <<'EOF'\n{agents}\nEOF\n"); (b / "agent_control").chmod(0o755)
    (b / "df").write_text(f"#!/bin/bash\necho 'Use%'; echo ' {dfpct}%'\n"); (b / "df").chmod(0o755)
    c = tmp_path / "security.conf"
    if conf is not None:
        c.write_text(conf)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_SECURITY_CONF=str(c),
               CHP_AGENT_CONTROL=str(b / "agent_control"))
    r = subprocess.run(["bash", str(M / name)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_not_enabled_is_silent_ok(tmp_path):
    assert run(tmp_path, "70-wazuh-service.sh", conf=None).startswith("OK")


def test_server_services_down_alert(tmp_path):
    out = run(tmp_path, "70-wazuh-service.sh", active="chp-wazuh-alerts")
    assert "ALERT Wazuh wazuh-manager is not running" in out


def test_server_services_up_ok(tmp_path):
    assert run(tmp_path, "70-wazuh-service.sh", active="wazuh-manager chp-wazuh-alerts").startswith("OK")


def test_client_checks_its_agent(tmp_path):
    out = run(tmp_path, "70-wazuh-service.sh", conf="ROLE=client\n", active="")
    assert "ALERT Wazuh wazuh-agent is not running" in out


def test_disconnected_agents_alert(tmp_path):
    agents = ("   ID: 000, Name: srv1 (server), IP: 127.0.0.1, Active/Local\n"
              "   ID: 001, Name: ws1, IP: 192.0.2.21, Active\n   ID: 002, Name: ws2, IP: 192.0.2.22, Disconnected\n"
              "   ID: 003, Name: ws3, IP: 192.0.2.23, Never connected")
    out = run(tmp_path, "71-wazuh-agents.sh", agents=agents)
    assert "ALERT Wazuh agent ws2 (002) is disconnected" in out and "ALERT Wazuh agent ws3 (003) has never connected" in out
    assert "ws1" not in out


def test_agents_check_is_server_only(tmp_path):
    assert run(tmp_path, "71-wazuh-agents.sh", conf="ROLE=client\n").startswith("OK")


def test_disk_over_80_alerts(tmp_path):
    assert "ALERT Wazuh data directory /srv/wazuh is 85% full" in run(tmp_path, "72-wazuh-disk.sh", dfpct="85")
    assert run(tmp_path, "72-wazuh-disk.sh", dfpct="50").startswith("OK")
```

`tests/test_chp_security_static.py`:

```python
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-security"
SPEC = (D / "chp-security.spec").read_text()


def test_spec_requires_and_files():
    assert "Version:        0.1.0" in SPEC and "Requires:       chp-site >= 0.8.0, chp-base" in SPEC
    for f in ("70-wazuh-service.sh", "71-wazuh-agents.sh", "72-wazuh-disk.sh", "chp-wazuh-alerts.service",
              "chp-wazuh-retention.timer", "wazuh-retention"):
        assert f in SPEC, f


def test_wazuh_units_wait_for_the_bind_mount():
    for f in ("wazuh-manager.override.conf", "wazuh-agent.override.conf"):
        assert "RequiresMountsFor=/var/ossec" in (D / f).read_text()


def test_forwarder_unit():
    u = (D / "chp-wazuh-alerts.service").read_text()
    assert "ExecStart=/usr/bin/chp-site wazuh-forward" in u and "Restart=always" in u and "After=wazuh-manager.service" in u


def test_retention_uses_the_site_period():
    s = (D / "wazuh-retention.sh").read_text()
    assert "RETENTION_DAYS" in s and "-mtime" in s and "/var/ossec/logs/alerts" in s and "-delete" in s


def test_aide_watches_wazuh_config_not_its_churn():
    a = (Path(__file__).resolve().parents[1] / "appliance/rpm/chp-integrity/chp-additions.conf").read_text()
    assert "/var/ossec/etc" in a and "!/srv/wazuh" in a
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_chp_security_monitor.py tests/test_chp_security_static.py`
Expected: FAIL / ERROR (files missing).

- [ ] **Step 3: Write the monitor checks**

`monitor.d/70-wazuh-service.sh`:

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 70-wazuh-service (security bundle spec §5): the Wazuh services this host's role needs are running. Never repairs.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
role=$(sed -n 's/^ROLE=//p' "$C" | head -1)
if [ "$role" = server ]; then units="wazuh-manager chp-wazuh-alerts"; else units="wazuh-agent"; fi
bad=0
for u in $units; do
  systemctl is-active --quiet "$u" || { echo "ALERT Wazuh $u is not running: systemctl status $u"; bad=1; }
done
[ "$bad" -eq 0 ] && echo "OK Wazuh services running ($units)"
exit 0
```

`monitor.d/71-wazuh-agents.sh`:

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 71-wazuh-agents (spec §5): on the server, every client agent is connected (Wazuh marks one Disconnected after 10 min).
# Backstop for the forwarder's immediate lifecycle alerts.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}; AC=${CHP_AGENT_CONTROL:-/var/ossec/bin/agent_control}
[ -f "$C" ] && [ "$(sed -n 's/^ROLE=//p' "$C" | head -1)" = server ] || { echo "OK agent check: not a Wazuh server"; exit 0; }
out=$("$AC" -l 2>&1) || { echo "ALERT Wazuh agent_control failed: $out"; exit 0; }
bad=0
while IFS= read -r ln; do
  case $ln in *"ID: 000,"*) continue ;; esac
  id=$(sed -n 's/.*ID: \([0-9]*\),.*/\1/p' <<<"$ln"); name=$(sed -n 's/.*Name: \([^,]*\),.*/\1/p' <<<"$ln")
  case $ln in
    *", Disconnected"*) echo "ALERT Wazuh agent $name ($id) is disconnected"; bad=1 ;;
    *", Never connected"*) echo "ALERT Wazuh agent $name ($id) has never connected"; bad=1 ;;
  esac
done <<<"$out"
[ "$bad" -eq 0 ] && echo "OK Wazuh agents connected"
exit 0
```

`monitor.d/72-wazuh-disk.sh`:

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 72-wazuh-disk (spec §5): the Wazuh data directory's file system is below 80% (it shares the root volume or /data).
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
d=$(sed -n 's/^DATA_DIR=//p' "$C" | head -1); d=${d:-/var/ossec}
pct=$(df --output=pcent "$d" 2>/dev/null | tail -1 | tr -dc '0-9')
case $pct in ''|*[!0-9]*) echo "ALERT Wazuh data directory $d: cannot read its disk use"; exit 0 ;; esac
if [ "$pct" -ge 80 ]; then echo "ALERT Wazuh data directory $d is $pct% full (limit 80%): check alert retention"
else echo "OK Wazuh data directory $d $pct% full"; fi
exit 0
```

- [ ] **Step 4: Write the units, the retention script, the overrides and the AIDE additions**

`chp-wazuh-alerts.service`:

```ini
[Unit]
Description=CyberHygiene: send important Wazuh alerts to the log and ALERT_HOOK (security bundle spec §5)
After=wazuh-manager.service
Requires=wazuh-manager.service

[Service]
ExecStart=/usr/bin/chp-site wazuh-forward
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

`chp-wazuh-retention.service`:

```ini
[Unit]
Description=CyberHygiene: delete Wazuh alert logs older than the site's retention period

[Service]
Type=oneshot
ExecStart=/usr/libexec/chp/wazuh-retention
```

`chp-wazuh-retention.timer`:

```ini
[Unit]
Description=Daily Wazuh alert-log retention

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

`wazuh-retention.sh`:

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# wazuh-retention (spec §5): delete rotated Wazuh alert and archive logs older than RETENTION_DAYS (default 90).
set -u
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
days=$(sed -n 's/^RETENTION_DAYS=//p' "$C" 2>/dev/null | head -1); case $days in ''|*[!0-9]*) days=90 ;; esac
n=$(find /var/ossec/logs/alerts /var/ossec/logs/archives -type f -mtime +"$days" -print -delete 2>/dev/null | wc -l)
logger -t chp-wazuh "retention: removed $n alert/archive files older than $days days"
```

`wazuh-manager.override.conf` (installed as `/etc/systemd/system/wazuh-manager.service.d/chp.conf`) and `wazuh-agent.override.conf` (`…/wazuh-agent.service.d/chp.conf`), both:

```ini
[Unit]
# security bundle spec §3: Wazuh's data lives in a bind-mounted directory; never start (and write into /var) without it
RequiresMountsFor=/var/ossec
```

In `appliance/rpm/chp-integrity/chp-additions.conf`, append (after reading the file's style and keeping it):

```
# security bundle (spec §5): Wazuh's configuration is watched; its queues, logs and data directory change constantly
/var/ossec/etc CONTENT_EX
!/srv/wazuh(/|$)
!/data/wazuh(/|$)
!/var/ossec/(queue|logs|stats|tmp|var|api/configuration/security)(/|$)
```

Check that `CONTENT_EX` is a group name defined in the CHP `aide.conf`: `grep -n "^CONTENT_EX\|^[A-Z_]* *=" appliance/rpm/chp-integrity/aide.conf | head`. If it isn't, use the group the file uses for config directories, and record a ledger ruling.

Bump `chp-integrity.spec` to `0.1.6` with a changelog line ("security bundle: watch /var/ossec/etc; exclude Wazuh's data churn"). Update any version pin in `tests/test_chp_integrity_static.py`.

- [ ] **Step 5: Write `chp-security.spec` and `build-rpm.sh`**

`chp-security.spec`:

```spec
Name:           chp-security
Version:        0.1.0
Release:        1.chp%{?dist}
Summary:        CyberHygiene security add-on: Wazuh monitor checks, alert forwarder and retention
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        70-wazuh-service.sh
Source1:        71-wazuh-agents.sh
Source2:        72-wazuh-disk.sh
Source3:        chp-wazuh-alerts.service
Source4:        chp-wazuh-retention.service
Source5:        chp-wazuh-retention.timer
Source6:        wazuh-retention.sh
Source7:        wazuh-manager.override.conf
Source8:        wazuh-agent.override.conf
Source9:        LICENSE
Requires:       chp-site >= 0.8.0, chp-base
BuildRequires:  systemd-rpm-macros

%description
Security bundle part 1 (spec 2026-10-27): monitor checks for the Wazuh services, agents and data directory; the
chp-wazuh-alerts forwarder unit (chp-site wazuh-forward); daily alert-log retention; and drop-ins so Wazuh never
starts without its bind-mounted data directory. Wazuh itself is configured by chp-site security enable.

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_prefix}/lib/chp/monitor.d/70-wazuh-service.sh
install -Dm0755 %{SOURCE1} %{buildroot}%{_prefix}/lib/chp/monitor.d/71-wazuh-agents.sh
install -Dm0755 %{SOURCE2} %{buildroot}%{_prefix}/lib/chp/monitor.d/72-wazuh-disk.sh
install -Dm0644 %{SOURCE3} %{buildroot}%{_unitdir}/chp-wazuh-alerts.service
install -Dm0644 %{SOURCE4} %{buildroot}%{_unitdir}/chp-wazuh-retention.service
install -Dm0644 %{SOURCE5} %{buildroot}%{_unitdir}/chp-wazuh-retention.timer
install -Dm0755 %{SOURCE6} %{buildroot}%{_libexecdir}/chp/wazuh-retention
install -Dm0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/systemd/system/wazuh-manager.service.d/chp.conf
install -Dm0644 %{SOURCE8} %{buildroot}%{_sysconfdir}/systemd/system/wazuh-agent.service.d/chp.conf
install -dm0755 %{buildroot}%{_sharedstatedir}/chp/wazuh
install -Dm0644 %{SOURCE9} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

%post
%systemd_post chp-wazuh-alerts.service chp-wazuh-retention.timer
systemctl daemon-reload >/dev/null 2>&1 || :

%preun
%systemd_preun chp-wazuh-alerts.service chp-wazuh-retention.timer

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%{_prefix}/lib/chp/monitor.d/70-wazuh-service.sh
%{_prefix}/lib/chp/monitor.d/71-wazuh-agents.sh
%{_prefix}/lib/chp/monitor.d/72-wazuh-disk.sh
%{_unitdir}/chp-wazuh-alerts.service
%{_unitdir}/chp-wazuh-retention.service
%{_unitdir}/chp-wazuh-retention.timer
%{_libexecdir}/chp/wazuh-retention
%{_sysconfdir}/systemd/system/wazuh-manager.service.d/chp.conf
%{_sysconfdir}/systemd/system/wazuh-agent.service.d/chp.conf
%dir %attr(0755,root,root) %{_sharedstatedir}/chp/wazuh

%changelog
* Tue Oct 27 2026 The CyberHygiene Project - 0.1.0-1.chp
- First release (security bundle Plan W1): monitor checks 70/71/72, alert forwarder unit, retention, mount drop-ins.
```

`build-rpm.sh`: copy `appliance/rpm/chp-integrity/build-rpm.sh`, replacing the name, the work dir (`/tmp/chps`) and the source list with the ten sources above.

- [ ] **Step 6: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add appliance/rpm/chp-security appliance/rpm/chp-integrity tests/test_chp_security_monitor.py tests/test_chp_security_static.py tests/test_chp_integrity_static.py
git commit -m "chp-security 0.1.0: Wazuh monitor checks, forwarder unit, retention, mount drop-ins; chp-integrity 0.1.6 watches /var/ossec/etc"
```

---

### Task 5: Repo trust and release plumbing: Wazuh key, packages, key-expiry check, chp-site 0.8.0

**Files:**
- Create: `appliance/release/RPM-GPG-KEY-WAZUH`, `appliance/release/check-key-expiry.sh`, `appliance/release/test_check_key_expiry.sh` (if the release dir's shell tests follow that pattern; otherwise a pytest)
- Modify:
  - `appliance/release/trusted-keys.txt`, `appliance/release/PACKAGES.txt`;
  - `appliance/release/release-repo.sh`, `release-iso.sh`, `release-kit.sh` (call the expiry check first);
  - `appliance/chp-site/chp-site.spec` (0.8.0; ships `RPM-GPG-KEY-WAZUH`), `appliance/chp-site/build-rpm.sh`, `appliance/chp-site/chp_site/__init__.py` (`VERSION = "0.8.0"`);
  - `appliance/branding/NOTICE.txt` (Wazuh, GPLv2).
- Test: `tests/test_release_iso_static.py` (extend), `tests/test_chp_site_cli.py` (version pin)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_release_iso_static.py`:

```python
def test_wazuh_key_pinned_and_packages_listed():
    t = (R / "trusted-keys.txt").read_text()
    assert "0DCFCA5547B19D2A6099506096B3EE5F29111145 wazuh RPM-GPG-KEY-WAZUH" in t
    p = (R / "PACKAGES.txt").read_text()
    assert "wazuh-manager wazuh" in p and "wazuh-agent wazuh" in p and "chp-security ours" in p


def test_release_scripts_check_key_expiry_first():
    for s in ("release-repo.sh", "release-iso.sh", "release-kit.sh"):
        t = (R / s).read_text()
        assert 'bash "$here/check-key-expiry.sh"' in t, s


def test_notice_names_wazuh_gplv2():
    n = (R.parent / "branding" / "NOTICE.txt").read_text()
    assert "Wazuh" in n and "GPL" in n
```

Create `tests/test_check_key_expiry.py`:

```python
import os
import subprocess
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "appliance" / "release" / "check-key-expiry.sh"


def run(tmp_path, expires, now=1800000000):
    (tmp_path / "trusted-keys.txt").write_text("ABCD wazuh K\n")
    (tmp_path / "K").write_text("key")
    b = tmp_path / "bin"; b.mkdir()
    (b / "gpg").write_text(f"#!/bin/bash\necho 'pub:-:4096:1:X:1470009600:{expires}::-:'\necho 'fpr:::::::::ABCD:'\n")
    (b / "gpg").chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_NOW=str(now))
    return subprocess.run(["bash", str(S), str(tmp_path)], env=env, capture_output=True, text=True)


def test_far_expiry_passes(tmp_path):
    r = run(tmp_path, 1800000000 + 200 * 86400)
    assert r.returncode == 0 and "KEYS OK" in r.stdout


def test_expiry_within_90_days_refuses(tmp_path):
    r = run(tmp_path, 1800000000 + 30 * 86400)
    assert r.returncode == 1 and "expires in 30 days" in r.stdout


def test_expired_refuses(tmp_path):
    r = run(tmp_path, 1800000000 - 86400)
    assert r.returncode == 1 and "EXPIRED" in r.stdout


def test_no_expiry_passes(tmp_path):
    assert run(tmp_path, "").returncode == 0
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_release_iso_static.py tests/test_check_key_expiry.py`
Expected: FAIL (the files and lines are missing).

- [ ] **Step 3: Implement**

Copy the Wazuh key in from the session download, and re-check its fingerprint first:

```bash
S=$SCRATCH/wazuh-dl
gpg --show-keys --with-colons "$S/GPG-KEY-WAZUH" | awk -F: '/^fpr/{print $10; exit}'   # must print 0DCFCA5547B19D2A6099506096B3EE5F29111145
cp "$S/GPG-KEY-WAZUH" appliance/release/RPM-GPG-KEY-WAZUH
echo "0DCFCA5547B19D2A6099506096B3EE5F29111145 wazuh RPM-GPG-KEY-WAZUH" >> appliance/release/trusted-keys.txt
printf '%s\n' "chp-security ours" "wazuh-manager wazuh" "wazuh-agent wazuh" >> appliance/release/PACKAGES.txt
```

`appliance/release/check-key-expiry.sh`:

```bash
#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# check-key-expiry.sh [keys-dir]: refuse (exit 1) if any key pinned in trusted-keys.txt has expired or expires within
# 90 days (security bundle spec §6; Wazuh's key expires 2027-05-15). Run first by every release script.
set -uo pipefail
K=${1:-$(cd "$(dirname "$0")" && pwd)}; now=${CHP_NOW:-$(date -u +%s)}; bad=0
while read -r fpr label file; do
  [[ -z ${fpr:-} || $fpr == \#* ]] && continue
  exp=$(gpg --show-keys --with-colons "$K/$file" 2>/dev/null | awk -F: '/^pub/{print $7; exit}')
  [[ -z $exp ]] && continue                                        # no expiry date
  days=$(( (exp - now) / 86400 ))
  if (( exp <= now )); then echo "EXPIRED: $label key ($fpr) expired $((-days)) days ago"; bad=1
  elif (( days < 90 )); then echo "REFUSING: $label key ($fpr) expires in $days days (renew or re-pin before releasing)"; bad=1
  fi
done < "$K/trusted-keys.txt"
(( bad )) && exit 1
echo "KEYS OK: no pinned key expires within 90 days"
```

In each of `release-repo.sh`, `release-iso.sh` and `release-kit.sh`, after the `here=…` line, insert:

```bash
bash "$here/check-key-expiry.sh" "$here" || { echo "refusing: a pinned signing key has expired or expires soon"; exit 1; }
```

`chp-site.spec`:
- add `Source5: RPM-GPG-KEY-WAZUH`;
- install it to `%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-WAZUH` (0644) and list it in `%files`;
- `Version: 0.8.0`;
- changelog: "security bundle: security enable|status, alerts, wazuh-forward; ships Wazuh's signing key (pinned 0DCF…1145)".

Make `build-rpm.sh` copy `appliance/release/RPM-GPG-KEY-WAZUH` alongside the CHP key, following how it copies `RPM-GPG-KEY-cyberhygiene`. Set `VERSION = "0.8.0"` in `chp_site/__init__.py`, and update the version pin in `tests/test_chp_site_cli.py`.

`NOTICE.txt`: add a line in its component list, matching the existing style: "Wazuh 4.14.9 (manager and agent): GPLv2, © Wazuh Inc.; shipped unmodified, signed by Wazuh."

- [ ] **Step 4: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass. Also run `bash appliance/release/check-key-expiry.sh appliance/release`. Expected: `KEYS OK…`. Wazuh's key has about 200 days left at 2026-10-27.

- [ ] **Step 5: Commit**

```bash
git add appliance/release appliance/chp-site appliance/branding/NOTICE.txt tests/test_release_iso_static.py tests/test_check_key_expiry.py tests/test_chp_site_cli.py
git commit -m "Repo trust: Wazuh key pinned, wazuh-manager/agent + chp-security listed, release scripts refuse expiring keys; chp-site 0.8.0 ships Wazuh's key; NOTICE"
```

---

### Task 6: Build, sign repo 0.7.8, lab proof 1 (upgrade a 0.2.0 site)

**Files:**
- Create: `lab/security/prove-w1.sh` (staged, not run blind), `lab/security/PROOF-RECORD-W1.md`

- [ ] **Step 1: Stage the Wazuh RPMs as third-party inputs on aero, verified**

```bash
S=$SCRATCH/wazuh-dl
ssh aero 'ls -d /data/chp-release/third-party' && scp "$S"/wazuh-*.rpm aero:/data/chp-release/third-party/
ssh aero 'cd /data/chp-release/third-party && sha256sum wazuh-*.rpm'
```

Expected: the two sha256 values in Global Constraints. Find the actual third-party directory name first, from `assemble-repo.sh` usage or the previous release's command history in `RELEASE-RECORD-0.7.7.md`, and use that.

- [ ] **Step 2: Build the changed RPMs on aero**

Run `bash appliance/chp-site/build-rpm.sh`, `bash appliance/rpm/chp-security/build-rpm.sh` and `bash appliance/rpm/chp-integrity/build-rpm.sh`.
Expected: each prints its file list. `chp-site-0.8.0` contains `/etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH`.

- [ ] **Step 3: Assemble, then sign repo 0.7.8** (YubiKey: ask the owner for "go" first, and explain the touch)

Follow `RELEASE-RECORD-0.7.7.md`'s commands: `assemble-repo.sh`, `sign-session.sh`/`sign-repo.sh`, `verify-repo.sh`.
Expected: `REPO OK: 17 packages, all signed by pinned keys`. The Wazuh RPMs keep Wazuh's signature, key ID `29111145`.

- [ ] **Step 4: Proof 1 on the golden lab** (`lab/security/prove-w1.sh` stages each step and its evidence)
  1. Unpack repo 0.7.8 on srv1, client2 and cli1. `dnf --enablerepo=chp upgrade chp-site chp-integrity`.
  2. srv1: `chp-site security enable --stick <lab stick dir or the attached stick>`. Then client2 and cli1 the same.
  3. Evidence, recorded in `PROOF-RECORD-W1.md`:
     - `/var/opt/ossec/bin/agent_control -l` (or `/var/ossec/bin/…`) shows both agents **Active**;
     - `findmnt /var/ossec` shows the bind mount from `/srv/wazuh`;
     - `ss -ltnp`: 1514 on all addresses, 55000 **only on 127.0.0.1**, nothing on 1515;
     - `firewall-cmd --list-rich-rules` has exactly the two client rules;
     - `/var/ossec/bin/wazuh-analysisd -t` and `/var/ossec/bin/wazuh-agentd -t` both pass (the settings are accepted);
     - `grep -c "vulnerability-scanner" ossec.log` is 0 starts, and `du -sh /srv/wazuh` is well under 2 GB;
     - since the start of the proof: 0 Wazuh SELinux denials (the known `kanidm_unixd` row-49 lines excluded), 0 fapolicyd denials;
     - a second `security enable` on srv1 prints the same steps, and `client.keys`, `fstab` and the rich rules are unchanged (diff before/after).
  4. Reboot srv1 and confirm `wazuh-manager` comes back with `/var/ossec` mounted.

- [ ] **Step 5: Commit the proof record**

```bash
git add lab/security
git commit -m "Security bundle W1: repo 0.7.8 and proof 1 (upgrade + enable on the golden lab)"
```

---

### Task 7: Proof 2 (catch) and proof 3 (24-hour quiet check)

**Files:**
- Modify: `lab/security/PROOF-RECORD-W1.md`
- Possibly create: a tuning rules file `appliance/rpm/chp-security/chp_rules.xml` (only if the quiet check finds noise; see Step 3)

- [ ] **Step 1: Set a lab hook** that appends to a file: `ALERT_HOOK=/usr/local/sbin/lab-hook`, a script writing `date + "$1"` to `/var/log/lab-hook.log` (set in `/etc/chp/site.conf` on the lab server only).

- [ ] **Step 2: Catch proof**
  - From cli1, attempt 10 failed SSH logins to client2 within 1 minute.
    Expected: **one** hook line for client2 at level ≥ 10 (sshd brute force, e.g. rule 5712 or 5763), then after 15 minutes one "(N more …)" line.
  - On client2, `useradd labprobe`.
    Expected: no hook line (level 8); it is counted for the daily summary, and `chp-site alerts --level 7` shows it.
  - On cli1, `systemctl stop wazuh-agent`.
    Expected: within 1 minute, a hook line `cli1 rule 506 …`. Within 25 minutes, monitor check 71 reports "disconnected" (start the agent again afterwards).

  Record each line with its timestamp in the proof record.

- [ ] **Step 3: Quiet check:** leave the lab running 24 hours with the hook on. Then count the hook lines that did not come from the catch proof.
  - Expected: **0–2**.
  - For each noisy rule: add a local rule in `chp_rules.xml` lowering its level, with a comment giving the rule id, the reason and the date. Ship the file in `chp-security`, have `security enable` copy it to `/var/ossec/etc/rules/chp_rules.xml`, add a test for that copy, and record the tuning.
  - If no tuning is needed, record "no tuning needed" and do not create the file.

- [ ] **Step 4: Resources:** record the manager's RSS and `du -sh /srv/wazuh` after 24 hours.

- [ ] **Step 5: Commit**

```bash
git add lab/security appliance/rpm/chp-security tests
git commit -m "Security bundle W1: proof 2 (catch) and proof 3 (24-h quiet check)"
```

---

### Task 8: Release `0.2.0-update4`, final review, PR

**Files:**
- Create: `appliance/release/RELEASE-RECORD-0.7.8.md`, `appliance/release/UPDATE-0.2.0-update4.md.in`
- Modify: `appliance/release/release-kit.sh` (the README row), `appliance/site-stick-kit/SITE-STICK.md` (a short "From 0.2.0 update 4 on: the security add-on" section), `lab/iso-requirements.md` (a new row for the Wazuh FIPS POA&M fact)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_release_iso_static.py`):

```python
def test_update4_note_covers_enable_order_and_aide():
    u = (R / "UPDATE-0.2.0-update4.md.in").read_text()
    for s in ("dnf --enablerepo=chp upgrade chp-site chp-integrity", "chp-site security enable", "server first",
              "site stick", "aide-accept", "Explained by signed package updates", "FIPS", "POA&M"):
        assert s in u, s


def test_readme_lists_update4():
    assert "`0.2.0-update4/`" in (R / "release-kit.sh").read_text()
```

- [ ] **Step 2: Write the update note, release record, kit section and requirements row** (following the update3 files' shape).
  - The update note must say:
    - upgrade first;
    - then `security enable` on the server, with the site stick;
    - then each client, with the stick;
    - expect one AIDE alert, explained by signed package updates;
    - the FIPS POA&M wording from spec §6.
  - The release record carries proofs 1–3 with their evidence, and the package table (sha256 and signer key IDs; Wazuh's are `29111145`).

- [ ] **Step 3: Run the full suite.** Expected: all pass.

- [ ] **Step 4: Final whole-branch review** (executing-plans: a fresh reviewer on the most capable model, with this plan's Review Focus), then one fix pass for Critical and Important findings.

- [ ] **Step 5: Release** (the owner's "go" first): `V=0.2.0-update4 REPO_V=0.7.8 NOTE=UPDATE-0.2.0-update4.md.in bash appliance/release/release-repo.sh`. Add the share README row by hand, as for update3.

- [ ] **Step 6: Pre-publication scan, push, PR for the owner to merge.** Copy the update note to the Desktop as "Update 0.2.0-update4 - REVIEW.md".

## Out of scope (Plan W2 and later)

- ISO 0.3.0: the first-boot install, the `SECURITY_ADDONS` and `SECURITY_ALERT_LEVEL` site keys (in `sitefile.py`), and agent keys in the client bundle.
- The chp-templates narrative and POA&M updates (a chp-templates release after W2's proof).
- YARA, Suricata, metrics, the indexer and dashboard.
