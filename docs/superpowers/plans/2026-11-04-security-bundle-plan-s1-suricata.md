# Security Bundle Plan S1: Suricata Network IDS (0.4.0-update1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Suricata network intrusion detection (every host watches its own traffic, IDS only, ET Open rules) to the security add-on and release it to existing 0.4.0 sites as `0.4.0-update1` (repo 0.9.0).

**Architecture:** EPEL's `suricata` runs on every host with a CHP-owned config file (`/etc/suricata/chp-suricata.yaml`) that `chp-site security enable` writes: af-packet capture on the host's site interface, `HOME_NET` from `SUBNET`, alert-only `eve.json`. A new `chp-suricata-rules` package ships ET Open, tested with `suricata -T` at build time, with clean-appliance false alarms disabled by SID. Each Wazuh agent reads `eve.json`; CHP child rules of Wazuh's stock 86601 set the level from `alert.severity` (1 → 12, 2 → 7, 3 → 3).

**Tech Stack:** Python 3.9 stdlib (chp-site zipapp), bash, Suricata 7.0.x (EPEL 9), ET Open, Wazuh 4.14.9, RPM, systemd, the iso5 lab on aero.

**Spec:** `docs/superpowers/specs/2026-11-04-security-bundle-suricata-design.md` (frame: `2026-10-27-security-bundle-wazuh-design.md`; part 2: `2026-11-01-security-bundle-yara-design.md`).

## Global Constraints

- Every host with `SECURITY_ADDONS=yes` watches its own traffic; **IDS only**: nothing blocked or dropped, no automatic response.
- Rules: **ET Open only**; shipped as the signed package `chp-suricata-rules`, updated monthly; the appliance never downloads rules.
- Alerts through Wazuh's built-in Suricata decoding; CHP rules: severity **1 → level 12**, **2 → 7**, **3 → 3**.
- `eve.json` carries **alert events only**; no packet capture, no flow/DNS/HTTP/file logs; logs rotate daily, kept `RETENTION_DAYS`.
- No listening ports, no internet, SELinux enforcing, fapolicyd trusts only signed packages, FIPS mode on.
- `SECURITY_ADDONS=no` changes nothing; re-running `security enable` keeps the agent keys.
- Versions: chp-site **0.11.0**, chp-security **0.3.0**, chp-suricata-rules **<ET Open download date YYYY.MM.DD>**, repo **0.9.0**.
- Lessons carried from Y1: bump the RPM Release for every rebuild; create the log file before Wazuh starts; `dnf --refresh` in update notes; build helpers reach aero as a zipapp (fapolicyd blocks raw `.py`); the lab order on a fresh install is scan → adapter → nvram → snapspike → fixtures → golden.
- Owner "go" before every YubiKey signing; restart helpers first (`gpgconf --kill all`). The owner merges PRs; pre-publication scan before every push.

## Review Focus

1. **A host whose site address is not on any interface yet** (first boot before networking settles, or a renamed NIC): `enable` must refuse with a clear message, not write `af-packet: interface: None` (Task 3 test `test_no_interface_for_the_site_address_is_a_clear_error`).
2. **`SUBNET` missing from the site values** (an older site.conf): a clear SiteError naming the key (Task 3 test `test_missing_subnet_is_a_clear_error`).
3. **An `eve.json` line that is not an alert** (stats, a future event type) must not raise a CHP alert (Task 3 test `test_only_alert_events_are_levelled`).
4. **Suricata running but capturing nothing** (wrong interface, link down): the monitor must say so, not stay green (Task 4 test `test_monitor_alerts_when_eve_is_stale_while_running`).
5. **A rule SID in `disable.conf` that no longer exists upstream** must not break the build; it is reported (Task 2 test `test_unknown_disabled_sid_is_reported_not_fatal`).

---

## File Structure

| File | Responsibility |
|---|---|
| `lab/inputs/fetch-et-open.sh` (create) | fetch ET Open for Suricata 7 into a dated file, check its pinned sha256 |
| `lab/security/SPIKE-SURICATA.md` (create) | Task 1 findings |
| `appliance/rpm/chp-suricata-rules/build-rules.py` (create) | merge ET Open rules into one file, disable listed SIDs, write `DISABLED.txt` |
| `appliance/rpm/chp-suricata-rules/disable.conf`, `NOTICE`, `chp-suricata-rules.spec`, `build-rpm.sh` (create) | the rules package |
| `appliance/chp-site/chp_site/suricata_conf.py` (create) | the config text, the interface lookup, `HOME_NET` |
| `appliance/chp-site/chp_site/wazuh.py` (modify) | `eve.json` localfile; `SURICATA_RULES` |
| `appliance/chp-site/chp_site/security.py` (modify) | install, write config, start `suricata` |
| `appliance/rpm/chp-security/monitor.d/74-suricata.sh`, `chp-suricata.logrotate` (create) | health check, rotation |
| `lab/security/prove-s1.sh` (create) | stages `repo`, `enable`, `on`, `hook`, `catch`, `res` |
| `lab/security/PROOF-RECORD-S1.md` (create) | the proofs |
| `appliance/release/UPDATE-0.4.0-update1.md.in`, `RELEASE-RECORD-0.9.0.md`, `RULES-UPDATE.md`, `release-kit.sh`, `PACKAGES.txt` | release |

---

### Task 1: Spike: Suricata under FIPS, rule load, resources, clean-day alerts

No product code. It produces the facts later tasks use.

**Files:** Create `lab/inputs/fetch-et-open.sh`, `lab/security/SPIKE-SURICATA.md`; modify `lab/inputs/fetch-epel.sh` (`PKGS`).

**Interfaces:**
- Produces: `ET_DATE`, `ET_SHA256` (in `fetch-et-open.sh`); the EPEL file names (`suricata-7.0.x…`, plus EPEL-only dependencies); the EPEL `/etc/sysconfig/suricata` and unit facts; the measured memory/CPU; the SIDs that fired on a clean host (→ Task 2's `disable.conf`); a severity-1 test signature for the catch proof.

- [ ] **Step 1: Fetch Suricata from EPEL.** Find the file names: `curl -fsSL https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages/s/ | grep -o 'suricata-[0-9][^"]*x86_64.rpm'`. Add them to `PKGS` in `lab/inputs/fetch-epel.sh`, run it with `IDM_INPUTS` set to a scratch folder, copy the RPMs to aero `/data/lab-inputs/rpms` (with `sudo`), and run `lab/inputs/verify-epel.sh` there. For each requirement that is not on the Rocky DVD (`dnf --disablerepo='*' --enablerepo=lab-* provides <req>` on aero), fetch it from EPEL the same way. Expected: every RPM "OK signed by EPEL 9". Record the list.

- [ ] **Step 2: Write `lab/inputs/fetch-et-open.sh`**

```bash
#!/usr/bin/env bash
# Fetch ET Open for Suricata 7 (Suricata spec §2) into a dated file and check its pinned sha256. Mac only (internet).
set -Eeuo pipefail
IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
ET_URL=https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz
ET_DATE=<YYYY.MM.DD of the download>      # the chp-suricata-rules version
ET_SHA256=<sha256 of that download>
mkdir -p "$IN"; out="$IN/et-open-$ET_DATE.tar.gz"
[[ -s $out ]] || curl -fsSL "$ET_URL" -o "$out"
got=$(shasum -a 256 "$out" | cut -d' ' -f1)
[[ $got == "$ET_SHA256" ]] || { echo "ET Open sha256 $got is not the pinned $ET_SHA256"; exit 1; }
echo "OK ET Open $ET_DATE"
```

The URL serves the latest set; the date and sha256 pin the one we tested. Run it once with `ET_SHA256=x`, put the printed sha256 and today's date in, run again: expected `OK ET Open <date>`. Copy the file to aero `/data/lab-inputs/`. (If the ET URL path for Suricata 7 differs, use the one listed at `https://rules.emergingthreats.net/open/`; record it.)

- [ ] **Step 3: Install and check on iso5-cli2** (reset to golden first). Copy the RPMs over, `sudo dnf install -y --disablerepo='*' ./suricata*.rpm <deps>`. Then record:
  - `suricata --build-info | grep -i -E 'version|nss|openssl|af-packet|hyperscan'`;
  - `readelf -d /usr/sbin/suricata | grep NEEDED` (crypto libraries);
  - `cat /etc/sysconfig/suricata`, `systemctl cat suricata` (how options and the config path are passed; the run user);
  - `ls -Z /usr/sbin/suricata; ps -eZ | grep suricata` after a start (SELinux domain);
  - fapolicyd denials and AVCs since the start (0 expected).

- [ ] **Step 4: A minimal CHP config loads.** Write `/tmp/chp-suricata.yaml` with the text Task 3's `config_text()` will produce (copy it from Task 3 Step 3, with the lab's interface and `192.168.100.0/24`), unpack ET Open to `/tmp/et`, merge the rules (`cat /tmp/et/rules/*.rules > /tmp/all.rules`) and run `sudo suricata -T -c /tmp/chp-suricata.yaml -S /tmp/all.rules -v 2>&1 | tail -20`. Record: rules loaded, rules failed (and why), warnings. Adjust the config text until `-T` passes, and carry every change into Task 3.

- [ ] **Step 5: Resources and a clean day.** Run Suricata for real with that config on iso5-srv and iso5-cli2 (`sudo suricata -c /tmp/chp-suricata.yaml -S /tmp/all.rules --af-packet -D`), for at least 4 hours of normal lab activity (one regression scenario run included). Record RSS (`ps -o rss= -C Suricata-Main` or `suricata`), CPU, packet drops (`/var/log/suricata/stats.log`: `capture.kernel_drops`), and every alert in `eve.json`: SID, signature, severity, count. Each SID that fires on a clean appliance becomes a `disable.conf` line with the reason, unless it is a real finding (then report it to the owner).

- [ ] **Step 6: Pick the catch test.** Check the severity of rule 2100498 (`grep 2100498 /tmp/all.rules`, classtype → `/tmp/et/classification.config` priority). If it is not priority 1, find a priority-1 rule that a harmless in-lab HTTP response can trigger (search `classtype:trojan-activity` or `attempted-admin` rules with simple `content:` matches) and record the exact response body to serve.

- [ ] **Step 7: Revert and commit.** `bash lab/iso5/reset.sh`. Commit `lab/inputs/fetch-epel.sh lab/inputs/fetch-et-open.sh lab/security/SPIKE-SURICATA.md` ("S1 spike: Suricata under FIPS, ET Open load, resources, clean-day alerts").

**Stop rule:** if Suricata cannot run under FIPS/SELinux/fapolicyd, or a client needs more than 1.5 GB RSS, stop and report to the owner.

---

### Task 2: The `chp-suricata-rules` package

**Files:** Create `appliance/rpm/chp-suricata-rules/{build-rules.py, disable.conf, NOTICE, chp-suricata-rules.spec, build-rpm.sh}`; modify `appliance/release/PACKAGES.txt`; test `tests/test_chp_suricata_rules.py`.

**Interfaces:**
- Consumes: `ET_DATE`, the disable list (Task 1).
- Produces: `/usr/share/chp-suricata-rules/chp-suricata.rules` (one file), `DISABLED.txt` (`<sid>\t<reason>`), `ET_DATE`, `LICENSE`, `NOTICE`, plus ET's `classification.config` and `reference.config` in the same folder. `Requires: suricata >= 7.0, suricata < 8`.

- [ ] **Step 1: Write the failing tests**

```python
import importlib.util
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-suricata-rules"
spec = importlib.util.spec_from_file_location("build_rules_s", D / "build-rules.py")
br = importlib.util.module_from_spec(spec); spec.loader.exec_module(br)

R1 = 'alert http any any -> any any (msg:"one"; content:"x"; sid:1001; rev:1;)\n'
R2 = 'alert tcp any any -> any any (msg:"two"; sid:1002; rev:3;)\n'
R3 = '# alert tcp any any -> any any (msg:"commented upstream"; sid:1003; rev:1;)\n'


def tree(tmp_path):
    src = tmp_path / "rules"; src.mkdir()
    (src / "a.rules").write_text(R1 + R3); (src / "b.rules").write_text(R2)
    (src / "classification.config").write_text("config classification: x,X,1\n")
    out = tmp_path / "out"; out.mkdir()
    return src, out


def test_merges_rules_and_disables_listed_sids_with_reasons(tmp_path):
    src, out = tree(tmp_path)
    n_on, n_off, unknown = br.build(src, {"1002": "fires on the appliance's own Wazuh traffic"}, out)
    text = (out / "chp-suricata.rules").read_text()
    assert "sid:1001;" in text and text.count("\n# chp-disabled: ") == 1 and "#alert tcp any any" not in text
    assert "# chp-disabled: fires on the appliance's own Wazuh traffic\n# alert tcp any any -> any any (msg:\"two\"" in text
    assert (n_on, n_off, unknown) == (1, 1, [])
    assert (out / "DISABLED.txt").read_text() == "1002\tfires on the appliance's own Wazuh traffic\n"


def test_unknown_disabled_sid_is_reported_not_fatal(tmp_path):              # Review Focus 5
    src, out = tree(tmp_path)
    assert br.build(src, {"9999": "gone upstream"}, out)[2] == ["9999"]


def test_classification_and_reference_files_are_copied(tmp_path):
    src, out = tree(tmp_path); (src / "reference.config").write_text("config reference: url http://\n")
    br.build(src, {}, out)
    assert (out / "classification.config").exists() and (out / "reference.config").exists()


def test_disable_file_format():
    assert br.load_disable("# c\n2100498 fires on the lab's test page  # note\n\n2000001\n") == \
        {"2100498": "fires on the lab's test page", "2000001": "disabled"}


def test_spec_and_notice():
    s = (D / "chp-suricata-rules.spec").read_text()
    assert "Vendor:         The CyberHygiene Project" in s and "Requires:       suricata >= 7.0, suricata < 8" in s
    for f in ("chp-suricata.rules", "DISABLED.txt", "ET_DATE", "LICENSE", "NOTICE", "classification.config"):
        assert f in s, f
    n = (D / "NOTICE").read_text()
    assert "Emerging Threats" in n and "ET Open" in n


def test_packages_list():
    p = (Path(__file__).resolve().parents[1] / "appliance/release/PACKAGES.txt").read_text().splitlines()
    assert "suricata epel" in p and "chp-suricata-rules ours" in p
```

- [ ] **Step 2: Run them.** `.venv/bin/python -m pytest -q tests/test_chp_suricata_rules.py` → FAIL (no `build-rules.py`).

- [ ] **Step 3: Write `build-rules.py`**

```python
#!/usr/bin/env python3
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Merge ET Open into one rules file for chp-suricata-rules (Suricata spec §2). Usage: build-rules.py RULES_DIR
DISABLE_CONF OUT_DIR. Listed SIDs are commented out with the reason; DISABLED.txt lists them; unknown SIDs are reported."""
import re
import shutil
import sys
from pathlib import Path

SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")


def load_disable(text):
    out = {}
    for ln in text.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if ln:
            sid, _, why = ln.partition(" ")
            out[sid] = why.strip() or "disabled"
    return out


def build(src, disable, out):
    src, out = Path(src), Path(out)
    lines, on, off, seen = [], 0, 0, set()
    for f in sorted(src.glob("*.rules")):
        for ln in f.read_text(errors="replace").splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue                                   # upstream-commented rules stay out
            m = SID.search(s)
            sid = m.group(1) if m else None
            if sid in disable:
                lines.append(f"# chp-disabled: {disable[sid]}\n# {s}"); off += 1; seen.add(sid)
            else:
                lines.append(s); on += 1
    (out / "chp-suricata.rules").write_text("\n" + "\n".join(lines) + "\n")
    (out / "DISABLED.txt").write_text("".join(f"{s}\t{disable[s]}\n" for s in sorted(seen, key=int)))
    for name in ("classification.config", "reference.config"):
        if (src / name).exists():
            shutil.copy(src / name, out / name)
    return on, off, sorted(set(disable) - seen, key=int)


if __name__ == "__main__":
    s, d, o = sys.argv[1:4]
    on, off, unknown = build(s, load_disable(Path(d).read_text()), o)
    print(f"enabled {on} rules, disabled {off}" + (f"; NOT FOUND upstream: {', '.join(unknown)}" if unknown else ""))
```

- [ ] **Step 4: Package files.** `disable.conf` (header `# <sid> <reason>: ET Open rules disabled because they fire on a clean appliance (Suricata spec §2)` plus Task 1's lines). `NOTICE`: "chp-suricata-rules contains the Emerging Threats Open ruleset (ET Open) for Suricata, © Proofpoint, Inc., downloaded on the date in ET_DATE and used unmodified except for the rules listed in DISABLED.txt. ET Open is distributed under the licence in LICENSE. Packaged by the CyberHygiene Project." The spec (as `chp-yara-rules.spec`, with `Vendor:`/`URL:`, `License: GPL-2.0-only AND BSD-3-Clause` or what ET's LICENSE says — read it in Task 1 and record it; `Version: %{rules_version}`; files under `%{_datadir}/chp-suricata-rules/`; `Requires: suricata >= 7.0, suricata < 8`). `build-rpm.sh` as `appliance/rpm/chp-yara-rules/build-rpm.sh`: read `ET_DATE` from `fetch-et-open.sh`, ship `build-rules.py` as a zipapp, unpack `/data/lab-inputs/et-open-$ET_DATE.tar.gz`, run the zipapp, copy ET's LICENSE, then **`suricata -T`** with a test config pointing at the merged file (fail the build on error), `echo $ET_DATE > ET_DATE`, `rpmbuild` with `--define "rules_version $ET_DATE"`, copy to `/data/chp-release/built/`. `PACKAGES.txt`: `suricata epel` (and any EPEL-only dependency names from Task 1), `chp-suricata-rules ours`.

- [ ] **Step 5: Tests, build, commit.** Suite green; `bash appliance/rpm/chp-suricata-rules/build-rpm.sh` → `enabled N rules, disabled M` and the `-T` pass; commit "chp-suricata-rules: ET Open merged, clean-appliance SIDs disabled with reasons, tested with suricata -T".

---

### Task 3: `chp-site` settings writer and the Wazuh rules

**Files:** Create `appliance/chp-site/chp_site/suricata_conf.py`; modify `wazuh.py`; tests `tests/test_chp_site_suricata.py`, `tests/test_chp_site_wazuh.py`.

**Interfaces:**
- Produces: `suricata_conf.CONF = "/etc/suricata/chp-suricata.yaml"`, `EVE = "/var/log/suricata/eve.json"`, `RULES_DIR = "/usr/share/chp-suricata-rules"`; `iface_for(ip, run) -> str` (SiteError if none); `home_net(site) -> str` (SiteError if no SUBNET); `config_text(iface, home_net) -> str`; `sysconfig_text(iface) -> str`; `wazuh.SURICATA_RULES` (XML); both `harden_*` add a `json` localfile for `EVE`.

- [ ] **Step 1: Write the failing tests** (`tests/test_chp_site_suricata.py`)

```python
import ipaddress
from types import SimpleNamespace

import pytest

from chp_site import suricata_conf as sc
from chp_site.sitefile import SiteError

IP_ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
           "2: enp1s0    inet 192.168.100.52/24 brd 192.168.100.255 scope global enp1s0\\       valid_lft forever\n")


def run_ip(out=IP_ADDR):
    return lambda argv, **kw: SimpleNamespace(returncode=0, stdout=out, stderr="")


def test_iface_for_finds_the_site_address():
    assert sc.iface_for("192.168.100.52", run_ip()) == "enp1s0"


def test_no_interface_for_the_site_address_is_a_clear_error():                # Review Focus 1
    with pytest.raises(SiteError, match="192.168.100.99"):
        sc.iface_for("192.168.100.99", run_ip())


def test_home_net_is_the_site_subnet():
    assert sc.home_net({"SUBNET": ipaddress.IPv4Network("192.168.100.0/24")}) == "[192.168.100.0/24]"


def test_missing_subnet_is_a_clear_error():                                    # Review Focus 2
    with pytest.raises(SiteError, match="SUBNET"):
        sc.home_net({})


def test_config_is_ids_only_alert_only_on_one_interface():
    t = sc.config_text("enp1s0", "[192.168.100.0/24]")
    assert "HOME_NET: \"[192.168.100.0/24]\"" in t and "EXTERNAL_NET: \"!$HOME_NET\"" in t
    assert "- interface: enp1s0" in t and "copy-mode" not in t and "nfq" not in t
    assert "filename: eve.json" in t and "- alert" in t
    for off in ("- flow", "- dns", "- http", "- tls", "- fileinfo", "pcap-log", "- drop"):
        assert off not in t, off
    assert f"default-rule-path: {sc.RULES_DIR}" in t and "- chp-suricata.rules" in t
    assert "unix-command" not in t or "enabled: no" in t
```

In `tests/test_chp_site_wazuh.py`:

```python
from chp_site import suricata_conf as _sc


def test_both_roles_read_eve_once():
    for out in (w.harden_manager(MGR), w.harden_agent(AGT, "192.0.2.10"), w.harden_manager(w.harden_manager(MGR))):
        locs = [e.findtext("location") for x in w.parse_conf(out) for e in x.findall("localfile")
                if e.findtext("location") == _sc.EVE]
        assert len(locs) == 1


def test_suricata_levels():
    r = w.SURICATA_RULES
    assert "<if_sid>86601</if_sid>" in r and '<field name="alert.severity">^1$</field>' in r
    assert 'level="12"' in r and 'level="7"' in r and '<field name="alert.severity">^2$</field>' in r


def test_only_alert_events_are_levelled():                                     # Review Focus 3
    assert "86600" not in w.SURICATA_RULES                                      # children of the alert rule only
```

- [ ] **Step 2: Run them** → FAIL (no module).

- [ ] **Step 3: Write `suricata_conf.py`** (use Task 1's verified config text if `-T` required changes)

```python
"""Suricata settings (Suricata spec §3): IDS only on the host's site interface, HOME_NET from SUBNET, alert-only eve.json.
Pure text and one read-only lookup; security.enable writes the files."""
import re

from .sitefile import SiteError

CONF = "/etc/suricata/chp-suricata.yaml"
EVE = "/var/log/suricata/eve.json"
RULES_DIR = "/usr/share/chp-suricata-rules"


def iface_for(ip, run):
    out = run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/", ln)
        if m and m.group(2) == str(ip):
            return m.group(1)
    raise SiteError(f"no network interface holds this host's site address {ip}: Suricata cannot pick an interface")


def home_net(site):
    if not site.get("SUBNET"):
        raise SiteError("SUBNET is not set in site.conf: Suricata needs it for HOME_NET")
    return f"[{site['SUBNET']}]"


def config_text(iface, home_net):
    return f"""%YAML 1.1
---
# Managed by chp-security (Suricata spec §3); rewritten by chp-site security enable. IDS only: nothing is blocked.
vars:
  address-groups:
    HOME_NET: "{home_net}"
    EXTERNAL_NET: "!$HOME_NET"
default-log-dir: /var/log/suricata/
default-rule-path: {RULES_DIR}
rule-files:
  - chp-suricata.rules
classification-file: {RULES_DIR}/classification.config
reference-config-file: {RULES_DIR}/reference.config
af-packet:
  - interface: {iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
  - stats:
      enabled: yes
      filename: stats.log
      interval: 60
logging:
  default-log-level: notice
  outputs:
    - file:
        enabled: yes
        filename: /var/log/suricata/suricata.log
unix-command:
  enabled: no
"""


def sysconfig_text(iface):
    return f'# Managed by chp-security (Suricata spec §3)\nOPTIONS="-c {CONF} --af-packet={iface} --user suricata"\n'
```

(The EPEL unit's exact variable name comes from Task 1 Step 3 — if the unit does not read `OPTIONS` from `/etc/sysconfig/suricata`, write a systemd drop-in `ExecStart=` instead and test that text.)

- [ ] **Step 4: Wazuh pieces in `wazuh.py`.** Add `from . import suricata_conf as _sc`; a `_eve_log(blocks)` like `_yara_log` for `_sc.EVE`, called in both `harden_manager` and `harden_agent`; and

```python
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
```

(Severity 3 keeps the stock level 3 of 86601.)

- [ ] **Step 5: Tests green; commit** "chp-site: Suricata settings (IDS only, HOME_NET from SUBNET, alert-only eve) and Wazuh severity rules".

---

### Task 4: `chp-security` 0.3.0, `chp-site` 0.11.0 and `security enable`

**Files:** Create `appliance/rpm/chp-security/monitor.d/74-suricata.sh`, `chp-suricata.logrotate`; modify `chp-security.spec`, `build-rpm.sh`, `appliance/chp-site/chp_site/security.py`, `chp-site.spec`, `chp_site/__init__.py`; tests in `tests/test_chp_security_static.py`, `tests/test_chp_security_monitor.py`, `tests/test_chp_site_security.py`, `tests/test_chp_site_cli.py`.

**Interfaces:** Consumes Task 3. Produces: `enable` installs `suricata chp-suricata-rules` with the rest; writes `CONF` (0640 root:suricata) and the sysconfig/drop-in; writes `/var/ossec/etc/rules/chp_suricata_rules.xml` on the server; creates `EVE` before the units start; adds `suricata` to the enabled units on both roles.

- [ ] **Step 1: Failing tests.**
  - Static: `Version: 0.3.0`; `Requires: …, suricata, chp-suricata-rules`; the logrotate file rotates `/var/log/suricata/*.log /var/log/suricata/*.json` daily with `copytruncate` and `missingok`; `74-suricata.sh` packaged.
  - Monitor (`74-suricata.sh`, env `CHP_SECURITY_CONF`, `CHP_SURICATA_LOG_DIR`, `CHP_NOW`, a fake `systemctl`):
    - not enabled → `OK`;
    - service not active → `ALERT … Suricata is not running`;
    - `test_monitor_alerts_when_eve_is_stale_while_running` (Review Focus 4): active, `stats.log` older than 10 minutes → `ALERT … Suricata is running but has written no stats for N minutes (check the capture interface)`;
    - active and fresh → `OK`;
    - `stats.log` showing `capture.kernel_drops` above 1% of `capture.kernel_packets` → `ALERT … dropping packets`.
  - Enable (existing helpers in `tests/test_chp_site_security.py`; give `enable()`'s site dict a `SUBNET` and make the fake `Run` answer `ip -o -4 addr show` with a line holding the host's IP):
    - the dnf install list ends `"yara", "chp-yara-rules", "suricata", "chp-suricata-rules"`;
    - `etc/suricata/chp-suricata.yaml` equals `config_text(<iface>, "[<subnet>]")` with mode 0640;
    - `suricata` in the `systemctl enable --now` call on both roles;
    - the server writes `chp_suricata_rules.xml` equal to `SURICATA_RULES`; the client does not;
    - `var/log/suricata/eve.json` exists before the units start;
    - re-running `enable` keeps `client.keys`.
  - CLI: version `chp-site 0.11.0`.

- [ ] **Step 2: Run** → the new tests FAIL.

- [ ] **Step 3: Implement.**
  - `74-suricata.sh` (bash, same header and env pattern as `73-yara-scan.sh`; `date -r` for file ages, not `stat -c`).
  - `chp-suricata.logrotate`:

```
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 90
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
```

  - The spec: version, requires, sources, `%install`, `%files`, changelog.
  - In `security._enable`:
    - add `"suricata", "chp-suricata-rules"` to the dnf call;
    - after `_conf(...)`, write the config and sysconfig (`iface = sc.iface_for(me_ip, run)`, where `me_ip` is the IP of the `hosts` entry whose hostname is `host`; `sc.home_net(site)`);
    - create `EVE` (0640) like the YARA log;
    - on the server, write `chp_suricata_rules.xml`;
    - add `"suricata"` to both unit lists.
  - `chp-site.spec` / `__init__.py` → 0.11.0-1; `chp-security.spec` → 0.3.0-1.

- [ ] **Step 4: Suite green; commit** "chp-security 0.3.0 + chp-site 0.11.0: Suricata (config, Wazuh rules, rotation, monitor 74); enable installs it".

---

### Task 5: Build, sign repo 0.9.0, prove on the lab

**Files:** Create `lab/security/prove-s1.sh`, `lab/security/PROOF-RECORD-S1.md`.

- [ ] **Step 1: Build and assemble.**
  - Build chp-site, chp-security and chp-suricata-rules (`build.sh`, the three `build-rpm.sh`).
  - Copy the EPEL RPMs into `/data/lab-inputs/rpms`.
  - Run `push.sh`, then `assemble-repo.sh /data/chp-release/0.9.0/stage …`.
  - Expected: chp-site 0.11.0-1, chp-security 0.3.0-1, chp-suricata-rules, suricata, plus the 0.8.0 set.

- [ ] **Step 2: Sign (owner "go").** Restart helpers (`gpgconf --kill all`), cue the owner, then run `sign-session.sh` with `sign-repo.sh … 0.9.0 …`. Expected: `REPO OK`. If it is REFUSED for a missing `Vendor`, fix the spec and bump Release.

- [ ] **Step 3: Write `prove-s1.sh`.** Base it on `lab/security/prove-y1.sh` (same `X`, `A`, `check`, `done_` helpers, srv + cli2; cli1 has no lab sudo). Stages:
  - `repo`: unpack 0.9.0; `dnf -q -y --refresh --enablerepo=chp upgrade`; record a hash of `client.keys` in `/root/s1-keys-before`.
  - `enable H`: attach the stick and run `security enable`, as in `prove-y1.sh enable`.
  - `on`, on both hosts:
    - packages installed;
    - `systemctl is-active suricata` → `active`;
    - `suricata -T -c /etc/suricata/chp-suricata.yaml` passes;
    - the interface in the config holds the host's IP;
    - eve exists; 0 Suricata AVCs and 0 fapolicyd denials since enable;
    - keys unchanged; Suricata's RSS is recorded.
    - On the server only: the rules XML is present and both agents are Active.
  - `hook`: as in `prove-y1.sh`.
  - `catch`: on the server, serve the Task 1 test body with `python3 -m http.server` from a temporary folder bound to the server's IP on a high port. On iso5-cli2, `curl` that URL. Then check:
    - an `alert` line with the expected SID in cli2's `eve.json` within 60 s;
    - the server's `alerts.json` has rule 100510 (or 100511/86601, whichever the chosen test's severity gives);
    - for severity 1, a line in the lab hook.
    - Then stop the server and remove the folder.
  - `res`: RSS and CPU of Suricata on both hosts; `capture.kernel_drops` versus packets from `stats.log`.

- [ ] **Step 4: Run the proofs.** Run `reset.sh`, then `prove-s1.sh repo`, `enable srv`, `enable cli2`, `on`, `hook`, `catch`, `res`. Expected: ALL PASS. Record the results in `PROOF-RECORD-S1.md`.

- [ ] **Step 5: Quiet day.** 24 h without resets, then record:
  - every Suricata alert by SID and severity on both hosts. **Expected: no severity-1 alerts.** Any other new clean-day SIDs go back to Task 2's `disable.conf` (rebuild, bump Release, re-sign);
  - the first daily AIDE check's added and changed entries, all explained, for the update notes;
  - RSS and CPU at 24 h.

- [ ] **Step 6: Commit** "S1: repo 0.9.0 lab proofs (Suricata on, catch, resources, quiet day)".

---

### Task 6: Gates on the upgraded lab

- [ ] Run, in order:
  - `prove.sh adapter`, `nvram`, `golden` (the scenario users are already in the 0.4.0 golden snapshot; if `fixtures.py` stops on an existing user, ignore it);
  - the regression: `IDM_PROFILE=appliance IDM_TEST_APPROVE=1 .venv/bin/python -m engine regress --runs 3 --out lab/iso5/regression-<date>.md` → **33/33**;
  - `prove.sh row36` → 3/3;
  - `prove.sh scan` and `deviations.py` → **108/2, Gate 3 met** (compress the results).
- Record the results in `PROOF-RECORD-S1.md` and commit "S1: gates on repo 0.9.0".

---

### Task 7: Release `0.4.0-update1`

- [ ] **Step 1: Failing test** (`tests/test_release_iso_static.py`): `UPDATE-0.4.0-update1.md.in` contains `@REPO@`, `chp-site security enable`, `IDS`, `nothing is blocked`, `/var/log/suricata/eve.json`, `--refresh`, `chp-site aide-accept`, `ET Open`, `monthly`. `RULES-UPDATE.md` mentions `fetch-et-open.sh` and `disable.conf`. `release-kit.sh` has rows for `0.4.0-update1/` and `site-stick-kit-0.4.0-update1/`.
- [ ] **Step 2: Write the notes**, following `UPDATE-0.3.0-update1.md.in`:
  - what it adds;
  - how to apply it, with `--refresh`, server first;
  - how to test it (the in-lab test page);
  - the AIDE list from Task 5;
  - known limits (IDS only; each host sees only its own traffic; resource figures).
  - Also:
    - extend `RULES-UPDATE.md` with the ET Open steps;
    - add a kit guide section "From 0.4.0 update 1 on: network intrusion detection (Suricata)";
    - add the README rows.
- [ ] **Step 3: Final whole-branch review** (fresh reviewer, most capable model), then one fix pass. Every fix is test-first, bumps the Release, and is followed by re-sign and re-proof.
- [ ] **Step 4: Release (owner "go").**
  - Put the notes on the Desktop.
  - Run `release-repo.sh` (V=0.4.0-update1, REPO_V=0.9.0, NOTE=UPDATE-0.4.0-update1.md.in), then `release-kit.sh` (V=0.4.0-update1).
  - Write `RELEASE-RECORD-0.9.0.md`.
- [ ] **Step 5: chp-templates.** Add Rev 2 narratives for 3.14.6, 3.14.7 and 3.13.1 (Suricata with the add-on), content 1.2.3, golden regenerated, PR there. **Tell the owner and diwai before any templates release.**
- [ ] **Step 6: PR.** Pre-publication scan, push, open a PR with the rulings and deferred minors; the owner merges.
