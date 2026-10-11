# ISO Plan 5b: Regression on Installed Hosts, Then Release — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Meet spec §1 gate 2 on hosts installed from the ISO (the 11 scenarios L1–L6, L3n, C1–C4 GREEN ×3, plus the
row-36 `gdm-password` check). Then release the tested ISO to the For Jeff share (spec §8 step 5).

**Architecture:** The diagnostic engine gets a **profile**: `lab` (today's srv1 + client2, the default; nothing changes)
or `appliance` (iso5-srv + iso5-cli2, installed from the ISO). Scenarios and repairs keep the logical names `srv1` and
`client2`. The profile maps them to real hosts (a separate ssh config), hostnames, IPs, the domain, group naming, file
paths, trust pins, the lab-secrets prefix, the reset script and the login method.
- Two product defects found while planning are fixed first. A last ISO (rc4) is built from them and installed from
  nothing, and the CUI scan is run again.
- A lab adapter (lab only, added **after** the scan) gives the harness admin access. Golden snapshots are then taken.
- The regression runs with `IDM_PROFILE=appliance`.

**Tech Stack:** Python 3 (engine, pytest), POSIX sh/bash, expect, libvirt on aero, the signed RPM repo, YubiKey signing.

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md` (§1 gates 1–3, §8 release, §11 acceptance,
§12 item 5). Requirements: `lab/iso-requirements.md` (rows 9–11, 18, 19, 24–36). Plan 5a: `lab/iso5/PROOF-RECORD.md`,
`DEVIATIONS.md` (rc3 is the base).

## Facts established while planning (2026-10-11, measured on the running iso5 hosts)

- **Defect P1:** clients have no usable `/etc/idm-collect/collect.conf` (`KANIDM_URL` and `CA_ANCHOR` missing). Only
  `server-firstboot.sh` writes it. As a result `idm-collect` on every appliance client reports `COLLECT_CONF_INVALID` and
  cannot check TLS or trust. The server's report is clean.
- **Defect P2:** the collector's `restorecon -n` path list names the lab path `/etc/ssh/trusted_user_ca_keys`, but the
  appliance keeps the SSH CA key at `/etc/ssh/chp_user_ca.pub`. A mislabel there would go unseen (row 33).
- **Layout differences, lab → appliance:**

  | Item | Lab | Appliance |
  |---|---|---|
  | anchor | `kanidm-lab-root.crt` | `/etc/pki/ca-trust/source/anchors/chp-root.crt` |
  | sshd drop-in | `10-kanidm.conf` | `10-chp.conf` |
  | SSH CA key file | `trusted_user_ca_keys` | `/etc/ssh/chp_user_ca.pub` |
  | domain | `kanidm.lab.test` | `iso5.lab.test` (Kanidm: `idm.<domain>`) |
  | group names | SPNs | short names (row 9) |
  | client login group | `lab_users` | `chp_users` |
  | root CA certificate on the server | `/root/.step/certs/root_ca.crt` | `/etc/step-ca/certs/root_ca.crt` |
  | CA root pin | colon-hex file in `lab/trust/` | lower-case hex in `client.conf` (`CA_ROOT_SHA256`) |

  Unchanged in both: `STEPPATH=/root/.step`, the Kanidm certificate paths, `cert-renew-kanidm.timer`, `/var/lib/ssh-ca`.
- **Logins:** appliance sshd requires `publickey,keyboard-interactive:pam`: a key or certificate, **and** the GA code,
  **and** the password. So the lab probes (password only: `ssh-login.exp`; certificate only: `ssh-cert-login.sh`)
  can never succeed there. GA refuses a code reused in the same 30-second window (`-d`).
- **Admin access:** `chpadmin` (key-only, wheel) has no password, so `sudo` cannot work for it.
- **Snapshots:** the iso5 VMs have a raw NVRAM and a vTPM. libvirt needs a qcow2 NVRAM for internal snapshots
  (`lab/host/nvram-qcow2.sh`, as for the old lab). Snapshots with a vTPM are **unproven**, so Task 6 tests them first.

## Global Constraints

- `IDM_PROFILE` unset or `lab` = exactly today's behaviour. The existing suite must stay green unchanged, apart from the
  attribute-to-call changes named in Task 3.
- **Lab adapter (assumed default, 2026-10-10):** added only **after** the final CUI scan (Task 5). It is never in the ISO
  or an RPM. It is recorded in `lab/iso5/LAB-ADAPTER.md`.
  - What it is: `/etc/sudoers.d/99-lab-adapter` = `chpadmin ALL=(ALL) NOPASSWD: ALL`, mode 0440, on `iso5-srv` and
    `iso5-cli2` only.
- Lab secrets live only in `~/idm-lab-secrets` (0600), with an `iso5-` prefix for the appliance profile. They are never
  printed, committed, or copied to For Jeff.
- The release copies the **exact tested ISO bytes**. It never rebuilds after testing.
- **Model:** the regression uses the LM Studio model, as in Plans 6–8. If it is unavailable, runs report `EXPLAIN-FAILED`;
  start LM Studio and re-run.
- **Faillock:** a probe that fails counts toward faillock. A scenario may plan at most one expected refusal per user.
- Python: `.venv/bin/python`; tests `.venv/bin/python -m pytest -q tests`. Commits end with the Co-Authored-By line.
- **Never edit a script while it runs** (Plan 5a lesson). Launch any run longer than 2 hours with `nohup` plus a watcher.

## Review Focus

1. **`IDM_PROFILE` has an unknown value:** the engine stops with a clear message. It never silently uses the lab (test in
   Task 2).
2. **Two probes for the same user within one 30-second window:** the second must not fail because of GA's reuse refusal.
   The login helper waits for a fresh window (test in Task 4).
3. **A report's hostname doesn't match the profile's mapping** (for example a stale ssh config pointing at the wrong
   VM): `target_role` refuses. A repair never runs on the wrong host (test in Task 2).
4. **The appliance pins file is missing or stale** after a reinstall: the CA-trust and SSH-CA repairs refuse ("pin
   missing") instead of trusting what the host serves (test in Task 3).
5. **The regression is started while the hosts aren't at golden** (for example right after a failed run): the reset
   script fails loudly if a revert or the clock resync fails. It never runs scenarios on a dirty host (check in Task 6).

---

### Task 1: Product fixes P1 and P2

**Files:**
- Modify: `appliance/rpm/chp-identity-client/client-enrol.sh` (new step `collect`), `chp-identity-client.spec`
  (0.2.2-1, changelog); `collector/idm-collect` (relabel path list), `appliance/rpm/idm-collect/idm-collect.spec` (0.1.0-10)
- Test: `tests/test_client_role_static.py`, `tests/test_collector_script.py`

- [ ] **Step 1: Failing tests.** Append to `tests/test_client_role_static.py`:

```python
def test_enrol_writes_the_collector_conf():          # Plan 5b P1: clients had no collect.conf (COLLECT_CONF_INVALID)
    t = text("client-enrol.sh")
    assert "chp-site render collect-conf > /etc/idm-collect/collect.conf.new" in t
    assert "install -m 0644 /etc/idm-collect/collect.conf.new /etc/idm-collect/collect.conf" in t
    assert t.index("step collect do_collect") > t.index("step trust do_trust")
```

  Append to `tests/test_collector_script.py`:

```python
def test_relabel_check_covers_the_appliance_ssh_ca_key():   # Plan 5b P2 (row 33)
    t = SCRIPT.read_text()
    loop = t[t.index("for pth in /run/kanidm-unixd"):t.index("relab=\"[]\"")]
    assert "/etc/ssh/chp_user_ca.pub" in loop and "/etc/ssh/trusted_user_ca_keys" in loop
```

- [ ] **Step 2:** `.venv/bin/python -m pytest -q tests/test_client_role_static.py tests/test_collector_script.py` → the 2 new tests FAIL.

- [ ] **Step 3: Implement.** In `client-enrol.sh`, before the `step trust do_trust` line, add:

```bash
do_collect() {        # Plan 5b P1: the collector's site data (the server writes the same at its first boot)
  install -d -m 0755 /etc/idm-collect
  chp-site render collect-conf > /etc/idm-collect/collect.conf.new
  install -m 0644 /etc/idm-collect/collect.conf.new /etc/idm-collect/collect.conf; rm -f /etc/idm-collect/collect.conf.new
  restorecon -R /etc/idm-collect
}
```

  After `step accounts do_accounts`, add `step collect do_collect`.
  - In `collector/idm-collect`, change the loop head to
    `for pth in /run/kanidm-unixd /var/cache/kanidm-unixd /var/lib/kanidm-unixd /etc/kanidm /etc/ssh/trusted_user_ca_keys /etc/ssh/chp_user_ca.pub \`.
    The next line stays `/etc/pki/ca-trust/source/anchors; do`.
  - Bump the specs: chp-identity-client `0.2.2`, idm-collect release `10`, each with a dated changelog line naming
    P1 or P2.
  - Copy the collector into the RPM source, the same way earlier releases did (check how
    `appliance/rpm/idm-collect/build-rpm.sh` takes `collector/idm-collect`).

- [ ] **Step 4:** Full suite → all PASS.
- [ ] **Step 5: Commit** `ISO Plan 5b Task 1: clients write collect.conf (P1); collector checks the appliance SSH CA key label (P2)`.

---

### Task 2: Engine profile, remote access, host mapping

**Files:**
- Create: `engine/profile.py`, `lab/iso5/ssh_config`, `tests/test_profile.py`
- Modify: `engine/remote.py` (ssh `-F`), `engine/labsecrets.py` (prefix), `engine/repairs.py` (`target_role`),
  `engine/cli.py` (reset command, report header)

**Interfaces (Produces):**
- `profile.current() -> Profile`: reads `IDM_PROFILE` at every call; raises `ValueError` on an unknown name.
- `Profile` fields: `name, hostnames: dict, vms: dict, ips: dict, domain, short_names: bool, login_group, anchor,
  sshd_dropin, trusted_ca_keys, ca_root_path, ssh_config: Optional[str], secrets_prefix, reset`.
- Methods: `fqdn() -> "idm.<domain>"`, `group(name) -> str`, `ip(alias)`, `pinned_root() -> "AA:BB:…"`,
  `pinned_ssh_ca() -> "SHA256:…"`.
- `remote.ssh_base() -> list[str]`. `labsecrets.path(name)` = `DIR / (prefix + name)`.

- [ ] **Step 1: Failing tests** `tests/test_profile.py`:

```python
import json

import pytest

from engine import labsecrets, profile, remote
from engine.repairs import target_role


def test_default_is_the_lab(monkeypatch):
    monkeypatch.delenv("IDM_PROFILE", raising=False)
    p = profile.current()
    assert p.name == "lab" and p.fqdn() == "idm.kanidm.lab.test" and p.group("lab_users") == "lab_users@idm.kanidm.lab.test"
    assert remote.ssh_base() == ["ssh", "-o", "BatchMode=yes"] and labsecrets.path("x.json").name == "x.json"


def test_appliance_mapping(monkeypatch):
    monkeypatch.setenv("IDM_PROFILE", "appliance")
    p = profile.current()
    assert p.hostnames == {"srv1": "iso5-srv", "client2": "iso5-cli2"} and p.ip("srv1") == "192.168.100.50"
    assert p.group("chp_users") == "chp_users" and p.anchor.endswith("/chp-root.crt")
    assert p.sshd_dropin.endswith("/10-chp.conf") and p.trusted_ca_keys == "/etc/ssh/chp_user_ca.pub"
    assert remote.ssh_base()[:3] == ["ssh", "-F", str(profile.ROOT / "lab/iso5/ssh_config")]
    assert labsecrets.path("lab01.json").name == "iso5-lab01.json"


def test_unknown_profile_stops(monkeypatch):                    # Review Focus 1
    monkeypatch.setenv("IDM_PROFILE", "aplliance")
    with pytest.raises(ValueError, match="IDM_PROFILE"):
        profile.current()


def test_target_role_uses_the_mapped_hostname(monkeypatch):    # Review Focus 3
    monkeypatch.setenv("IDM_PROFILE", "appliance")
    assert target_role({"host": "iso5-cli2", "role": "client"}, "client2") == "client"
    with pytest.raises(ValueError):
        target_role({"host": "iso5-cli1", "role": "client"}, "client2")


def test_appliance_pins_come_from_the_secrets_file(monkeypatch, tmp_path):
    monkeypatch.setenv("IDM_PROFILE", "appliance"); monkeypatch.setattr(labsecrets, "DIR", tmp_path)
    (tmp_path / "iso5-pins.json").write_text(json.dumps({"CA_ROOT_SHA256": "ab" * 32, "SSH_CA_FPR": "SHA256:xyz"}))
    assert profile.current().pinned_root() == ":".join(["AB"] * 32) and profile.current().pinned_ssh_ca() == "SHA256:xyz"


def test_missing_pins_file_refuses(monkeypatch, tmp_path):        # Review Focus 4
    monkeypatch.setenv("IDM_PROFILE", "appliance"); monkeypatch.setattr(labsecrets, "DIR", tmp_path)
    with pytest.raises(FileNotFoundError, match="pins"):
        profile.current().pinned_root()
```

- [ ] **Step 2:** run → FAIL (no `engine.profile`).

- [ ] **Step 3: `engine/profile.py`**

```python
"""Which hosts the engine drives. "lab" (default): the aero lab srv1 + client2. "appliance": hosts installed from the CHP
ISO (iso5-srv + iso5-cli2). Scenarios and repairs keep the LOGICAL names srv1/client2; this maps them to real hosts,
names, paths and pins. Read from IDM_PROFILE at every call."""
import json
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Profile:
    name: str
    hostnames: dict
    vms: dict
    ips: dict
    domain: str
    short_names: bool
    login_group: str
    anchor: str
    sshd_dropin: str
    trusted_ca_keys: str
    ca_root_path: str
    ssh_config: Optional[str]
    secrets_prefix: str
    reset: str

    def fqdn(self):
        return f"idm.{self.domain}"

    def group(self, name):
        return name if self.short_names else f"{name}@{self.fqdn()}"

    def ip(self, alias):
        return self.ips[alias]

    def _pins(self):
        from engine import labsecrets
        p = labsecrets.path("pins.json")
        if not p.exists():
            raise FileNotFoundError(f"appliance pins missing: {p} (run lab/iso5/prove.sh adapter after each install)")
        return json.loads(p.read_text())

    def pinned_root(self):
        if self.name == "lab":
            return (ROOT / "lab/trust/kanidm-lab-root.sha256").read_text().strip()
        h = self._pins()["CA_ROOT_SHA256"].upper()
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))

    def pinned_ssh_ca(self):
        if self.name == "lab":
            return (ROOT / "lab/trust/ssh-user-ca.sha256").read_text().strip()
        return self._pins()["SSH_CA_FPR"]


PROFILES = {
    "lab": Profile("lab", {"srv1": "srv1", "client2": "client2"}, {"srv1": "srv1", "client2": "client2"},
                   {"srv1": "192.168.100.10", "client2": "192.168.100.13"}, "kanidm.lab.test", False, "lab_users",
                   "/etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt", "/etc/ssh/sshd_config.d/10-kanidm.conf",
                   "/etc/ssh/trusted_user_ca_keys", "/root/.step/certs/root_ca.crt", None, "", "lab/reset.sh"),
    "appliance": Profile("appliance", {"srv1": "iso5-srv", "client2": "iso5-cli2"},
                         {"srv1": "iso5-srv", "client2": "iso5-cli2"},
                         {"srv1": "192.168.100.50", "client2": "192.168.100.52"}, "iso5.lab.test", True, "chp_users",
                         "/etc/pki/ca-trust/source/anchors/chp-root.crt", "/etc/ssh/sshd_config.d/10-chp.conf",
                         "/etc/ssh/chp_user_ca.pub", "/etc/step-ca/certs/root_ca.crt", "lab/iso5/ssh_config", "iso5-",
                         "lab/iso5/reset.sh"),
}


def current():
    n = os.environ.get("IDM_PROFILE") or "lab"
    if n not in PROFILES:
        raise ValueError(f"IDM_PROFILE={n!r} is not a profile ({', '.join(PROFILES)})")
    return PROFILES[n]
```

  `_pins()`'s message contains "pins", so the test's `match="pins"` holds.

- [ ] **Step 4: Wire it in.**
  - `engine/remote.py`: add `ssh_base()`, which returns `["ssh", "-F", str(ROOT / p.ssh_config), "-o", "BatchMode=yes"]`
    when `p.ssh_config` is set, otherwise `["ssh", "-o", "BatchMode=yes"]`.
    - Use it in `run()` and in both ssh calls inside `push()`.
    - Give `rsync` `-e` with the same base, joined by `shlex.join`, without `-o BatchMode` duplication issues.
  - `engine/labsecrets.py`: `path(name)` → `DIR / (profile.current().secrets_prefix + name)`. Import inside the function,
    to avoid a cycle.
  - `engine/repairs.py` `target_role`: `want = profile.current().hostnames.get(host, host)` and compare
    `report.get("host")` with `want`.
  - `engine/cli.py`:
    - The reset line becomes `subprocess.run([str(ROOT / profile.current().reset), "srv1", "client2"], …)`.
    - The regress header line names `profile.current().name` and the mapped hosts.
  - `lab/iso5/ssh_config`:

```
# IDM_PROFILE=appliance: logical names -> the hosts installed from the ISO (lab/iso5). Admin = chpadmin + the LAB ADAPTER
# sudo rule (lab/iso5/LAB-ADAPTER.md); collector = the diag forced-command key (ISSO #22).
Host aero
    HostName 192.168.100.1
    User itadmin
Host srv1 client2 srv1-diag client2-diag
    ProxyJump aero
    IdentitiesOnly yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
Host srv1
    HostName 192.168.100.50
    User chpadmin
    IdentityFile ~/idm-lab-secrets/iso2_chpadmin
Host client2
    HostName 192.168.100.52
    User chpadmin
    IdentityFile ~/idm-lab-secrets/iso2_chpadmin
Host srv1-diag
    HostName 192.168.100.50
    User diag
    IdentityFile ~/idm-lab-secrets/iso5_diag_ecdsa
Host client2-diag
    HostName 192.168.100.52
    User diag
    IdentityFile ~/idm-lab-secrets/iso5_diag_ecdsa
```

  First check that `Host aero` in `~/.ssh/config` uses the same key options; with `-F` the user's config is **not**
  read. Copy any `IdentityFile` line for aero from `~/.ssh/config`.

- [ ] **Step 5:** full suite → all PASS (the existing tests run under the default `lab`).
- [ ] **Step 6: Commit** `ISO Plan 5b Task 2: engine profiles (lab default | appliance): ssh config, hostnames, secrets prefix, reset`.

---

### Task 3: Repairs and findings follow the profile

**Files:** Modify `engine/repairs.py`, `engine/findings.py`. Test: `tests/test_repairs.py` (append).

**Changes (each read at call time):**
- `KanidmCertRenew.apply`: `idm.kanidm.lab.test` → `profile.current().fqdn()`.
- `ClientCaTrust`:
  - `ANCHOR` and `ROOT_PATH` become properties reading the profile.
  - `undo` copies `{backup dir}/{basename(ANCHOR)}`.
  - The pin comparison uses `profile.current().pinned_root()`. A `FileNotFoundError` becomes the precheck reason
    `"pin missing: …"` (Review Focus 4).
  - `describe` uses the same value.
- `SelinuxRestorecon.paths()` (new method) = the lab tuple with `/etc/ssh/trusted_user_ca_keys` replaced by the
  profile's `trusted_ca_keys`. Keep `PATHS` (lab) for the existing tests. Use `self.paths()` wherever `self.PATHS` was
  used.
- `sign_user_cert`: the principal `user@{SSH_REALM}` → `user@{profile.current().fqdn()}`. Keep `SSH_REALM` as the lab
  constant for the existing tests.
- `SshCaTrustRestore`:
  - `DROPIN` and `KEYS` become properties from the profile.
  - The pin uses `profile.current().pinned_ssh_ca()`, with the same "pin missing" handling.
  - `verify_present` uses the profile pin.
- `findings.py` line 138: the TLS evidence text names `profile.current().fqdn()`.
- Keep the module names `PINNED_ROOT` and `PINNED_SSH_CA` (the lab values) for the existing tests.

- [ ] **Step 1: Failing tests** (append to `tests/test_repairs.py`):

```python
def test_appliance_profile_paths(monkeypatch, tmp_path):
    from engine import labsecrets
    monkeypatch.setenv("IDM_PROFILE", "appliance"); monkeypatch.setattr(labsecrets, "DIR", tmp_path)
    assert repairs.ClientCaTrust().ANCHOR == "/etc/pki/ca-trust/source/anchors/chp-root.crt"
    assert repairs.ClientCaTrust().ROOT_PATH == "/etc/step-ca/certs/root_ca.crt"
    r = repairs.SshCaTrustRestore()
    assert r.DROPIN == "/etc/ssh/sshd_config.d/10-chp.conf" and r.KEYS == "/etc/ssh/chp_user_ca.pub"
    assert "/etc/ssh/chp_user_ca.pub" in repairs.SelinuxRestorecon().paths()
    assert "/etc/ssh/trusted_user_ca_keys" not in repairs.SelinuxRestorecon().paths()


def test_appliance_trust_repairs_refuse_without_pins(monkeypatch, tmp_path):     # Review Focus 4
    from engine import labsecrets
    monkeypatch.setenv("IDM_PROFILE", "appliance"); monkeypatch.setattr(labsecrets, "DIR", tmp_path)

    class R:                      # the CA host answers with SOME certificate; without a pin it must not be trusted
        @staticmethod
        def run(host, argv, **kw):
            return type("P", (), {"stdout": FIXROOT})()
    ctx = type("C", (), {"remote": R, "host": "client2"})()
    assert repairs.ClientCaTrust().precheck(ctx).startswith("pin missing")
```

  (`FIXROOT` is the lab root fixture already used in this file at line 302.)
- [ ] **Step 2:** run → FAIL. **Step 3:** implement the changes listed. **Step 4:** full suite → PASS.
- [ ] **Step 5: Commit** `ISO Plan 5b Task 3: repairs follow the profile (fqdn, anchor, sshd drop-in, CA key, pins)`.

---

### Task 4: Scenarios follow the profile; appliance login probe

**Files:**
- Create: `scenarios/_login.py`, `lab/iso5/login.exp`, `tests/test_login_probe.py`
- Modify: `scenarios/{l1,c1,l2,l3,l3n,c2,l5,l6,c3,c4}.py` (l4 needs no change)

**Interfaces (Produces):**
- `_login.probe(user, which, log) -> "OK" | "DENIED" | "ERROR"`. `which` is `posix | primary`.
- `_login.cert_probe(user, log) -> "RESULT: OK <u>" | "RESULT: DENIED"`. It uses the user's **stored** certificate
  (c3 and c4 test that certificate).
- `_login.prepare_user(user, posix=True, log=print)`. In `lab` it does nothing. In `appliance` it does three things:
  - registers the user's key on the CA (the key is in the lab secrets);
  - signs a fresh certificate;
  - enrols GA on client2, then stores `iso5-<user>.ga`.

- [ ] **Step 1: Failing tests** `tests/test_login_probe.py`:

```python
from scenarios import _login


def test_fresh_window_waits_into_the_next_30s_window():              # Review Focus 2
    slept = []
    _login.fresh_window(now=lambda: 1020.0 + 29.5, sleep=slept.append)    # 0.5 s before a boundary (1020 = 34 x 30)
    assert slept and 1.0 <= slept[0] <= 2.0                               # waits past the boundary (+1 s margin)
    slept.clear()
    _login.fresh_window(now=lambda: 1020.0 + 1.0, sleep=slept.append)     # 1 s into a window
    assert 29.0 <= slept[0] <= 31.0


def test_appliance_probe_command(monkeypatch):
    monkeypatch.setenv("IDM_PROFILE", "appliance")
    argv = _login.appliance_argv("lab01")
    assert argv[0] == "/usr/bin/expect" and argv[1].endswith("lab/iso5/login.exp")
    assert argv[2:4] == ["192.168.100.52", "lab01"] and argv[4].endswith("iso5-lab01_ecdsa")
    assert argv[5].endswith("iso5-lab01_ecdsa-cert.pub") and argv[6].endswith("iso5-lab01.ga")


def test_scenarios_carry_no_lab_literals():
    from pathlib import Path
    for f in Path(_login.__file__).parent.glob("[lc][0-9]*.py"):
        t = f.read_text()
        for lit in ("kanidm.lab.test", "192.168.100.1", "kanidm-lab-root.crt", "10-kanidm.conf", "lab_users@"):
            assert lit not in t, (f.name, lit)
```

- [ ] **Step 2:** run → FAIL.

- [ ] **Step 3: `scenarios/_login.py`**

```python
"""Login probes for both profiles. lab: password-only (ssh-login.exp) or certificate-only (ssh-cert-login.sh) logins to
client2, as before. appliance: sshd demands key/certificate AND the GA code AND the password (row 10), so one helper
(lab/iso5/login.exp) does all three. GA refuses a code reused in the same 30-s window (-d): wait for a fresh one."""
import subprocess
import time
from pathlib import Path

from engine import labsecrets, profile, remote

ROOT = Path(__file__).resolve().parents[1]


def fresh_window(now=time.time, sleep=time.sleep):
    sleep(31 - now() % 30)              # 1 s past the next 30-s boundary: a code never used yet


def appliance_argv(user):
    k = labsecrets.path(f"{user}_ecdsa")
    return ["/usr/bin/expect", str(ROOT / "lab/iso5/login.exp"), profile.current().ip("client2"), user, str(k),
            f"{k}-cert.pub", str(labsecrets.path(f"{user}.ga"))]


def _appliance(user, password, log, fresh_cert):
    from engine.repairs import sign_user_cert
    if fresh_cert:          # password probes test the PASSWORD path: give them a valid certificate
        labsecrets.write(f"{user}_ecdsa-cert.pub", sign_user_cert(remote, "srv1", user, "+10m"))
    fresh_window()
    r = subprocess.run(appliance_argv(user), input=f"{password}\n", capture_output=True, text=True)
    return "OK" if "LOGIN_OK" in r.stdout else "DENIED" if "LOGIN_REFUSED" in r.stdout else "ERROR"


def probe(user, which, log):
    if profile.current().name == "appliance":
        d = labsecrets.read_json(f"{user}.json")
        pw = d["password"] if which == "primary" else (d.get("posix_password") or "")
        res = _appliance(user, pw, log, fresh_cert=True)
    else:
        r = subprocess.run(["/usr/bin/expect", str(ROOT / "lab/client/ssh-login.exp"), user, which,
                            profile.current().ip("client2")], stdin=subprocess.DEVNULL, capture_output=True, text=True)
        res = "OK" if "RESULT: uid=" in r.stdout else "DENIED" if "RESULT: DENIED" in r.stdout else "ERROR"
    log(f"login probe {user}@client2 with its {which} password: {res}")
    return res


def cert_probe(user, log):
    if profile.current().name == "appliance":
        d = labsecrets.read_json(f"{user}.json")
        res = _appliance(user, d.get("posix_password") or "", log, fresh_cert=False)
        out = f"RESULT: OK {user}" if res == "OK" else "RESULT: DENIED"
    else:
        out = subprocess.run([str(ROOT / "lab/client/ssh-cert-login.sh"), user], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True).stdout.strip()
    log(f"certificate login probe {user}@client2: {out}")
    return out
```

  Add `prepare_user` too. In the appliance profile it runs these steps, through `engine.remote`, with logical names:
  1. Create `~/idm-lab-secrets/iso5-<u>_ecdsa` with `ssh-keygen -t ecdsa -b 384 -N ''` if it is missing.
  2. On `srv1`: `sudo install -m 0644 /dev/stdin /var/lib/ssh-ca/keys/<u>.pub`, with the public key on stdin.
  3. Write the certificate from `sign_user_cert(remote, "srv1", u, "+1h")`.
  4. On `client2`: `sudo kanidm-unix cache-invalidate`, then `sudo chp-site ga-enrol <u> --reset --no-confirm`, with its
     output discarded.
  5. Store the GA secret: `sudo head -1 /var/lib/google-authenticator/<u>` → `labsecrets.write(f"{u}.ga", …)`. The value
     is never logged.

- [ ] **Step 4: `lab/iso5/login.exp`**: copy `lab/iso4/ssh-ki.exp` and change only:
  - it runs on the Mac: `spawn ssh -J aero …`;
  - the `code` proc runs `python3 <repo>/lab/tools/totp.py - sha1 < $sf`, with the path taken from `[file dirname [info script]]/../tools/totp.py`;
  - argv: `IP USER KEY CERT GA_FILE`, MODE fixed to `id`;
  - the password comes from stdin line 1.

  The output (`LOGIN_OK <user>` / `LOGIN_REFUSED`) stays the same. Keep its header comment style.
- [ ] **Step 5: Port the scenarios.** All of these use `profile.current()` at call time, not at import:

  | Scenario | Change |
  |---|---|
  | l1 | probe → `_login.probe`; group → `p.login_group`; after the enrolment: `_login.prepare_user(USER, posix=False)` |
  | l5 | probe → `_login.probe` |
  | l6 | probe → `_login.probe` |
  | c1 | `idm.kanidm.lab.test` → `p.fqdn()` |
  | l2 | `GROUP` → `p.group(p.login_group)`, used inside the functions |
  | l3 | `SPN` → `p.group("lab_admins")`; IP → `p.ip("srv1")` |
  | l3n | IP → `p.ip("srv1")` |
  | c2 | `ANCHOR` → `p.anchor` |
  | c3 | `cert_probe` → `_login.cert_probe` |
  | c4 | `DROPIN` → `p.sshd_dropin`; `cert_probe` → `_login.cert_probe` |

  Edit the `SYMPTOM` strings only where they hold a literal domain or IP.
- [ ] **Step 6:** full suite → PASS (the lab-profile behaviour is unchanged; the literal-free test passes). The d1, d2,
  f1, f2, p1–p3 and r1 scenarios are not part of gate 2 and keep their lab literals (out of scope; listed in the PR).
- [ ] **Step 7: Commit** `ISO Plan 5b Task 4: scenarios follow the profile; appliance login probe (key/cert + GA + password)`.

---

### Task 5: Signed repo 0.6.2, ISO rc4, install from nothing again (gates 1 and 3 on the final ISO)

- [ ] **Step 1:** Build `chp-identity-client` 0.2.2 and `idm-collect` 0.1.0-10 (each package's `build-rpm.sh`).
  Assemble `/data/chp-release/0.6.2/stage`.
- [ ] **Step 2: Signing (the user).** Tell the user: "PIN dialog (click inside it first; type the PIN there, not in the
  chat), about 15 touches". Then run `sign-session.sh … sign-repo.sh … 0.6.2`, as in Plan 5a Task 5 Step 2. Publish the
  lab copy.
- [ ] **Step 3:**
  - Point `lab/iso5/prove.sh` at `CHP_REPO=0.6.2`, `0.1.0-rc4`.
  - Add a stage `baseline` (after `client2`): collect from all three hosts through the diag key and evaluate. Expected:
    **zero findings on every host** (proves P1). Use the engine:
    `IDM_PROFILE=appliance .venv/bin/python -m engine findings srv1` and `… client2`. For cli1, use the direct diag ssh
    command with `iso5_diag_ecdsa`.
  - Add `GRUB_PASSWORD` to the run-log secrets regex.
- [ ] **Step 4:** Build rc4 (`push.sh`, `build-iso.sh 0.6.2 0.1.0-rc4`, `check-iso.sh` → `ISO OK`). Delete rc3 after
  rc4 passes.
- [ ] **Step 5:** Fresh proof **run 3**, detached:
  - The stages: `cleanup prep negrepo server firstboot reboot export client1 client2 baseline ga negtrust scan`
    (`nohup` + the `until` watcher from Plan 5a).
  - Expected: every stage `ALL PASS`; `baseline` 0 findings; `scan` 102 pass / 0 fail on all three hosts.
  - Update `PROOF-RECORD.md` (run 3 = the record of proof for rc4), `DEVIATIONS.md` (rc4) and
    `RELEASE-RECORD-0.6.2.md`.
- [ ] **Step 6: Commit** `ISO Plan 5b Task 5: repo 0.6.2 + ISO rc4 installed from nothing (run 3), baseline 0 findings, scan clean`.

---

### Task 6: Lab adapter, fixtures, golden snapshots, reset

**Files:** Create `lab/iso5/LAB-ADAPTER.md`, `lab/iso5/reset.sh`, `lab/iso5/fixtures.py`. Modify `lab/iso5/prove.sh`
(stages `adapter`, `golden`).

- [ ] **Step 1: Stage `adapter`** in `prove.sh`. It runs only after `scan` (the stage checks that `scan-results/` for rc4
  exist):
  - On `iso5-srv` and `iso5-cli2`, via `Rh` (root console):
    `printf 'chpadmin ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/99-lab-adapter && chmod 0440 … && visudo -cf …`.
  - Write the pins file: `client.conf` from the stick → `CA_ROOT_SHA256`, `SSH_CA_FPR` →
    `~/idm-lab-secrets/iso5-pins.json` (0600). Use `stick.sh escrow $STICK ../client.conf` piped into python on the Mac.
  - Write `idm_admin`: the stick's `iso5-srv-server.txt` → `KANIDM_ADMINS_JSON` → `["idm_admin"]` →
    `~/idm-lab-secrets/iso5-idm_admin.json` `{"password": …}` (0600). Pipes only, nothing printed.
  - Checks:
    - `ssh -F lab/iso5/ssh_config srv1 sudo -n true` → rc 0;
    - the same for `client2`;
    - `IDM_PROFILE=appliance … engine findings client2` → `[]`.
- [ ] **Step 2: `lab/iso5/fixtures.py`** (`IDM_PROFILE=appliance`): it creates the scenario users and groups with the
  engine's own helpers.
  - `admin_login`.
  - Kanidm person create, `posix set`, add to `chp_users`, for each of:

    | User | Used by |
    |---|---|
    | lab01 | l2, c2, l6 |
    | lab02 | c3, c4 |
    | lab03 | l3 |
    | lab04 | l3n |
    | lab06 | l5 |

  - The reset token, then `enrol-user.exp` (mode `totp`: password + TOTP + POSIX password). Store
    `iso5-<u>.json`, as the lab does.
  - Create the group `lab_admins` (posix).
  - `_login.prepare_user(u)` for lab01, lab02 and lab06.
  - Then a check:
    - `_login.probe("lab01", "posix", print) == "OK"`;
    - `_login.cert_probe("lab02", print)` starts with `RESULT: OK`.
- [ ] **Step 3: Snapshots spike (Global facts: unproven with a vTPM).**
  - Run `nvram-qcow2.sh iso5-srv` and `… iso5-cli2`. They shut each VM down; the TPM unlocks the disk at the next boot.
  - Then `virsh snapshot-create-as iso5-cli2 spike --atomic`, `snapshot-revert … --running`, `snapshot-delete`.
  - Check that the VM answers and that unixd is online.
  - **If libvirt refuses a snapshot because of the TPM, stop and ask the user.** The options:
    - external snapshots;
    - a TPM-less test pair, which conflicts with row 15;
    - a reinstall per run.
- [ ] **Step 4: `lab/iso5/reset.sh`** (Mac). Every step under `set -Eeuo pipefail`, so any failure stops it
  (Review Focus 5):
  1. `virsh snapshot-revert iso5-srv golden --running`, then the same for `iso5-cli2`.
  2. Wait for ssh on both (`-F lab/iso5/ssh_config`).
  3. On both: `sudo systemctl restart chronyd; chronyc waitsync 30 0.5` (row 18). It fails if not synced.
  4. On srv1: `sudo /usr/libexec/chp/cert-renew-kanidm --issue`.
  5. On client2: loop up to 60 s on
     `curl -fsS --max-time 5 "$(sed -n 's/^uri = "\(.*\)"/\1/p' /etc/kanidm/config)/status"`. This must succeed
     (a fresh, trusted certificate is served).
  6. `sudo kanidm-unix cache-invalidate`. Then wait 31 s, so GA's reuse window and the restored rate limit pass
     (row 19).
- [ ] **Step 5: Stage `golden`:**
  - `virsh snapshot-create-as iso5-srv golden --atomic` (the same for `iso5-cli2`, after deleting any old `golden`).
  - Then run `lab/iso5/reset.sh` once → expected exit 0.
  - Then `IDM_PROFILE=appliance … engine findings srv1` and `client2` → `[]` on both.
- [ ] **Step 6:** `LAB-ADAPTER.md`: what was added, where, when (after the rc4 scan), why, and that nothing of it is in
  the ISO or an RPM. Commit
  `ISO Plan 5b Task 6: lab adapter (after the scan), fixtures, golden snapshots, appliance reset`.

---

### Task 7: Shakedown, then the gate-2 regression

- [ ] **Step 1: Shakedown, one run of each scenario.** For each id in `l1 c1 l2 l3 l3n l4 c2 l5 l6 c3 c4`, run
  `IDM_PROFILE=appliance IDM_TEST_APPROVE=1 .venv/bin/python -m engine scenario <id>`. Expected: `GREEN`.
  - A non-GREEN run is debugged with superpowers:systematic-debugging. The fix depends on the cause:
    - **harness/profile cause:** fix it with a test in `tests/`;
    - **appliance product cause:** stop and present it in the decision form. It needs a new RPM → repo → rc5 →
      Task 5 again.
  - Record each cause and fix in the ledger.
- [ ] **Step 2: Gate 2.** Run detached with `nohup`:
  `IDM_PROFILE=appliance IDM_TEST_APPROVE=1 .venv/bin/python -m engine regress --runs 3 --out lab/iso5/regression-<date>.md`.
  Expected: `**Overall: 11 of 11 scenarios green in every run.**` (33/33).
- [ ] **Step 3: Row 36 ×3.** Stage `row36` in `prove.sh`. Three times, each in a fresh GA window:
  `ssh -F lab/iso5/ssh_config client2 'sudo chp-site pam-test gdm-password lab01'`, with stdin = the posix password, then
  the current GA code (computed on the Mac from `iso5-lab01.ga`). Expected exit 0 ×3, then the token's label check (row 36,
  as in Plan 4b).
- [ ] **Step 4: Records.**
  - In `PROOF-RECORD.md`, add a gate-2 section: the regression report, row 36 ×3, model and commit.
  - In `lab/iso-requirements.md`, add a Plan 5b paragraph.
  - Commit `ISO Plan 5b Task 7: gate 2 met on the appliance: 33/33 + row 36 ×3`.

---

### Task 8: Release to For Jeff (spec §8 step 5)

**Files:** Create `appliance/release/release-iso.sh`, `appliance/release/VERIFY.md.in`,
`appliance/release/RELEASE-RECORD-ISO-0.1.0.md`. Test: `tests/test_release_iso_static.py`.

- [ ] **Step 1: Failing static test**: `release-iso.sh` must:
  - refuse an existing target dir;
  - copy the rc4 ISO bytes, checking the sha256 equals rc4's `SHA256SUMS`;
  - write `SHA256SUMS` naming `cyberhygiene-lab-installer-el9.iso`;
  - make `SHA256SUMS.asc` with `gpg --armor --detach-sign --local-user <pinned fpr>` (the YubiKey on the Mac);
  - copy `RPM-GPG-KEY-cyberhygiene`, `NOTICE.txt`, `VERIFY.md` and `chp-repo-0.6.2.tar.gz` (signed repo tarball);
  - never touch the share's `idm-lab-secrets` folder;
  - end by running `gpg --verify` on the signature.
- [ ] **Step 2: Implement `release-iso.sh` (Mac).**
  - Target: `/Volumes/For Jeff/cyberhygiene-lab-installer/0.1.0/`.
  - Stream the ISO: `ssh aero cat …iso > target` (15 GB; the Mac's disk is not used).
  - Compare sha256 on both ends.
  - `VERIFY.md`: how to check `SHA256SUMS.asc` with the public key and the pinned fingerprint
    `2DE0D71BF37D8F5E4201A590521276F43C908F8E`, how to check the ISO's sha256, and how to write it to a USB stick.
    The site stick is a **secret** and is never kept on a share.
- [ ] **Step 3 (the user, YubiKey):** run the release. Expected: `gpg: Good signature`, and sha256 equal to rc4's.
- [ ] **Step 4:** `RELEASE-RECORD-ISO-0.1.0.md`:
  - 0.1.0 == rc4 bytes (sha256);
  - the repo 0.6.2 record, the gates and where their evidence is;
  - the known limits: VMs only, a real USB stick unproven, and the first start uses the stick's LUKS passphrase
    (ISSO-accepted).
- [ ] **Step 5: Commit** `ISO Plan 5b Task 8: ISO 0.1.0 (= rc4) released to For Jeff with signed checksums`.

---

### Task 9: Finish

- [ ] Final whole-branch review (fresh reviewer, most capable model). Its focus: this plan's Review Focus; that the
  `lab` profile is unchanged; secrets.
- [ ] Fix Important findings with RED→GREEN tests, and defer the minors to the PR body.
- [ ] Push `iso-plan5b` and open a PR to `main` (attribution as in earlier PRs). The merge is the user's.
- [ ] Leave the iso5 VMs at golden. Update `lab/iso-requirements.md`, and the memory note.
