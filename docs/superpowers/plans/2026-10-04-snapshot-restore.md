# Snapshot / Image Restore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect a restored host's hidden clock error (chrony says synchronized, its source is flagged `~`), make
`time-resync` actually fix it (restart chronyd first, row 18) and prove it, and give operators an after-restore procedure.

**Architecture:** The collector records chrony's source state character. `_skewed` also fires on `~` with a large
source offset. `time-resync` restarts chronyd before stepping and verifies against the source, not the stale tracking
offset. Scenario R1 reproduces the restore; a procedure page documents the rest.

**Tech Stack:** POSIX sh, Python 3 / pytest, libvirt lab, signed RPM.

**Spec:** `docs/superpowers/specs/2026-10-04-snapshot-restore-design.md`

## Global Constraints

- Requirement row 18 (restart chronyd first after a restore) and ISSO #30 (a person may approve one clock step).
- `SKEW_S = 30`. Reports without `time.source_state` behave exactly as before.
- `remote.run` raises on a non-zero exit unless `check=False`.
- Python `~/idm-assistant/.venv/bin/python`; tests `~/idm-assistant/.venv/bin/python -m pytest -q tests`. Commits end with the Co-Authored-By line.

## Review Focus

1. `chronyc -n sources` with no `^` line (chronyd down, no sources): `source_state` null, no crash.
2. A legitimate step just done (`*`, stale large sample): no TOTP_TIME_SKEW (the 2026-09-28 behaviour).
3. Source `?` (unreachable) with a large old sample: not treated as the restore case (only `~`).
4. `chronyc waitsync` timing out inside apply: the verify decides, apply does not crash.
5. R1 run right after a fresh golden: the injection waits until the skew is visible instead of failing.

---

### Task 1: Collector `source_state`

**Files:** Modify `collector/idm-collect` (`source-offset` block; the `"time":{...}` printf). Test `tests/test_collector_script.py`.

- [ ] **Step 1: Failing tests** (append)

```python
def _source_state(line):
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> source-offset"), lines.index("# <<< source-offset")
    body = f"printf '%s\\n' 'MS Name/IP address Stratum Poll Reach LastRx Last sample' '{line}'" if line else "true"
    sh = f"chronyc() {{ {body}; }}\n" + "\n".join(lines[i + 1:j]) + '\necho "[$sst]"'
    return subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()


@pytest.mark.parametrize("line,want", [
    ("^~ 192.168.100.1                10   6    37    15  -50085s[-50085s] +/-  317us", "[~]"),
    ("^* 192.168.100.1                10   6   377    12    -52us[  -58us] +/-  242us", "[*]"),
    ("^? 192.168.100.1                 0   6     0     -     +0ns[   +0ns] +/-    0ns", "[?]"),
    ("", "[]"),
])
def test_source_state_character(line, want):
    assert _source_state(line) == want


def test_report_emits_source_state():
    assert '"source_offset_s":%s,"source_state":%s}' in SCRIPT.read_text()
```

- [ ] **Step 2: Run** `-k source_state` → FAIL (`$sst` empty for all).
- [ ] **Step 3: Implement.** Inside the `source-offset` block, after the `soff=…` command:

```sh
# The first source's state (chronyc -n sources, the character after '^'): '*' in use, '~' too variable (what a
# restored snapshot shows: chrony keeps saying synchronized while its source is hours away), '?' unusable.
sst=$(chronyc -n sources 2>/dev/null | awk '/^\^/ { print substr($0, 2, 1); exit }') || sst=""
case "$sst" in '*'|'+'|'-'|'~'|'?'|'x') ;; *) sst="" ;; esac
```

Change the time printf to end `"source_offset_s":%s,"source_state":%s},'` with the extra argument
`"$( [ -n "$sst" ] && json_str "$sst" || printf null)"`.

- [ ] **Step 4: Run** collector tests + `shellcheck -s sh collector/idm-collect` → PASS/clean.
- [ ] **Step 5: Commit** `Restore Task 1: collector records chrony's source state`.

---

### Task 2: The skew rule sees the restore case

**Files:** Modify `engine/findings.py` (`_skewed`, `time_skew`). Test `tests/test_restore.py` (new).

- [ ] **Step 1: Failing tests**

```python
import copy

from engine.findings import evaluate

BASE = {"schema": "idm-report/1", "host": "client2", "role": "client", "collected_at": "2026-10-04T13:20:00Z",
        "errors": [], "time": {"offset_s": 1e-8, "synced": True, "source": "192.168.100.1",
                                "source_offset_s": -50085.0, "source_state": "~"}}


def ids(**time):
    r = copy.deepcopy(BASE); r["time"].update(time)
    return {f.id: f for f in evaluate(r)}


def test_restored_clock_is_skew_even_while_synced():
    f = ids()["TOTP_TIME_SKEW"]
    assert ("chrony rejects its time source as too variable (-50085.0 s off): typical after restoring a snapshot or "
            "image (requirement row 18)") in f.evidence


def test_stale_sample_after_a_real_step_is_not_skew():
    assert "TOTP_TIME_SKEW" not in ids(source_state="*")


def test_unusable_source_is_not_the_restore_case():
    assert "TOTP_TIME_SKEW" not in ids(source_state="?")


def test_small_offset_with_tilde_is_not_skew():
    assert "TOTP_TIME_SKEW" not in ids(source_offset_s=-2.0)


def test_old_reports_without_the_field_behave_as_before():
    r = copy.deepcopy(BASE); del r["time"]["source_state"]
    assert "TOTP_TIME_SKEW" not in {f.id for f in evaluate(r)}
```

- [ ] **Step 2: Run** → FAIL (no TOTP_TIME_SKEW for the restored report).
- [ ] **Step 3: Implement.**

```python
def _restored(r):
    """Requirement row 18: after a restore chrony keeps 'synchronized' from the snapshot while it rejects its source as
    too variable ('~', hours away; spike 2026-10-04). A stale sample after a real step shows '*', not '~'."""
    t = r.get("time") or {}
    src = t.get("source_offset_s")
    return t.get("source_state") == "~" and src is not None and abs(src) > SKEW_S
```

`_skewed` returns True early when `_restored(r)`. In `time_skew`, build the evidence tuple and append
`f"chrony rejects its time source as too variable ({t.get('source_offset_s')} s off): typical after restoring a snapshot or image (requirement row 18)"`
when `_restored(r)`.

- [ ] **Step 4: Run** all tests → PASS (L4/skew fixtures unchanged).
- [ ] **Step 5: Commit** `Restore Task 2: TOTP_TIME_SKEW sees a restored clock behind a stale 'synchronized'`.

---

### Task 3: `time-resync` restarts chronyd and proves the clock; runbook wording

**Files:** Modify `engine/repairs.py` (`TimeResync`), `runbooks/TOTP_TIME_SKEW.md`. Test `tests/test_restore.py`.

- [ ] **Step 1: Failing tests** (append)

```python
from types import SimpleNamespace

from engine import runbooks
from engine.case import Case
from engine.repairs import REGISTRY, Ctx

R = REGISTRY["time-resync"]


def test_apply_restarts_chronyd_before_stepping(tmp_path):
    calls = []
    remote = SimpleNamespace(run=lambda host, argv, **kw: calls.append(argv[-1]) or SimpleNamespace(stdout=""))
    R.apply(Ctx(host="client2", role="client", case=Case(tmp_path, "r", "s"), collect=lambda: BASE, remote=remote))
    s = calls[-1]
    assert s.index("systemctl restart chronyd") < s.index("chronyc makestep")


def test_verify_refuses_a_stale_synchronized():
    t = dict(BASE["time"]); assert R.verify_present({"time": t})                               # '~', far off
    assert R.verify_present({"time": dict(t, source_state="*", source_offset_s=0.2, offset_s=0.0)}) is None
    assert R.verify_present({"time": dict(t, source_state="*", source_offset_s=40.0, offset_s=0.0)})


def test_verify_unchanged_for_reports_without_the_field():
    assert R.verify_present({"time": {"offset_s": 0.1, "synced": True}}) is None


def test_runbook_wording_restarts_the_time_service():
    assert runbooks.load("TOTP_TIME_SKEW").repair.startswith("Restart the time service and set this workstation's clock")
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** in `TimeResync`:

```python
    def describe(self, ctx):
        return ("restart the time service and step the clock to the time source (chronyc makestep). Not reversible, "
                "and not meant to be: the old time was wrong")

    def apply(self, ctx):
        # Row 18: restarting chronyd clears the restored sample history (the CUI 'makestep 1.0 3' then steps on the
        # first updates); makestep alone does nothing while the source is rejected as too variable (spike 2026-10-04).
        _sh(ctx, "systemctl restart chronyd; chronyc waitsync 30 0.5 >/dev/null 2>&1; chronyc makestep >/dev/null; "
                 "chronyc burst 4/4 >/dev/null; chronyc waitsync 6 1.0 >/dev/null 2>&1 || true")

    def verify_present(self, report):
        t = report.get("time") or {}
        if not t.get("synced") or t.get("offset_s") is None or abs(t["offset_s"]) >= 1:
            return f"clock not synced within 1 s: {t}"
        if "source_state" in t:          # a stale 'synchronized' is what made the old check pass after a restore
            src = t.get("source_offset_s")
            if t.get("source_state") != "*" or src is None or abs(src) >= 1:
                return f"time source not in use or still off: state {t.get('source_state')!r}, sample {src} s"
        return None
```

`runbooks/TOTP_TIME_SKEW.md`: `repair: Restart the time service and set this workstation's clock to the time source now, once, with your approval.`
and append to the model text: `After a snapshot or image restore chrony can keep saying "synchronized" while it rejects its source as too variable (~); restarting chronyd is required first (requirement row 18), which this repair does.`

- [ ] **Step 4: Run** all tests → PASS.
- [ ] **Step 5: Commit** `Restore Task 3: time-resync restarts chronyd first and verifies against the source`.

---

### Task 4: Scenario R1, procedure

**Files:** Create `scenarios/r1.py`, `runbooks/procedures/after-restore.md`; modify `runbooks/README.md`. Test `tests/test_restore.py`.

- [ ] **Step 1: Failing test** (append)

```python
def test_r1_and_procedure():
    import importlib
    from pathlib import Path
    r1 = importlib.import_module("scenarios.r1")
    assert r1.EXPECT == {"client2": {"TOTP_TIME_SKEW"}} and r1.REPAIRS == [("client2", "time-resync")]
    assert r1.HOSTS == ["client2"] and r1.USER == "lab04"
    root = Path(__file__).resolve().parents[1]
    text = (root / "runbooks" / "procedures" / "after-restore.md").read_text()
    for must in ("Restart chronyd before anything else", "requirement row 18", "TLS_CERT_EXPIRED", "row 19",
                 "ACCOUNT_LOCKED", "on the server too"):
        assert must in text, must
    assert "procedures/after-restore.md" in (root / "runbooks" / "README.md").read_text()
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**

`scenarios/r1.py`:

```python
"""R1: client2 is restored from its snapshot (golden) with none of reset.sh's fix-ups. Its clock is as old as the
snapshot, but chrony keeps saying 'synchronized' while it rejects its source as too variable (~): requirement row 18.
TOTP_TIME_SKEW must be found, and time-resync (restart chronyd first) must fix and prove it."""
import subprocess
import time

from engine import remote
from engine.findings import evaluate
from scenarios import f1

ID = "r1"
USER = "lab04"
SYMPTOM = "client2 was restored from a backup image; authenticator codes are rejected there."
EXPECT = {"client2": {"TOTP_TIME_SKEW"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "time-resync")]


def inject(log):
    subprocess.run(["ssh", "-n", "aero", "sudo virsh snapshot-revert client2 golden --running"], check=True,
                   capture_output=True, text=True, timeout=300)
    for _ in range(60):
        if subprocess.run(["ssh", "-n", "-o", "ConnectTimeout=3", "-o", "BatchMode=yes", "client2", "true"]).returncode == 0:
            break
        time.sleep(3)
    log("injected: client2 reverted to golden without a chronyd restart (row 18)")
    for _ in range(30):             # the error is the time since golden was taken: wait until it is past the window
        if "TOTP_TIME_SKEW" in {f.id for f in evaluate(remote.collect("client2-diag", USER))}:
            log("restored clock visible to the collector")
            return
        time.sleep(10)
    raise RuntimeError("restored clock not visible within ~5 min")


def final_probe(log):
    t = remote.collect("client2-diag", USER).get("time") or {}
    src = t.get("source_offset_s")
    ok_clock = t.get("source_state") == "*" and src is not None and abs(src) < 1   # 0.0 is a perfect clock, not missing
    login = f1.login("posix")
    log(f"probe: source {t.get('source_state')!r} {t.get('source_offset_s')} s; login {login}")
    return ok_clock and login == "OK"
```

`runbooks/procedures/after-restore.md`:

```markdown
# After restoring from a snapshot or image

A restored machine starts with the clock, the memory and the certificates it had when the image was taken. In a lab
test on 2026-10-04 a restored workstation and server were **14 hours behind**, while the time service still said
"synchronized" and no check noticed. Do these steps in order.

1. **Restart chronyd before anything else** (requirement row 18), on the server too. On a workstation the decision
   form's clock repair does it for you (TOTP_TIME_SKEW, "Restart the time service…"); on the server, run
   `systemctl restart chronyd` by hand. Then run a check: there must be no clock finding.
2. **Check the certificate.** An image older than about a day can carry an expired identity-server certificate
   (TLS_CERT_EXPIRED); its decision form offers a new one from the project's certificate authority.
3. **On machines with the authenticator, wait about a minute and do not retry failed logins** (requirement row 19).
   Codes from a wrong clock fail, and every failed try counts toward the lockout (ACCOUNT_LOCKED).
4. **Expect what a restore brings back.** People, groups and access changes made after the image was taken exist only
   on the identity server; a restored workstation catches up once it reaches the server.
```

`runbooks/README.md`, under "Procedures", add:
`- [After restoring from a snapshot or image](procedures/after-restore.md): restart chronyd first (row 18), then the certificate, then logins.`

- [ ] **Step 4: Run** all tests → PASS.
- [ ] **Step 5: Commit** `Restore Task 4: scenario R1 and the after-restore procedure`.

---

### Task 5: Release, lab, golden, regression (the user's signing round)

- [ ] **Step 1:** `Release: 8.chp%{?dist}`; changelog "chrony source state; uptime_s". Build.
- [ ] **Step 2:** assemble `/data/chp-release/0.5.7/stage` (third-party dir `/data/chp-release/0.4.1/stage`) → 11 packages, idm-collect 0.1.0-8.
- [ ] **Step 3: Signing round** (announce; wait for "ready"; PIN cue) → `REPO OK`.
- [ ] **Step 4:** publish `/data/lab-inputs/chp/0.5.7`; `RELEASE-RECORD-0.5.7.md`; `diag-access.sh` → `0.1.0-8`, `0.5.7/repo`.
- [ ] **Step 5:** reset, install, readonly-proof; report `time.source_state == "*"`, `uptime_s` an integer; fixtures `healthy-{srv1,client2}-restore.json` (+ test: both `[]`).
- [ ] **Step 6:** re-take golden.
- [ ] **Step 7:** regress `r1 l4 --runs 3`; full `--runs 1`; `d1 d2 f1 f2 p1 p2 p3 --runs 1` → all GREEN.
- [ ] **Step 8:** commit spec bump, records, diag-access, fixtures, reports.

### Task 6: Pull request

- [ ] Final whole-branch review; fix pass; scan; push; PR.
