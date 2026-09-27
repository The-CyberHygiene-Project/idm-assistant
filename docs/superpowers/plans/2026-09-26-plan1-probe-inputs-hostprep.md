# Plan 1: Model Probe, Offline Inputs, and aero Host Preparation (M0 + M1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce (a) a repeatable local-model tool-calling probe with its first results, (b) a verified offline input set for the dc2-stack lab, and (c) aero prepared as an offline, FIPS KVM host that the Mac drives over SSH.

**Architecture:** The probe is a small Python package (`probe/`) that talks to LM Studio's OpenAI-compatible API through an injectable transport, so every scoring and reporting path is unit-tested without a model. Offline inputs are fetched and verified on the Mac by `lab/inputs/fetch.sh` and re-verified by an independent `verify.sh`. Host preparation is six idempotent bash scripts (`lab/host/b1..b6`) that share `lab/host/lib.sh`. Each supports `--check` (a dry run that changes nothing). They are copied to aero with `scp` and run with passwordless `sudo`.

**Tech Stack:** Python 3.14 (uv, pytest, requests, jsonschema) on the Mac; bash + shellcheck; Rocky 9.8 (dnf, libvirt/KVM, NetworkManager, chrony, firewalld, OpenSCAP) on aero.

**Spec:** `docs/superpowers/specs/2026-09-26-idm-diagnostic-lab-design.md` (rev 2, approved 2026-09-26)

## Global Constraints

- aero is a disposable lab asset. **Keep FIPS, SELinux enforcing, and the CUI profile.** Record every convenience change in `lab/aero-deviations.md`.
- aero has **no network except the lab cable** (Wi-Fi radio disabled). Nothing in this plan may re-enable Wi-Fi or add a default route on aero.
- All external inputs are fetched **on the Mac only** and verified (SHA-256, plus GPG where upstream signs) before they reach aero.
- Pinned versions: **Rocky Linux 9.8** DVD (`Rocky-9.8-x86_64-dvd.iso`, 15,194,259,456 bytes); **Kanidm v1.11.2** (MSRV Rust 1.96); **Rust 1.96.0** standalone installer; **step-ca 0.30.2**, **step-cli 0.31.0** (x86_64 RPMs).
- Pinned GPG fingerprints: Rocky 9 release key `21CB256AE16FC54C6E652949702D426D350D275D` (confirmed identical to `/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9` on aero); Rust signing key `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`.
- Inputs live **outside the repo** at `~/idm-lab-inputs/` on the Mac and `/data/lab-inputs/` on aero.
- The probe runs **only after the user confirms LM Studio is free**. It records and restores the models that were loaded before it started.
- Models: US/EU origin only (Gemma, Devstral, Llama). No web tools.
- Lab network: aero `192.168.100.1/24` (bridge `br-lab` after b4), Mac `192.168.100.2`, no gateway anywhere.

## Review Focus

1. **b4-net drops the SSH link and the rollback never fires**, leaving aero unreachable. The rollback path is exercised on purpose first (`b4-net --rollback-test`, Task 12 Step 3) before the real apply.
2. **An interrupted or partial ISO download** must be caught, not carried to aero. Covered by `verify.sh` failing on a size or hash mismatch, tested with a truncated copy in Task 8 Step 4.
3. **A model writes its tool call as JSON text in the message instead of a structured `tool_calls` entry.** That must score as `prose_json`, never as `valid`. Covered by `test_json_in_content_is_not_a_structured_call` in Task 3.
4. **LM Studio auto-loads another model mid-probe**, which skews memory and results. The runner snapshots loaded models before each size point and aborts the point if the set changed. Covered by `test_runner_aborts_when_loaded_models_change` in Task 5.
5. **A dnf command on aero reaching for the (unreachable) online repos** and hanging or failing slowly. b1 disables the online Rocky repos and every later script uses only `lab-*` repos. Covered by the b1 verify step `dnf repolist` showing only lab repos (Task 9 Step 4).

---

## File Structure

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Python project (probe) with deps and pytest config |
| `probe/tools.py` | the five probe tool schemas + argument validation |
| `probe/padding.py` | deterministic filler context of a target token size |
| `probe/score.py` | classifies one API response |
| `probe/client.py` | LM Studio chat-completions call through an injectable transport |
| `probe/runner.py` | loops models × sizes × runs; guards the loaded-model set |
| `probe/report.py` | results → markdown table |
| `probe/__main__.py` | CLI (`uv run python -m probe ...`) |
| `probe/lms.py` | thin wrapper over the `lms` CLI (ps/load/unload) |
| `tests/test_probe_*.py` | unit tests |
| `lab/inputs/fetch.sh` | download + verify all offline inputs into `~/idm-lab-inputs` |
| `lab/inputs/verify.sh` | independent re-verification from `MANIFEST.txt` |
| `lab/inputs/MANIFEST.txt` | generated: file, version, size, sha256, source, verification |
| `lab/host/lib.sh` | shared helpers: logging, `--check`, run/idempotence, root check |
| `lab/host/b1-media.sh` … `b6-scap-report.sh` | host preparation steps |
| `lab/host/push.sh` | copies `lab/host/*` to aero and runs one step |
| `lab/aero-deviations.md` | every change that departs from the standard build |

---

### Task 1: Repo skeleton and Python environment

**Files:**
- Create: `pyproject.toml`, `probe/__init__.py`, `tests/__init__.py`, `lab/aero-deviations.md`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `uv run pytest` works from the repo root; the `probe` package is importable.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "idm-assistant"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["requests>=2.31", "jsonschema>=4.21"]

[dependency-groups]
dev = ["pytest>=8"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create the package markers and the deviations log**

`probe/__init__.py`:
```python
"""Local-model tool-calling probe (spec Part A)."""
```

`tests/__init__.py`: empty file.

`lab/aero-deviations.md`:
```markdown
# aero: deviations from the standard workstation build

aero is a disposable, offline lab asset (no CUI, lab cable only). Fidelity settings
(FIPS, SELinux enforcing, CUI profile) are kept. Every convenience change is listed here.

| Date | Change | Why | How to revert |
|---|---|---|---|
| 2026-09-26 | Wi-Fi radio disabled (`nmcli radio wifi off`) | lab must be offline | `nmcli radio wifi on` |
| 2026-09-26 | `/etc/sudoers.d/90-itadmin-lab`: `itadmin ALL=(ALL) NOPASSWD: ALL` | Mac drives setup over SSH; approved by the ISSO | `rm /etc/sudoers.d/90-itadmin-lab` |
```

Append to `.gitignore`:
```
.venv/
.pytest_cache/
```

- [ ] **Step 3: Create the environment and confirm pytest runs**

Run: `cd ~/idm-assistant && uv sync && uv run pytest -q`
Expected: `no tests ran` (exit code 5 is fine at this point)

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock probe/__init__.py tests/__init__.py lab/aero-deviations.md .gitignore
git commit -m "Repo skeleton: probe package, pytest, aero deviations log"
```

---

### Task 2: Probe tool schemas and argument validation

**Files:**
- Create: `probe/tools.py`
- Test: `tests/test_probe_tools.py`

**Interfaces:**
- Produces: `TOOLS: list[dict]` (OpenAI tool format); `TOOL_NAMES: set[str]`; `validate_call(name: str, arguments: str) -> tuple[bool, str]` returning `(ok, reason)`.

- [ ] **Step 1: Write the failing test**

```python
from probe.tools import TOOLS, TOOL_NAMES, validate_call


def test_five_tools_in_openai_format():
    assert len(TOOLS) == 5
    assert all(t["type"] == "function" and "parameters" in t["function"] for t in TOOLS)
    assert TOOL_NAMES == {t["function"]["name"] for t in TOOLS}


def test_each_tool_validates_against_its_own_schema():
    assert validate_call("get_service_status", '{"unit": "kanidm-unixd"}') == (True, "ok")
    assert validate_call("read_log", '{"unit": "sshd", "lines": 50}') == (True, "ok")
    assert validate_call("check_certificate", '{"host": "idm.kanidm.lab.test", "port": 443}') == (True, "ok")
    assert validate_call("check_time_sync", "{}") == (True, "ok")
    assert validate_call("list_failed_logins", '{"user": "alice"}') == (True, "ok")


def test_unknown_tool_is_rejected():
    ok, reason = validate_call("run_shell", '{"cmd": "id"}')
    assert not ok and "unknown tool" in reason


def test_missing_required_argument_is_rejected():
    ok, reason = validate_call("read_log", '{"unit": "sshd"}')
    assert not ok and "lines" in reason


def test_wrong_type_is_rejected():
    ok, _ = validate_call("check_certificate", '{"host": "x", "port": "443"}')
    assert not ok


def test_arguments_that_are_not_json_are_rejected():
    ok, reason = validate_call("check_time_sync", "not json")
    assert not ok and "json" in reason.lower()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_probe_tools.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'probe.tools'`

- [ ] **Step 3: Implement `probe/tools.py`**

```python
"""The probe's five diagnostic tools. Each call is scored against ITS OWN schema
(MFR-2026-08-20 correction #2: a single hard-coded field misreported 16% for 83-100%)."""
import json

import jsonschema


def _tool(name, description, properties, required):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": required, "additionalProperties": False}}}


TOOLS = [
    _tool("get_service_status", "Show whether a systemd unit is active and its recent state.",
          {"unit": {"type": "string"}}, ["unit"]),
    _tool("read_log", "Read the last N journal lines for a systemd unit.",
          {"unit": {"type": "string"}, "lines": {"type": "integer", "minimum": 1}}, ["unit", "lines"]),
    _tool("check_certificate", "Show the TLS certificate chain and expiry for host:port.",
          {"host": {"type": "string"}, "port": {"type": "integer"}}, ["host", "port"]),
    _tool("check_time_sync", "Show clock offset and NTP synchronisation state.", {}, []),
    _tool("list_failed_logins", "List recent failed login attempts for a user.",
          {"user": {"type": "string"}}, ["user"]),
]
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}
_SCHEMAS = {t["function"]["name"]: t["function"]["parameters"] for t in TOOLS}


def validate_call(name: str, arguments: str) -> tuple[bool, str]:
    if name not in _SCHEMAS:
        return False, f"unknown tool {name!r}"
    try:
        args = json.loads(arguments) if arguments else {}
    except json.JSONDecodeError as e:
        return False, f"arguments are not valid JSON: {e.msg}"
    try:
        jsonschema.validate(args, _SCHEMAS[name])
    except jsonschema.ValidationError as e:
        return False, f"schema: {e.message}"
    return True, "ok"
```

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_probe_tools.py -q`
Expected: `6 passed`

- [ ] **Step 5: Commit**

```bash
git add probe/tools.py tests/test_probe_tools.py
git commit -m "probe: five tool schemas, per-tool argument validation"
```

---

### Task 3: Response scorer

**Files:**
- Create: `probe/score.py`
- Test: `tests/test_probe_score.py`

**Interfaces:**
- Consumes: `validate_call`, `TOOL_NAMES` (Task 2).
- Produces: `score(response: dict | None, error: str | None = None) -> dict` returning `{"category": one of "valid" | "invalid_call" | "prose_json" | "prose" | "error", "detail": str, "tool": str | None}`. `response` is the parsed chat-completions JSON.

- [ ] **Step 1: Write the failing test**

```python
from probe.score import score


def _resp(content=None, tool_calls=None):
    return {"choices": [{"message": {"content": content, "tool_calls": tool_calls}}]}


def _call(name, args):
    return [{"type": "function", "function": {"name": name, "arguments": args}}]


def test_structured_valid_call():
    r = score(_resp(tool_calls=_call("check_time_sync", "{}")))
    assert r["category"] == "valid" and r["tool"] == "check_time_sync"


def test_structured_call_with_bad_arguments_is_invalid():
    r = score(_resp(tool_calls=_call("read_log", '{"unit": "sshd"}')))
    assert r["category"] == "invalid_call" and "lines" in r["detail"]


def test_structured_call_to_unknown_tool_is_invalid():
    assert score(_resp(tool_calls=_call("rm_rf", "{}")))["category"] == "invalid_call"


def test_json_in_content_is_not_a_structured_call():
    text = 'I will call {"name": "check_time_sync", "arguments": {}}'
    assert score(_resp(content=text))["category"] == "prose_json"


def test_plain_advice_is_prose():
    r = score(_resp(content="You should run chronyc tracking on the client."))
    assert r["category"] == "prose"


def test_transport_error_is_error():
    assert score(None, error="timeout")["category"] == "error"


def test_empty_choices_is_error():
    assert score({"choices": []})["category"] == "error"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_probe_score.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'probe.score'`

- [ ] **Step 3: Implement `probe/score.py`**

```python
"""Classify one chat-completions response. Only a STRUCTURED tool_calls entry with a
known tool and schema-valid arguments counts as success (MFR F-7: under load the model
drifts into prose that describes what to run)."""
from probe.tools import TOOL_NAMES, validate_call


def score(response, error=None):
    if error is not None or not response:
        return {"category": "error", "detail": error or "no response", "tool": None}
    choices = response.get("choices") or []
    if not choices:
        return {"category": "error", "detail": "no choices", "tool": None}
    msg = choices[0].get("message") or {}
    calls = msg.get("tool_calls") or []
    if calls:
        fn = calls[0].get("function") or {}
        name, args = fn.get("name", ""), fn.get("arguments", "")
        ok, reason = validate_call(name, args)
        return {"category": "valid" if ok else "invalid_call", "detail": reason, "tool": name}
    content = msg.get("content") or ""
    if any(n in content for n in TOOL_NAMES) and "{" in content:
        return {"category": "prose_json", "detail": content[:200], "tool": None}
    return {"category": "prose", "detail": content[:200], "tool": None}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_probe_score.py -q`
Expected: `7 passed`

- [ ] **Step 5: Commit**

```bash
git add probe/score.py tests/test_probe_score.py
git commit -m "probe: response scorer (valid / invalid_call / prose_json / prose / error)"
```

---

### Task 4: Padding generator

**Files:**
- Create: `probe/padding.py`
- Test: `tests/test_probe_padding.py`

**Interfaces:**
- Produces: `padding(target_tokens: int) -> str`: deterministic sysadmin-style reference text of about `target_tokens` tokens (estimated at 4 chars/token; actual `prompt_tokens` from the API is recorded separately). `padding(0) == ""`.

- [ ] **Step 1: Write the failing test**

```python
from probe.padding import CHARS_PER_TOKEN, padding


def test_zero_is_empty():
    assert padding(0) == ""


def test_size_is_close_to_target():
    for t in (1000, 4000, 15000):
        n = len(padding(t)) / CHARS_PER_TOKEN
        assert 0.95 * t <= n <= 1.05 * t


def test_deterministic():
    assert padding(4000) == padding(4000)


def test_looks_like_reference_material_not_instructions():
    text = padding(2000)
    assert "kanidm" in text.lower() and "call" not in text.lower()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_probe_padding.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `probe/padding.py`**

```python
"""Deterministic filler: realistic operations text that grows the prompt without
changing the task (MFR F-6 measures reliability against prompt volume)."""
CHARS_PER_TOKEN = 4

_LINES = [
    "Sep 26 {h:02d}:{m:02d}:{s:02d} srv1 kanidmd[812]: INFO request completed path=/v1/auth status=200 duration_ms={d}",
    "Sep 26 {h:02d}:{m:02d}:{s:02d} client2 kanidm_unixd[655]: DEBUG cache hit for account uid={u} ttl=300",
    "Sep 26 {h:02d}:{m:02d}:{s:02d} srv1 step-ca[901]: INFO certificate renewed serial={u}{d} not_after=2026-10-26",
    "Sep 26 {h:02d}:{m:02d}:{s:02d} srv1 named[733]: client @0x7f{d} 192.168.100.{u}#53 query: idm.kanidm.lab.test IN A",
    "Runbook note {u}: the unixd cache keeps resolved accounts for 300 seconds; posix passwords are separate from primary credentials.",
    "Inventory {u}: host client{u} enrolled {d} days ago, trust anchor step-ca root, sshd TrustedUserCAKeys present.",
]


def padding(target_tokens: int) -> str:
    target_chars = target_tokens * CHARS_PER_TOKEN
    out, i = [], 0
    size = 0
    while size < target_chars:
        line = _LINES[i % len(_LINES)].format(
            h=(i // 3600) % 24, m=(i // 60) % 60, s=i % 60, d=100 + i % 900, u=10 + i % 90)
        out.append(line)
        size += len(line) + 1
        i += 1
    text = "\n".join(out)
    return text[:target_chars] if target_tokens else ""
```

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_probe_padding.py -q`
Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add probe/padding.py tests/test_probe_padding.py
git commit -m "probe: deterministic padding context"
```

---

### Task 5: LM Studio client, `lms` wrapper, and runner

**Files:**
- Create: `probe/client.py`, `probe/lms.py`, `probe/runner.py`
- Test: `tests/test_probe_runner.py`

**Interfaces:**
- Consumes: `TOOLS` (Task 2), `score` (Task 3), `padding` (Task 4).
- Produces:
  - `build_request(model: str, pad_tokens: int, temperature: float) -> dict`
  - `chat(request: dict, transport=None, timeout=300) -> tuple[dict | None, str | None, float]` returning `(response_json, error, seconds)`. `transport(url, payload, timeout)` defaults to `requests.post(...).json()`.
  - `lms.loaded() -> list[str]`, `lms.unload_all()`, `lms.load(model: str)`
  - `run_point(model, pad_tokens, n, *, transport=None, loaded=lms.loaded, temperature=0.5) -> dict` with keys `model, pad_tokens, n, counts{category: int}, prompt_tokens_mean, seconds_mean, aborted, reason`.

- [ ] **Step 1: Write the failing test**

```python
from probe import runner
from probe.client import build_request


def test_request_carries_tools_and_padding():
    req = build_request("m", 1000, 0.5)
    assert req["model"] == "m" and len(req["tools"]) == 5
    assert len(req["messages"][0]["content"]) > 3000


def _fake_transport(kind):
    def t(url, payload, timeout):
        if kind == "valid":
            msg = {"tool_calls": [{"type": "function", "function": {"name": "check_time_sync", "arguments": "{}"}}]}
        else:
            msg = {"content": "Run chronyc tracking."}
        return {"choices": [{"message": msg}], "usage": {"prompt_tokens": 1234}}
    return t


def test_run_point_counts_categories():
    r = runner.run_point("m", 1000, 4, transport=_fake_transport("valid"), loaded=lambda: ["m"])
    assert r["counts"]["valid"] == 4 and r["prompt_tokens_mean"] == 1234 and not r["aborted"]


def test_prose_is_counted_as_prose():
    r = runner.run_point("m", 1000, 3, transport=_fake_transport("prose"), loaded=lambda: ["m"])
    assert r["counts"]["prose"] == 3


def test_runner_aborts_when_loaded_models_change():
    states = iter([["m"], ["m", "other-model"]])
    r = runner.run_point("m", 1000, 5, transport=_fake_transport("valid"), loaded=lambda: next(states))
    assert r["aborted"] and "other-model" in r["reason"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_probe_runner.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement the three modules**

`probe/client.py`:
```python
"""One chat-completions call to LM Studio (localhost only)."""
import time

import requests

from probe.padding import padding
from probe.tools import TOOLS

URL = "http://127.0.0.1:1234/v1/chat/completions"
SYSTEM = ("You are a Linux identity-systems administrator's assistant. Diagnose by calling the "
          "provided tools. Reference material follows.\n\n")
TASK = ("Users report they cannot log in to client2 since this morning. Start diagnosing now: "
        "call exactly one tool.")


def build_request(model, pad_tokens, temperature):
    return {"model": model, "temperature": temperature, "max_tokens": 1024, "tools": TOOLS,
            "tool_choice": "auto",
            "messages": [{"role": "system", "content": SYSTEM + padding(pad_tokens)},
                         {"role": "user", "content": TASK}]}


def _post(url, payload, timeout):
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()


def chat(request, transport=None, timeout=300):
    t0 = time.monotonic()
    try:
        return (transport or _post)(URL, request, timeout), None, time.monotonic() - t0
    except Exception as e:  # recorded as an "error" run, never raised
        return None, f"{type(e).__name__}: {e}", time.monotonic() - t0
```

`probe/lms.py`:
```python
"""Thin wrapper over LM Studio's `lms` CLI."""
import json
import os
import subprocess

LMS = os.path.expanduser("~/.lmstudio/bin/lms")


def loaded():
    out = subprocess.run([LMS, "ps", "--json"], capture_output=True, text=True, check=True).stdout
    return sorted(m.get("identifier", "") for m in json.loads(out or "[]"))


def unload_all():
    subprocess.run([LMS, "unload", "--all"], capture_output=True, check=True)


def load(model):
    subprocess.run([LMS, "load", model, "-y"], capture_output=True, check=True)
```

`probe/runner.py`:
```python
"""Models x sizes x runs. A point is aborted if the loaded-model set changes while it
runs (LM Studio JIT-loading another model skews memory and timing)."""
from collections import Counter
from statistics import mean

from probe import lms
from probe.client import build_request, chat
from probe.score import score


def run_point(model, pad_tokens, n, *, transport=None, loaded=lms.loaded, temperature=0.5):
    before = loaded()
    counts, ptoks, secs = Counter(), [], []
    for _ in range(n):
        resp, err, s = chat(build_request(model, pad_tokens, temperature), transport=transport)
        counts[score(resp, err)["category"]] += 1
        secs.append(s)
        if resp and resp.get("usage"):
            ptoks.append(resp["usage"].get("prompt_tokens", 0))
    after = loaded()
    aborted = after != before
    return {"model": model, "pad_tokens": pad_tokens, "n": n, "counts": dict(counts),
            "prompt_tokens_mean": round(mean(ptoks)) if ptoks else None,
            "seconds_mean": round(mean(secs), 1) if secs else None,
            "aborted": aborted,
            "reason": f"loaded models changed: {before} -> {after}" if aborted else ""}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_probe_runner.py -q`
Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add probe/client.py probe/lms.py probe/runner.py tests/test_probe_runner.py
git commit -m "probe: LM Studio client, lms wrapper, runner with loaded-model guard"
```

---

### Task 6: Report writer and CLI

**Files:**
- Create: `probe/report.py`, `probe/__main__.py`
- Test: `tests/test_probe_report.py`

**Interfaces:**
- Consumes: `run_point` (Task 5); `lms.loaded/unload_all/load` (Task 5).
- Produces: `to_markdown(points: list[dict], meta: dict) -> str`; the CLI `uv run python -m probe --models A B --sizes 1000 4000 --n 20 --i-have-permission`, which writes `probe/results/<YYYY-MM-DD-HHMM>.md` and restores the originally loaded models.

- [ ] **Step 1: Write the failing test**

```python
from probe.report import to_markdown


def test_markdown_table_has_valid_rate_and_abort_marker():
    pts = [
        {"model": "gemma", "pad_tokens": 1000, "n": 20, "counts": {"valid": 18, "prose": 2},
         "prompt_tokens_mean": 1300, "seconds_mean": 2.1, "aborted": False, "reason": ""},
        {"model": "gemma", "pad_tokens": 15000, "n": 20, "counts": {"valid": 5},
         "prompt_tokens_mean": 15400, "seconds_mean": 9.8, "aborted": True, "reason": "changed"},
    ]
    md = to_markdown(pts, {"date": "2026-09-27", "temperature": 0.5})
    assert "| gemma | 1000 | 20 | 90% |" in md
    assert "ABORTED" in md and "temperature: 0.5" in md
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_probe_report.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`probe/report.py`:
```python
CATS = ["valid", "invalid_call", "prose_json", "prose", "error"]


def to_markdown(points, meta):
    lines = ["# Tool-calling probe results", ""]
    lines += [f"- {k}: {v}" for k, v in meta.items()] + [""]
    lines.append("| model | pad tokens | n | valid % | " + " | ".join(CATS) + " | prompt tok | s/call | note |")
    lines.append("|---|---:|---:|---:|" + "---:|" * len(CATS) + "---:|---:|---|")
    for p in points:
        c = p["counts"]
        pct = f"{round(100 * c.get('valid', 0) / p['n'])}%" if p["n"] else "-"
        note = f"ABORTED: {p['reason']}" if p["aborted"] else ""
        lines.append(f"| {p['model']} | {p['pad_tokens']} | {p['n']} | {pct} | "
                     + " | ".join(str(c.get(k, 0)) for k in CATS)
                     + f" | {p['prompt_tokens_mean']} | {p['seconds_mean']} | {note} |")
    return "\n".join(lines) + "\n"
```

`probe/__main__.py`:
```python
"""uv run python -m probe --models M1 M2 --sizes 1000 4000 8000 15000 25000 --n 20 --i-have-permission"""
import argparse
import datetime as dt
import pathlib

from probe import lms
from probe.report import to_markdown
from probe.runner import run_point


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--sizes", nargs="+", type=int, default=[1000, 4000, 8000, 15000, 25000])
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--temperature", type=float, default=0.5)
    ap.add_argument("--i-have-permission", action="store_true",
                    help="the user has confirmed LM Studio is free (the probe unloads models)")
    a = ap.parse_args()
    if not a.i_have_permission:
        raise SystemExit("Refusing to run: needs --i-have-permission (the user must free LM Studio).")
    original = lms.loaded()
    points = []
    try:
        for model in a.models:
            lms.unload_all()
            lms.load(model)
            for size in a.sizes:
                p = run_point(model, size, a.n, temperature=a.temperature)
                points.append(p)
                print(model, size, p["counts"], "ABORTED" if p["aborted"] else "", flush=True)
    finally:
        lms.unload_all()
        for m in original:
            lms.load(m)
    stamp = dt.datetime.now().strftime("%Y-%m-%d-%H%M")
    out = pathlib.Path(__file__).parent / "results" / f"{stamp}.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(to_markdown(points, {"date": stamp, "temperature": a.temperature,
                                        "n per point": a.n, "restored models": original}))
    print("wrote", out)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run all probe tests**

Run: `uv run pytest -q`
Expected: `22 passed`

- [ ] **Step 5: Commit**

```bash
git add probe/report.py probe/__main__.py tests/test_probe_report.py
git commit -m "probe: markdown report and CLI that restores the user's loaded models"
```

---

### Task 7: Mac developer tools

**Files:** none (environment)

- [ ] **Step 1: Install cargo and shellcheck** (gnupg is already installed)

Run: `brew install rust shellcheck`
Expected: `cargo --version` reports ≥ 1.96 and `shellcheck --version` prints its version.

- [ ] **Step 2: Record the versions** in the commit message of Task 8 (no separate commit).

---

### Task 8: Offline inputs: fetch, verify, manifest

**Files:**
- Create: `lab/inputs/fetch.sh`, `lab/inputs/verify.sh`
- Generated: `lab/inputs/MANIFEST.txt` (committed), inputs in `~/idm-lab-inputs/` (not committed)

**Interfaces:**
- Produces: `~/idm-lab-inputs/{Rocky-9.8-x86_64-dvd.iso, rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz, kanidm-1.11.2.tar.gz, kanidm-1.11.2-vendor.tar.gz, step-ca-0.30.2-1.x86_64.rpm, step-cli-0.31.0-1.x86_64.rpm}` plus `MANIFEST.txt` lines of the form `name|version|bytes|sha256|source|verification`.

- [ ] **Step 1: Write `lab/inputs/fetch.sh`**

```bash
#!/usr/bin/env bash
# Fetch + verify every offline input for the dc2-stack lab. Resumable (curl -C -).
# Runs on the Mac ONLY. Nothing unverified leaves this directory.
set -Eeuo pipefail
D="${IDM_INPUTS:-$HOME/idm-lab-inputs}"; mkdir -p "$D"; cd "$D"
ROCKY=https://download.rockylinux.org/pub/rocky/9.8/isos/x86_64
ROCKY_FPR=21CB256AE16FC54C6E652949702D426D350D275D
RUST=https://static.rust-lang.org/dist
RUST_FPR=108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE
KANIDM=v1.11.2
STEPCA=https://github.com/smallstep/certificates/releases/download/v0.30.2
STEPCLI=https://github.com/smallstep/cli/releases/download/v0.31.0
MAN="$(cd "$(dirname "$0")" && pwd)/MANIFEST.txt"
get() { curl -fL --retry 3 -C - -o "$2" "$1"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
bytes() { stat -f %z "$1"; }
fpr_ok() { gpg --batch --with-colons --fingerprint "$1" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}' | grep -qx "$1"; }
: > "$MAN.tmp"
rec() { echo "$1|$2|$(bytes "$1")|$(sha "$1")|$3|$4" >> "$MAN.tmp"; }

echo "== Rocky 9.8 DVD"
get "$ROCKY/Rocky-9.8-x86_64-dvd.iso.CHECKSUM" Rocky-9.8-x86_64-dvd.iso.CHECKSUM
get "$ROCKY/Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc" Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc
curl -fsSL https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9 | gpg --batch --import 2>/dev/null
fpr_ok "$ROCKY_FPR" || { echo "Rocky key fingerprint mismatch"; exit 1; }
gpg --batch --verify Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc Rocky-9.8-x86_64-dvd.iso.CHECKSUM 2>/dev/null \
  || gpg --batch --verify Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc   # detached or clearsigned
get "$ROCKY/Rocky-9.8-x86_64-dvd.iso" Rocky-9.8-x86_64-dvd.iso
want=$(grep -E 'SHA256 \(Rocky-9.8-x86_64-dvd.iso\)' Rocky-9.8-x86_64-dvd.iso.CHECKSUM | awk '{print $NF}')
[[ "$(sha Rocky-9.8-x86_64-dvd.iso)" == "$want" ]] || { echo "DVD sha256 mismatch"; exit 1; }
rec Rocky-9.8-x86_64-dvd.iso 9.8 "$ROCKY" "sha256 vs CHECKSUM, CHECKSUM gpg-signed $ROCKY_FPR"

echo "== Rust 1.96.0"
R=rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz
get "$RUST/$R" "$R"; get "$RUST/$R.asc" "$R.asc"; get "$RUST/$R.sha256" "$R.sha256"
curl -fsSL https://static.rust-lang.org/rust-key.gpg.ascii | gpg --batch --import 2>/dev/null
fpr_ok "$RUST_FPR" || { echo "Rust key fingerprint mismatch"; exit 1; }
gpg --batch --verify "$R.asc" "$R"
[[ "$(sha "$R")" == "$(awk '{print $1}' "$R.sha256")" ]] || { echo "rust sha256 mismatch"; exit 1; }
rec "$R" 1.96.0 "$RUST" "gpg $RUST_FPR + sha256"

echo "== Kanidm $KANIDM source + vendored crates"
get "https://github.com/kanidm/kanidm/archive/refs/tags/$KANIDM.tar.gz" kanidm-1.11.2.tar.gz
rm -rf kanidm-src && mkdir kanidm-src && tar -xzf kanidm-1.11.2.tar.gz -C kanidm-src --strip-components=1
( cd kanidm-src && cargo vendor --locked --versioned-dirs vendor > vendor-config.toml )
tar -czf kanidm-1.11.2-vendor.tar.gz -C kanidm-src vendor vendor-config.toml
rm -rf kanidm-src
rec kanidm-1.11.2.tar.gz 1.11.2 "github kanidm/kanidm tag $KANIDM" "sha256 recorded here (tag archive is unsigned)"
rec kanidm-1.11.2-vendor.tar.gz 1.11.2 "cargo vendor --locked" "crate hashes enforced by Cargo.lock at build time"

echo "== step-ca / step-cli RPMs"
get "$STEPCA/step-ca-0.30.2-1.x86_64.rpm" step-ca-0.30.2-1.x86_64.rpm
get "$STEPCA/checksums.txt" step-ca.checksums.txt
get "$STEPCLI/step-cli-0.31.0-1.x86_64.rpm" step-cli-0.31.0-1.x86_64.rpm
get "$STEPCLI/checksums.txt" step-cli.checksums.txt
for pair in "step-ca-0.30.2-1.x86_64.rpm step-ca.checksums.txt" "step-cli-0.31.0-1.x86_64.rpm step-cli.checksums.txt"; do
  set -- $pair
  [[ "$(sha "$1")" == "$(grep -E " \*?$1\$" "$2" | awk '{print $1}')" ]] || { echo "$1 sha256 mismatch"; exit 1; }
done
rec step-ca-0.30.2-1.x86_64.rpm 0.30.2 "$STEPCA" "sha256 vs release checksums.txt"
rec step-cli-0.31.0-1.x86_64.rpm 0.31.0 "$STEPCLI" "sha256 vs release checksums.txt"

mv "$MAN.tmp" "$MAN"
echo "ALL INPUTS VERIFIED. Manifest: $MAN"
```

- [ ] **Step 2: Write `lab/inputs/verify.sh`** (an independent check that uses only the manifest)

```bash
#!/usr/bin/env bash
# Re-verify every input against MANIFEST.txt (size + sha256). Run on the Mac, or on aero with
# IDM_INPUTS=/data/lab-inputs. Exit 1 on any mismatch or missing file.
set -Eeuo pipefail
D="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
MAN="${IDM_MANIFEST:-$(cd "$(dirname "$0")" && pwd)/MANIFEST.txt}"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }
bad=0
while IFS='|' read -r name ver bytes want src how; do
  f="$D/$name"
  if [[ ! -f "$f" ]]; then echo "MISSING  $name"; bad=1; continue; fi
  [[ "$(size "$f")" == "$bytes" ]] || { echo "SIZE     $name"; bad=1; continue; }
  [[ "$(sha "$f")" == "$want" ]] || { echo "SHA256   $name"; bad=1; continue; }
  echo "OK       $name ($ver)"
done < "$MAN"
exit $bad
```

- [ ] **Step 3: Run shellcheck, then the fetch**

Run: `chmod +x lab/inputs/*.sh && shellcheck lab/inputs/*.sh && lab/inputs/fetch.sh`
Expected: shellcheck clean; the run ends with `ALL INPUTS VERIFIED.` (the 15 GB DVD takes a while on the first run)

- [ ] **Step 4: Prove verify.sh catches a bad file** (Review Focus #2)

Run:
```bash
lab/inputs/verify.sh
cp ~/idm-lab-inputs/step-cli-0.31.0-1.x86_64.rpm /tmp/keep.rpm
head -c 1000 /tmp/keep.rpm > ~/idm-lab-inputs/step-cli-0.31.0-1.x86_64.rpm
lab/inputs/verify.sh; echo "exit=$?"
mv /tmp/keep.rpm ~/idm-lab-inputs/step-cli-0.31.0-1.x86_64.rpm && lab/inputs/verify.sh
```
Expected: the first run is all `OK`; the second shows `SIZE     step-cli-0.31.0-1.x86_64.rpm` and `exit=1`; the third is all `OK` again.

- [ ] **Step 5: Commit**

```bash
git add lab/inputs/fetch.sh lab/inputs/verify.sh lab/inputs/MANIFEST.txt
git commit -m "lab inputs: fetch + verify Rocky 9.8 DVD, Rust 1.96, Kanidm 1.11.2 (+vendor), step RPMs"
```

---

### Task 9: Host library and b1-media (local repos)

**Files:**
- Create: `lab/host/lib.sh`, `lab/host/push.sh`, `lab/host/b1-media.sh`

**Interfaces:**
- Produces:
  - `lib.sh`: `CHECK` (0/1 from `--check`), `log`, `die`, `run <desc> <cmd...>` (prints in check mode, executes otherwise), `need_root`.
  - `push.sh <step> [args]`: copies `lab/host/` to `aero:/tmp/lab-host/` and runs `sudo bash /tmp/lab-host/<step>.sh [args]`.
  - After b1: repos `lab-baseos`, `lab-appstream` (the DVD) and `lab-local` (`/data/lab-inputs/rpms`, created with createrepo_c) are the **only** enabled repos.

- [ ] **Step 1: Write `lab/host/lib.sh`**

```bash
# Shared helpers for aero host-prep steps. Source it; do not execute.
set -Eeuo pipefail
CHECK=0
for a in "$@"; do [[ "$a" == "--check" ]] && CHECK=1; done
log()  { printf '%s  %s\n' "$(date +%T)" "$*"; }
die()  { log "FAIL: $*"; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "run with sudo"; }
run() {
  local desc="$1"; shift
  if (( CHECK )); then log "[check] would: $desc  ($*)"; else log "$desc"; "$@"; fi
}
```

- [ ] **Step 2: Write `lab/host/push.sh`**

```bash
#!/usr/bin/env bash
# Copy the host-prep scripts to aero and run one step with sudo:  lab/host/push.sh b1-media --check
set -Eeuo pipefail
step="$1"; shift
here="$(cd "$(dirname "$0")" && pwd)"
ssh aero 'mkdir -p /tmp/lab-host'
scp -q "$here"/*.sh aero:/tmp/lab-host/
ssh aero "sudo bash /tmp/lab-host/${step}.sh $*"
```

- [ ] **Step 3: Write `lab/host/b1-media.sh`**

```bash
#!/usr/bin/env bash
# b1: DVD + lab RPMs become the ONLY dnf repos on aero (it is offline).
# Inputs must already be in /data/lab-inputs (copied by the Mac; see Task 9 Step 4).
source "$(dirname "$0")/lib.sh"; need_root
IN=/data/lab-inputs; MNT=$IN/dvd; ISO=$IN/Rocky-9.8-x86_64-dvd.iso
[[ -f $ISO ]] || die "missing $ISO"
run "create mount point" mkdir -p "$MNT" "$IN/rpms"
if ! grep -q " $MNT " /etc/fstab; then
  run "add DVD loop mount to fstab" sh -c "echo '$ISO $MNT iso9660 loop,ro,nofail 0 0' >> /etc/fstab"
fi
mountpoint -q "$MNT" || run "mount DVD" mount "$MNT"
run "disable online Rocky repos (aero has no internet)" \
  sh -c 'for f in /etc/yum.repos.d/rocky*.repo; do sed -i "s/^enabled=1/enabled=0/" "$f"; done'
run "write lab repo definitions" sh -c "cat > /etc/yum.repos.d/lab.repo <<EOF
[lab-baseos]
name=Lab DVD BaseOS (Rocky 9.8)
baseurl=file://$MNT/BaseOS
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
enabled=1
[lab-appstream]
name=Lab DVD AppStream (Rocky 9.8)
baseurl=file://$MNT/AppStream
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
enabled=1
[lab-local]
name=Lab local RPMs (sha256-verified on the Mac; unsigned)
baseurl=file://$IN/rpms
gpgcheck=0
enabled=1
EOF"
run "install createrepo_c from the DVD" dnf -y --disablerepo='*' --enablerepo='lab-baseos,lab-appstream' install createrepo_c
run "stage step RPMs in the local repo" cp -f "$IN"/step-ca-*.rpm "$IN"/step-cli-*.rpm "$IN/rpms/"
run "index the local repo" createrepo_c -q "$IN/rpms"
run "refresh metadata" dnf -q makecache
log "b1 done"
```

- [ ] **Step 4: Copy the inputs to aero, then check and apply**

Run:
```bash
ssh aero 'sudo mkdir -p /data/lab-inputs && sudo chown itadmin: /data/lab-inputs'
rsync -a --progress ~/idm-lab-inputs/ aero:/data/lab-inputs/
scp lab/inputs/verify.sh lab/inputs/MANIFEST.txt aero:/data/lab-inputs/
ssh aero 'IDM_INPUTS=/data/lab-inputs IDM_MANIFEST=/data/lab-inputs/MANIFEST.txt bash /data/lab-inputs/verify.sh'
chmod +x lab/host/*.sh && shellcheck -x lab/host/*.sh
lab/host/push.sh b1-media --check
lab/host/push.sh b1-media
ssh aero 'dnf repolist'
```
Expected: verify.sh on aero is all `OK`; `--check` prints only `[check] would:` lines; `dnf repolist` lists exactly `lab-baseos`, `lab-appstream`, `lab-local` (Review Focus #5).

- [ ] **Step 5: Log the deviation and commit**

Append to `lab/aero-deviations.md`:
```
| 2026-09-27 | Online Rocky repos disabled; lab-baseos/appstream (DVD loop mount in fstab) + lab-local repo added | aero is offline | re-enable `enabled=1` in rocky*.repo; remove lab.repo + fstab line |
```
```bash
git add lab/host/lib.sh lab/host/push.sh lab/host/b1-media.sh lab/aero-deviations.md
git commit -m "aero b1: DVD + local RPM repos as the only dnf sources"
```

---

### Task 10: b2-kvm

**Files:** Create `lab/host/b2-kvm.sh`

- [ ] **Step 1: Write it**

```bash
#!/usr/bin/env bash
# b2: KVM/libvirt from the DVD.
source "$(dirname "$0")/lib.sh"; need_root
run "install virtualization packages" dnf -y install qemu-kvm libvirt virt-install qemu-img libvirt-client policycoreutils-python-utils
run "enable modular libvirt daemons" systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket
run "stop the default NAT network autostarting (lab uses br-lab only)" sh -c 'virsh net-autostart default --disable 2>/dev/null || true; virsh net-destroy default 2>/dev/null || true'
log "b2 done"
```

- [ ] **Step 2: Check, apply, verify**

Run: `lab/host/push.sh b2-kvm --check && lab/host/push.sh b2-kvm && ssh aero 'sudo virt-host-validate qemu 2>&1 | grep -E "QEMU: Checking for (hardware virtualization|device /dev/kvm)"'`
Expected: both checked lines end in `PASS`.

- [ ] **Step 3: Commit**

```bash
git add lab/host/b2-kvm.sh && git commit -m "aero b2: KVM/libvirt from the DVD"
```

---

### Task 11: b3-storage

**Files:** Create `lab/host/b3-storage.sh`

- [ ] **Step 1: Write it**

```bash
#!/usr/bin/env bash
# b3: VM images on /data (LUKS), SELinux-labelled, as libvirt's default pool.
source "$(dirname "$0")/lib.sh"; need_root
P=/data/libvirt/images
run "create image dir" mkdir -p "$P"
semanage fcontext -l | grep -q "^/data/libvirt/images" || \
  run "label rule virt_image_t" semanage fcontext -a -t virt_image_t "/data/libvirt/images(/.*)?"
run "apply label" restorecon -R /data/libvirt
if ! virsh pool-info default >/dev/null 2>&1; then
  run "define default pool" virsh pool-define-as default dir --target "$P"
  run "autostart pool" virsh pool-autostart default
  run "start pool" virsh pool-start default
fi
log "b3 done"
```

- [ ] **Step 2: Check, apply, verify**

Run: `lab/host/push.sh b3-storage --check && lab/host/push.sh b3-storage && ssh aero 'sudo virsh pool-info default | grep -E "State|Autostart"; ls -dZ /data/libvirt/images'`
Expected: `State: running`, `Autostart: yes`, and the label contains `virt_image_t`.

- [ ] **Step 3: Commit**

```bash
git add lab/host/b3-storage.sh && git commit -m "aero b3: VM image pool on /data (virt_image_t)"
```

---

### Task 12: b4-net (bridge with automatic rollback)

**Files:** Create `lab/host/b4-net.sh`

**Interfaces:**
- Produces: bridge `br-lab` 192.168.100.1/24 (no gateway, no DNS) enslaving `enp49s0`. Old profile "Profile 1" kept, set to not autoconnect. Flag file `/run/lab-net-ok`, created by the Mac to confirm.

- [ ] **Step 1: Write it**

```bash
#!/usr/bin/env bash
# b4: move 192.168.100.1 from enp49s0 onto bridge br-lab (for the lab VMs).
# Applies in the background and ROLLS BACK after 90 s unless /run/lab-net-ok appears.
# --rollback-test applies and deliberately never confirms, to prove the rollback works.
source "$(dirname "$0")/lib.sh"; need_root
OLD="Profile 1"; NIC=enp49s0; TEST=0
for a in "$@"; do [[ "$a" == "--rollback-test" ]] && TEST=1; done
nmcli -t -f NAME con show | grep -qx br-lab && { log "br-lab already exists"; exit 0; }
(( CHECK )) && { log "[check] would: create br-lab 192.168.100.1/24 on $NIC, rollback in 90 s unless confirmed"; exit 0; }
# In --rollback-test mode the wait loop never looks for the confirmation file.
if (( TEST )); then WAIT='sleep 90'; else WAIT='for i in $(seq 90); do [[ -f /run/lab-net-ok ]] \&\& exit 0; sleep 1; done'; fi
cat > /run/lab-net-apply.sh <<EOF
#!/bin/bash
rm -f /run/lab-net-ok
nmcli con add type bridge ifname br-lab con-name br-lab ipv4.method manual ipv4.addresses 192.168.100.1/24 ipv6.method disabled bridge.stp no
nmcli con add type bridge-slave ifname $NIC master br-lab con-name br-lab-port
nmcli con mod "$OLD" connection.autoconnect no
nmcli con down "$OLD"; nmcli con up br-lab
$WAIT
nmcli con down br-lab; nmcli con delete br-lab-port br-lab
nmcli con mod "$OLD" connection.autoconnect yes; nmcli con up "$OLD"
echo "ROLLED BACK \$(date)" > /run/lab-net-rolledback
EOF
chmod 700 /run/lab-net-apply.sh
nohup /run/lab-net-apply.sh >/run/lab-net-apply.log 2>&1 &
log "applying in background; confirm from the Mac within 90 s: ssh aero sudo touch /run/lab-net-ok"
```

- [ ] **Step 2: Dry run**

Run: `lab/host/push.sh b4-net --check`
Expected: the single `[check] would: create br-lab …` line.

- [ ] **Step 3: Prove the rollback first** (Review Focus #1)

Run:
```bash
lab/host/push.sh b4-net --rollback-test
sleep 100
ssh aero 'cat /run/lab-net-rolledback; nmcli -t -f NAME,DEVICE con show --active'
```
Expected: `ROLLED BACK …` is printed, the active connections show `Profile 1:enp49s0`, and there's no `br-lab`. (The SSH session in the middle of the test may hang or drop; that's expected.)

- [ ] **Step 4: Real apply, then confirm within 90 s**

Run:
```bash
lab/host/push.sh b4-net
for i in $(seq 30); do ssh -o ConnectTimeout=3 aero 'sudo touch /run/lab-net-ok' 2>/dev/null && break; sleep 2; done
sleep 95; ssh aero 'nmcli -t -f NAME,DEVICE con show --active; ip -br addr show br-lab; ls /run/lab-net-rolledback 2>&1'
```
Expected: `br-lab:br-lab` and `br-lab-port:enp49s0` active; `br-lab UP 192.168.100.1/24`; `ls` reports that `/run/lab-net-rolledback` does not exist.

- [ ] **Step 5: Log the deviation and commit**

Append to `lab/aero-deviations.md`:
```
| 2026-09-27 | enp49s0 enslaved to bridge br-lab (192.168.100.1/24); "Profile 1" autoconnect off | lab VMs share the cable subnet | `nmcli con delete br-lab-port br-lab; nmcli con mod "Profile 1" connection.autoconnect yes; nmcli con up "Profile 1"` |
```
```bash
git add lab/host/b4-net.sh lab/aero-deviations.md
git commit -m "aero b4: br-lab bridge with self-rolling-back apply"
```

---

### Task 13: b5-time

**Files:** Create `lab/host/b5-time.sh`

- [ ] **Step 1: Write it**

```bash
#!/usr/bin/env bash
# b5: aero's chrony serves the lab (no internet time source exists here).
source "$(dirname "$0")/lib.sh"; need_root
C=/etc/chrony.conf
grep -q '^allow 192.168.100.0/24' "$C" || run "allow lab clients" sh -c "echo 'allow 192.168.100.0/24' >> $C"
grep -q '^local stratum 10' "$C" || run "serve local time when unsynchronised" sh -c "echo 'local stratum 10' >> $C"
run "restart chronyd" systemctl restart chronyd
ZONE=$(firewall-cmd --get-zone-of-interface=br-lab 2>/dev/null || firewall-cmd --get-default-zone)
run "open ntp on $ZONE" firewall-cmd --permanent --zone="$ZONE" --add-service=ntp
run "reload firewall" firewall-cmd --reload
log "RTC mode (reported, not changed): $(timedatectl show -p LocalRTC --value)"
log "b5 done"
```

- [ ] **Step 2: Check, apply, verify from the Mac**

Run: `lab/host/push.sh b5-time --check && lab/host/push.sh b5-time && sntp -t 3 192.168.100.1`
Expected: `sntp` prints an offset line from 192.168.100.1 (not a timeout).

- [ ] **Step 3: Log the deviation and commit**

Append to `lab/aero-deviations.md`:
```
| 2026-09-27 | chrony serves 192.168.100.0/24 (`local stratum 10`); ntp opened in firewalld | lab time source | remove the two chrony lines; `firewall-cmd --permanent --remove-service=ntp` |
```
```bash
git add lab/host/b5-time.sh lab/aero-deviations.md && git commit -m "aero b5: lab time source"
```

---

### Task 14: b6-scap-report (report only)

**Files:** Create `lab/host/b6-scap-report.sh`

- [ ] **Step 1: Write it**

```bash
#!/usr/bin/env bash
# b6: OpenSCAP CUI profile evaluation, REPORT ONLY (no remediation).
source "$(dirname "$0")/lib.sh"; need_root
DS=/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
OUT=/data/lab-inputs/reports; STAMP=$(date +%Y%m%d-%H%M)
run "make report dir" mkdir -p "$OUT"
run "evaluate cui profile" sh -c "oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cui \
  --results $OUT/aero-cui-$STAMP.xml --report $OUT/aero-cui-$STAMP.html $DS >/dev/null 2>&1 || true"
run "hand the report to itadmin" chown -R itadmin: "$OUT"
log "report: $OUT/aero-cui-$STAMP.html"
```

(`oscap` exits 2 when any rule fails; the `|| true` keeps a normal "some rules fail" result from stopping the script.)

- [ ] **Step 2: Run and bring the report to the Mac**

Run:
```bash
lab/host/push.sh b6-scap-report
mkdir -p lab/reports && scp 'aero:/data/lab-inputs/reports/aero-cui-*.html' lab/reports/
ls -la lab/reports/
```
Expected: one `aero-cui-<stamp>.html` of several hundred KB on the Mac.

- [ ] **Step 3: Summarize the failing rules into the deviations log**

Run:
```bash
ssh aero 'x=$(ls -t /data/lab-inputs/reports/aero-cui-*.xml | head -1); python3 - "$x" <<"PY"
import sys, xml.etree.ElementTree as ET
ns = "{http://checklists.nist.gov/xccdf/1.2}"
for rr in ET.parse(sys.argv[1]).iter(ns + "rule-result"):
    if rr.findtext(ns + "result") == "fail":
        print(rr.get("idref").split("content_rule_")[-1])
PY'
```
Expected: a list of failing rule ids. Confirm the NOPASSWD rule (for example `sudo_remove_nopasswd`) appears, and add a line to `lab/aero-deviations.md` naming every failing rule that is explained by a logged deviation.

- [ ] **Step 4: Commit**

```bash
git add lab/host/b6-scap-report.sh lab/reports/ lab/aero-deviations.md
git commit -m "aero b6: CUI profile report (report-only) and explained failures"
```

---

### Task 15: First probe run (only with the user's go-ahead)

**Files:** Generated `probe/results/<stamp>.md`

- [ ] **Step 1: Ask the user to confirm LM Studio is free.** Do not proceed without an explicit yes.

- [ ] **Step 2: Run the probe on the two installed models**

Run: `uv run python -m probe --models google/gemma-4-26b-a4b-qat mistralai/devstral-small-2-2512 --sizes 1000 4000 8000 15000 25000 --n 20 --i-have-permission`
Expected: ten progress lines, then `wrote probe/results/<stamp>.md`; `lms ps` afterwards lists the same models as before the run.

- [ ] **Step 3: Commit the results**

```bash
git add probe/results/ && git commit -m "probe: first results (Gemma 4 26B, Devstral Small 2)"
```

---

## Self-review notes
- Spec coverage for M0/M1: probe (§3; the interpretation cases wait for lab findings, Plan 4), inputs + manifest (§4.1), host prep b1–b6 (§4.2), deviations log (§1 constraint). Build VM, stack, clients, collector are Plans 2–4.
- The probe-test total after Task 6 is 22 (6 + 7 + 4 + 4 + 1).
