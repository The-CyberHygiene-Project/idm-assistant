# Plan 5: Read-Only Collector, Deterministic Findings, Allow-Listed Repairs: L1 and C1 End to End, Plus the ISO Requirements Log (M5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the diagnostic loop the assistant exists for, end to end, for two scenarios:
- **L1:** a Kanidm user has a primary credential but **no POSIX password**, so Linux login fails.
- **C1:** the Kanidm TLS certificate **expires** because its renewal timer stopped.

The loop is inject → collect (read-only) → findings (deterministic) → repair (allow-listed, human-approved, reversible) → verify, each green **three times in a row from `golden`** (spec success criterion 3). Alongside, keep an **ISO requirements log**: every default the dc2 installer should set, with its evidence.

**Architecture:**
- The **collector** is a POSIX-shell script on each host. It is read-only, emits one redacted JSON report, and runs as a `diag` user through a single-command sudo rule, reached by SSH key.
- The **Mac side** (`engine/`, Python) holds:
  - pure-function **findings rules** over reports;
  - an allow-listed **repair runner** (precheck → backup → apply → verify, with undo on a failed verify, and typed approval);
  - **case files** as the audit record;
  - scenario scripts for inject and cleanup.
- **No model in Plan 5.** Repair choice is the runbook default per finding. The Plan 6 interpreter will return the explainable-response schema defined here.

**Tech Stack:** POSIX sh (collector, runs under fapolicyd enforcing), Python 3.12 + pytest (engine), OpenSSH, Kanidm 1.11.2 CLI (read-only service account), step-cli, libvirt snapshots.

**Spec:** `docs/superpowers/specs/2026-09-26-idm-diagnostic-lab-design.md` (rev 2: §5.1–5.5, §6 rows L1 and C1, §7 M5, §8)

## Why run this test: what we will know afterwards that we don't know now

| Question | Today | After Plan 5 | Why it matters (lab + ISO) |
|---|---|---|---|
| **1. Can a strictly read-only collector see enough to diagnose real identity faults?** | Assumed in the spec. | Evidence that one redacted report (≤ 200 KB) identifies L1 and C1 correctly, with before/after proof that the collector changed nothing. | The whole assistant rests on it. For the ISO: what every host must expose (logs, service-account access, sudo rule). |
| **2. Can repairs be safe: allow-listed, approved, reversible, verified?** | Designed, never run. | Two repairs per scenario, with backup and undo exercised, and every step timed in a case file. | The audit story for the ISSO. Repeatable fixes become ISO defaults. |
| **3. Which defaults break in daily operation?** | Plans 3–4 found several by accident (clock after restore, expired certificates after revert, `initgroups`, SELinux labels). | A systematic **ISO requirements log** seeded from Plans 2–4 and extended by each scenario. | The ISO starts from evidence, not a blank page. |
| **4. Does the collector's access path work on hardened hosts?** | Key access works on srv1/client2. The CHP kit forbids keys (client1). | A proven `diag` single-command sudo rule under fapolicyd enforcing, and the client1 gap recorded against decision 3′ (key **and** GA). | dc2 access design (spec §9, ISSO question 3). |

**What Plan 5 will *not* tell us:**
- how well a local model explains findings (the Plan 6 interpreter, probe rounds 2–3);
- scenarios L2–L6 and C2–C4 (Plan 6);
- the ISO build itself (its own project).

## Global Constraints

- **Read-only collector:** no writes outside its own `mktemp` directory (removed on exit). Proven by before/after hashes of `/etc`, `/var/lib/kanidm-unixd`, `/etc/pki/kanidm` and `systemctl list-units --state=active` (spec §8 non-negotiable).
- **No repair without approval** outside test mode. Approval is the word `yes` typed at a prompt, chosen for low typing effort; the case file records who, when and what. The test mode (`IDM_TEST_APPROVE=1`) is only for the regression runner and is recorded as such.
- **The model never emits shell** (no model in Plan 5 at all).
- **Secrets** are never collected, printed or stored: private keys, tokens, TOTP secrets, reset tokens and passwords are redacted in the collector, and the Mac side runs `lab/tools/secrets-scan.sh` over every report. A credential-reset **token** issued by a repair goes to `~/idm-lab-secrets/` only; the case file references it by name.
- **Collector language: POSIX sh.** fapolicyd (enforcing on srv1/client2) allows shell scripts but denies untrusted Python (`ftype=%languages trust=0`), so no Python on the hosts.
- **Hosts:** srv1 and client2 (key access). client1 (PAM-only) is **out of scope** for collection in Plan 5; the gap is recorded in the ISO log (decision 3′ is not yet applied to the kit).
- Lab reset between runs: `lab/reset.sh srv1 client2` (re-issues the Kanidm certificate and resyncs clocks).

## Review Focus

1. **The collector leaks a secret** into a report: a token in a process list, a TOTP seed in a journal line, an `Authorization:` header, a reset token in shell history. A redaction test feeds a fixture containing every known secret shape through the redactor, and every real report is scanned. *Task 2, Step 3; Task 6.*
2. **The collector is not really read-only** (e.g. `kanidm` CLI refreshing a token cache, `chronyc` making changes, a `journalctl` vacuum, `sssctl` writing). Before/after hash test on real hosts. *Task 3, Step 4.*
3. **A repair runs without approval, or runs on the wrong host.** The runner refuses without `yes` (and outside test mode) and pins the host named in the case. Unit tests plus one live refusal. *Task 5.*
4. **A repair "succeeds" but the fault persists:** verify must use the finding engine on a **fresh** report, not the repair's own output. If verify fails, undo runs and the case says so. *Task 5, Step 4; Tasks 6–7.*
5. **A finding fires on the wrong evidence** (e.g. `TLS_CERT_EXPIRED` when the host clock is wrong, not the certificate). Rules consult time evidence first; unit tests with a skewed-clock fixture. *Task 1.*

---

## File Structure

| Path | Responsibility |
|---|---|
| `collector/idm-collect` | POSIX sh, read-only; `--user NAME` optional; prints one JSON report on stdout |
| `collector/redact.sed` | redaction rules (used by the collector; mirrored in a test) |
| `engine/__init__.py`, `engine/report.py` | load/validate a report (shape checks), helpers |
| `engine/findings.py` | pure rules: `evaluate(report) -> list[Finding]` |
| `engine/repairs.py` | the allow-list registry, the `Repair` protocol, the runner (precheck/backup/apply/verify/undo, approval) |
| `engine/remote.py` | SSH execution (`run(host, argv, stdin=None)`), argv only, no shell strings |
| `engine/case.py` | case files `cases/<ts>-<slug>/` (symptom, reports, findings, approvals, repair output, timings) |
| `engine/explain.py` | the explainable-response schema for Plan 6 (dataclass + JSON validation only) |
| `engine/cli.py` | `python -m engine collect|findings|repair|scenario` |
| `scenarios/l1.py`, `scenarios/c1.py` | inject / cleanup / expected findings / expected repairs |
| `lab/host/diag-access.sh` + `lab/srv1/45-diag-svcacct.sh` | `diag` user + sudo rule + key on srv1/client2; read-only Kanidm service account for the collector |
| `lab/iso-requirements.md` | the ISO requirements log |
| `tests/test_findings.py`, `test_repairs.py`, `test_redact.py`, `test_case.py`, `test_explain.py` + `tests/fixtures/reports/*.json` | unit tests |

---

### Task 1: Findings engine (pure, unit-tested)

**Files:** Create `engine/__init__.py`, `engine/report.py`, `engine/findings.py`, `tests/test_findings.py`, and fixtures `tests/fixtures/reports/{healthy-client2,healthy-srv1,l1-client2,l1-srv1,c1-srv1,c1-client2,skew-client2}.json`

**Interfaces:**
- `Finding(id: str, component: str, evidence: list[str], severity: str)` (frozen dataclass).
- `evaluate(report: dict) -> list[Finding]`: deterministic and sorted. Rules in Plan 5:
  - `POSIX_PW_MISSING`
  - `UNIXD_OFFLINE`
  - `TLS_CERT_EXPIRED(kanidm)`
  - `ACME_RENEWAL_STOPPED`
  - `TOTP_TIME_SKEW`
  - `SERVICE_DOWN(unit)`
  - `CLIENT_MISSING_CA_ROOT`
- Report shape (produced by Task 2):

```json
{"schema": "idm-report/1", "host": "srv1", "role": "server|client", "collected_at": "…Z", "user": "lab08|null",
 "time": {"offset_s": 0.001, "synced": true, "source": "192.168.100.1"},
 "services": {"kanidmd": "active", "step-ca": "active", "cert-renew-kanidm.timer": "active", "kanidm-unixd": "…"},
 "tls": {"kanidm": {"not_before": "…Z", "not_after": "…Z", "verify": "ok|expired|untrusted|unreachable"}},
 "unixd": {"status": "online|offline|absent"},
 "kanidm_user": {"name": "lab08", "exists": true, "posix": true, "unix_password": false, "primary_credential": true},
 "trust": {"kanidm_root_in_store": true},
 "selinux": {"mode": "Enforcing", "avc_recent": 0}, "errors": []}
```

- [ ] **Step 1: Write the failing tests**, one per rule plus negatives:
  - a healthy fixture gives `[]`;
  - `l1-srv1` gives `POSIX_PW_MISSING`;
  - `c1-srv1` gives `TLS_CERT_EXPIRED(kanidm)` **and** `ACME_RENEWAL_STOPPED`;
  - `c1-client2` (verify=`expired`) gives `TLS_CERT_EXPIRED(kanidm)`;
  - **`skew-client2`** (offset −600 s, cert valid by server time but "expired" by the skewed client clock) gives `TOTP_TIME_SKEW` and **not** `TLS_CERT_EXPIRED` (Review Focus 5);
  - a report with `errors` non-empty yields no finding claimed from the missing section.

  Example:

```python
from engine.findings import evaluate

def ids(r): return [f.id for f in evaluate(r)]

def test_skewed_clock_is_blamed_not_the_certificate(load):
    r = load("skew-client2")
    assert "TOTP_TIME_SKEW" in ids(r) and "TLS_CERT_EXPIRED(kanidm)" not in ids(r)
```
  Run `uv run pytest tests/test_findings.py -q` → Expected: FAIL (no module `engine`).

- [ ] **Step 2: Implement `engine/report.py`** (load + minimal shape check: schema, host, collected_at) and **`engine/findings.py`**:
  - each rule is a small function returning `Finding | None`;
  - `evaluate` runs them in a fixed order;
  - the time rule runs first, and if `abs(offset_s) > 30` the TLS-expiry rule is suppressed with evidence "clock skew makes expiry unreliable";
  - thresholds are module constants.

- [ ] **Step 3: Run → GREEN; commit.**

---

### Task 2: The collector (POSIX sh, read-only, redacted)

**Files:** Create `collector/idm-collect`, `collector/redact.sed`, `tests/test_redact.py`

**Interfaces:**
- `idm-collect [--user NAME]`, run as root via sudo. It prints `idm-report/1` JSON on stdout and exits 0 even when sections fail: failures go into `errors`, never a partial crash.

- [ ] **Step 1: Write the failing redaction test.**
  - Feed `collector/redact.sed`, through `sed -E -f`, a fixture with one sample of every secret shape:
    - the Kanidm reset token `xxxxx-xxxxx-xxxxx-xxxxx`;
    - JWS `eyJ…`;
    - `-----BEGIN … PRIVATE KEY-----` blocks;
    - `otpauth://…secret=…`;
    - `secret=BASE32`;
    - `password=…` / `"password": "…"`;
    - `Authorization: Bearer …`;
    - `TOTP_SECRET=`.
  - Assert every sample is replaced by `[REDACTED]`, and that benign lines (`kanidmd.service active`, a PEM **certificate** header) survive.
  - Run → FAIL (no file).
- [ ] **Step 2: Write `redact.sed`** → GREEN.
- [ ] **Step 3: Write `collector/idm-collect`:**
  - **Structure:** `set -eu`; a `mktemp -d` work dir with `trap 'rm -rf "$W"' EXIT`; each section is a function whose output is captured, redacted, and JSON-escaped by a POSIX `json_str()` (escapes `\`, `"`, control characters).
  - **Sections:**
    - **time:** `chronyc -n tracking`, parsing the last offset and leap status;
    - **services:** `systemctl is-active` for a fixed unit list per role;
    - **TLS:** `openssl s_client` to `idm.kanidm.lab.test:443` (no stdin; `timeout 10`), then `openssl x509 -noout -dates`, plus `openssl verify` against the system trust;
    - **unixd:** `kanidm-unix status` (clients);
    - **Kanidm user** (server role, when `--user` is given): the **read-only** service account token from `/etc/idm-collect/kanidm.token`, via `KANIDM_TOKEN_CACHE_PATH` pointed into `$W`, so the CLI's cache is **not** written to root's home (Review Focus 2). Exact read verbs are confirmed in Task 4;
    - **trust:** grep the lab root's fingerprint in `trust list`;
    - **SELinux:** `getenforce` and the recent AVC count (`ausearch --input-logs`);
    - **errors** collected per section.
  - Stays ≤ 200 KB (journals truncated to the last N lines per unit, counted).
  - `shellcheck -s sh` clean.
- [ ] **Step 4: Commit.**

---

### Task 3: `diag` access on srv1 and client2 (single-command sudo), and a read-only proof

**Files:** Create `lab/host/diag-access.sh` (Mac runner), `lab/client/diag-sudoers` (template)

- [ ] **Step 1: Generate the key.** `~/idm-lab-secrets/diag_ecdsa` (ECDSA P-384).
- [ ] **Step 2: On each host (srv1, client2):**
  - create `useradd -r -m diag` with that key only;
  - install `/usr/local/sbin/idm-collect` (root:root 0755) and label it with `restorecon`;
  - add the sudoers drop-in `diag ALL=(root) NOPASSWD: /usr/local/sbin/idm-collect, /usr/local/sbin/idm-collect --user *` (validated with `visudo -cf`);
  - `diag` has no password; its shell is `/bin/bash` so sudo works over SSH.
  - Add `Host srv1-diag` / `client2-diag` to `~/.ssh/config`.
- [ ] **Step 3: fapolicyd check (enforcing):** run `ssh srv1-diag sudo /usr/local/sbin/idm-collect | python3 -m json.tool | head`. Expected: valid JSON, and 0 new FANOTIFY denials (shell is allowed). If denied, record it (it's an ISO requirement: ship the collector as an RPM) and trust the file with `fapolicyd-cli --file add` as a ruling.
- [ ] **Step 4: Read-only proof** (Review Focus 2).
  - Before and after 3 runs on each host, capture:
    - `find /etc /var/lib/kanidm-unixd /etc/pki/kanidm /root -xdev -type f -newer <marker>` (must be empty);
    - `sha256sum` of `/etc/kanidm/*`, `/etc/nsswitch.conf`, `/etc/pam.d/*`;
    - `systemctl list-units --state=active --no-legend | sha256sum`.
  - Expected: identical, and no new files.
  - Commit the proof output to `lab/plan5/readonly-proof.txt`.
- [ ] **Step 5: Commit.**

---

### Task 4: Read-only Kanidm service account for the collector

**Files:** Create `lab/srv1/45-diag-svcacct.sh`

- [ ] **Step 1: Discover the read verbs.**
  - On srv1 (as idm_admin), find which CLI command shows, **without** privileged reauth:
    - whether a person has a POSIX password (candidates: `kanidm person posix show`, `kanidm person credential status`, `kanidm person get` attributes);
    - account validity.
  - Record exact commands and outputs (redacted) in the ledger. Pick the least-privileged group that allows them (e.g. `idm_people_pii_read`?). Record it as a ruling.
- [ ] **Step 2:** Create service account `idm-collect`, read-only, in that group only. Generate a **read-only** API token (not `--readwrite`) into `~/idm-lab-secrets/idm-collect.token`. Install it on srv1 at `/etc/idm-collect/kanidm.token` (root 0600) via stdin.
- [ ] **Step 3:** Collector test: `ssh srv1-diag sudo /usr/local/sbin/idm-collect --user lab03`. Expected: `kanidm_user` = exists, posix, **unix_password true**, primary_credential true.

  Negative: the same token must **fail** a write (e.g. `kanidm group add-members lab_users lab03`). Proof that it's read-only.
- [ ] **Step 4: Commit.**

---

### Task 5: Repair runner and case files

**Files:** Create `engine/repairs.py`, `engine/remote.py`, `engine/case.py`, `engine/explain.py`, `tests/test_repairs.py`, `tests/test_case.py`, `tests/test_explain.py`

**Interfaces:**
- `Repair` protocol: `id`, `host_role`, `precheck(ctx) -> str|None` (None = OK), `backup(ctx) -> dict`, `apply(ctx)`, `undo(ctx, backup)`, `verify_findings: set[str]` (must be **absent** in a fresh report after apply).
- `run_repair(repair_id, case, host, approve: Callable[[str], bool], remote, collect)`. Behaviour:
  1. unknown id → refuse;
  2. precheck fails → stop;
  3. **approval** (prints what will change, on which host; requires `yes`);
  4. backup;
  5. apply;
  6. **fresh collect + evaluate**;
  7. if any `verify_findings` are still present → **undo** and mark the case FAILED-UNDONE.

  Each step is timed into the case.
- `explain.py`: `ExplainableResponse` fields from sysadmin-agent (analysis, confidence_level/score/justification, evidence, alternative_hypotheses, validation_steps, human_review) **plus** `repair_id` (must be in the allow-list or `null`). `validate(dict) -> list[str]` errors. Used by Plan 6; tested now.

- [ ] **Step 1: Failing tests** with a fake `remote` and fake `collect`:
  - unknown id refused;
  - no approval → nothing applied (Review Focus 3);
  - the wrong host role is refused;
  - verify still finding the fault → undo called, case FAILED-UNDONE (Review Focus 4);
  - success path records the timings;
  - the case directory contains `symptom.txt`, `report-before.json`, `findings.json`, `approval.json`, `repair.log`, `report-after.json`, `timings.json`;
  - `explain.validate` rejects an unknown repair id and a missing confidence.
- [ ] **Step 2: Implement** → GREEN.
  - `remote.run` uses `subprocess.run(["ssh", host, *argv], input=…)`, argv only, never a shell string built from findings.
- [ ] **Step 3: Commit.**

---

### Task 6: C1 end to end (expired Kanidm certificate + stopped renewal)

**Files:** Create `scenarios/c1.py`; repairs `kanidm-cert-renew`, `acme-timer-restore` in `engine/repairs.py`

- [ ] **Step 1: Inject** (on srv1):
  - stop and disable `cert-renew-kanidm.timer`;
  - issue a **short-lived** certificate (`step-cli ca certificate … --not-after 3m` over ACME);
  - restart kanidmd;
  - wait until it expires (a poll loop on the served `notAfter`).
- [ ] **Step 2: Collect** on srv1 and client2 → Expected findings:
  - srv1: `TLS_CERT_EXPIRED(kanidm)` + `ACME_RENEWAL_STOPPED`;
  - client2: `TLS_CERT_EXPIRED(kanidm)`, and possibly `UNIXD_OFFLINE`. Record what actually appears.
- [ ] **Step 3: Repairs:**
  - **`kanidm-cert-renew`:**
    - precheck: the step-ca health is OK;
    - backup: copy `chain.pem`/`key.pem` to `/root/idm-backup/<case>/`;
    - apply: **re-issue over ACME** (Plan 3 finding: `step ca renew` refuses an expired certificate), then try-restart kanidmd;
    - undo: restore the backup files and restart.
  - **`acme-timer-restore`:**
    - backup: the timer's enable state;
    - apply: `systemctl enable --now cert-renew-kanidm.timer`;
    - undo: restore the state.
  - Verify: a fresh collect shows neither finding; the client2 TLS verify is `ok`.
- [ ] **Step 4: Regression:** `python -m engine scenario c1 --runs 3` (`lab/reset.sh srv1 client2` before each; test-mode approval, recorded). Expected: **3/3 green**, with case files and timings.
- [ ] **Step 5: ISO log entries:**
  - the renewal timer must be monitored;
  - the renew-vs-reissue behaviour when expired;
  - the LoadCredential/pre-start copy of the TLS key (D7).
- [ ] **Step 6: Commit.**

---

### Task 7: L1 end to end (no POSIX password)

**Files:** Create `scenarios/l1.py`; repair `kanidm-cred-reset-token` (guided)

- [ ] **Step 1: Inject.** Create `lab08` with password + TOTP and **no** POSIX password (the enrolment REPL without `unix-password`), and add it to `lab_users`. The symptom check `ssh-login.exp lab08 …` → DENIED.
- [ ] **Step 2: Collect** with `--user lab08` on srv1 → `POSIX_PW_MISSING`; on client2 → the user resolves, and the login fails in the journal.
- [ ] **Step 3: Repair `kanidm-cred-reset-token`** (guided, per spec: **the tool never sets a password**):
  - precheck: the user exists and has no unix password;
  - apply: issue a reset token (TTL 1 h) and store it in `~/idm-lab-secrets/lab08.reset-token` (the case references the file name only). Print the user instructions ("run `kanidm person credential use-reset-token <token>`, choose `unix-password`, commit");
  - undo: n/a (issuing a token changes nothing until used). It records "no-op undo".
  - The **lab stands in for the user** by completing the reset with `enrol-user.exp` in unix-password-only mode, a new mode added here. Then verify: a fresh collect has no `POSIX_PW_MISSING`, and `ssh-login.exp lab08` → OK.
- [ ] **Step 4: Regression 3/3** from `golden` (lab08 re-created each run).
- [ ] **Step 5: ISO log entries:**
  - new accounts need a POSIX-password step in the onboarding runbook;
  - the collector's read-only service account and its group.
- [ ] **Step 6: Commit.**

---

### Task 8: The ISO requirements log

**Files:** Create `lab/iso-requirements.md`

- [ ] **Step 1: Seed from Plans 2–4**, one row each: requirement, default the ISO should set, evidence (file/finding), status. Rows include:
  - signed RPMs + an in-ISO repo (fapolicyd trust, gpgcheck);
  - no compilers on servers;
  - `server.toml` 0644 and the TLS key via pre-start copy (D6/D7);
  - CUI umask vs config files (D8);
  - `initgroups` with kanidm (D9);
  - SSH certificate principals = SPN (D10);
  - the SELinux module for the unixd socket (Plan 3, pending the ISSO decision);
  - the step-ca `GODEBUG=fips140=on` note and its MD5 finding;
  - chronyd restart after restore;
  - bind clevis on first real boot and shred `/root/original-ks.cfg`;
  - Secure Boot + PCR 7;
  - `KbdInteractive`/`AuthenticationMethods publickey,keyboard-interactive:pam` (decision 3′);
  - GA tokens host-local in `/var/lib/google-authenticator` (decision 3);
  - the CHP kit identity mode (D-2);
  - pam_kanidm placement (no jump skip);
  - `without-nullok`;
  - the collector shipped as an RPM plus the diag sudo rule;
  - the read-only Kanidm service account.
- [ ] **Step 2:** Add the Plan 5 rows (from Tasks 3, 6, 7).
- [ ] **Step 3: Commit.**

---

### Task 9: Finish

- [ ] **Step 1:** Full suite, shellcheck, secrets scan (including all committed reports and case files).
- [ ] **Step 2:** Final whole-branch review, pre-publication scan, PR.

## Self-review notes
- **Spec coverage:**
  - §5.1 collector (areas used by L1/C1; the DNS and SSH-CA sections are Plan 6 scenarios) → Task 2;
  - redaction → Task 2;
  - access and sudo rule → Task 3;
  - §5.2 findings (a subset) → Task 1;
  - §5.4 repairs `kanidm-cred-reset-token`, `kanidm-cert-renew`, `acme-timer-restore` → Tasks 6–7;
  - §5.5 case file → Task 5;
  - §8 read-only proof and approval → Tasks 3 and 5;
  - success criterion 3 (3× from golden) → Tasks 6–7.
- **Interpreter (§5.3):** deferred to Plan 6 per §7 (M6). Its output schema is defined and tested now (`engine/explain.py`).
- **client1:** excluded from collection (PAM-only) and recorded as an ISO/access gap.
