# Plan 7: Account Expiry, SELinux Labels, SSH CA (L5, L6, C3, C4) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the spec's scenario set: L5 (account expired → `account-unexpire`), L6 (unixd socket mislabelled → `selinux-restorecon`), C3 (user SSH certificate expired → `ssh-user-cert-reissue`), C4 (sshd no longer trusts the SSH CA → `ssh-ca-trust-restore`), each 3× green from golden, plus the Plan 6 deferred minors and an 11-scenario regression.

**Architecture:** Same loop as Plans 5–6. The collector (read-only POSIX sh) gains: the Kanidm account validity window (server), the SSH CA's public-key fingerprint and its **issuance record** for the user (server), sshd's effective `TrustedUserCAKeys` and the fingerprints in that file (client), and a **dry-run** `restorecon -n -v` over a fixed list of identity paths (both). New deterministic findings + runbooks; four new allow-listed repairs; the SSH CA starts **recording what it issues** (public certificates only) so an expired user certificate is visible server-side.

**Tech Stack:** as Plan 6 (Python/uv/pytest, POSIX sh, expect, LM Studio Devstral, Kanidm 1.11.2, OpenSSH CA, SELinux targeted + the lab `kanidm_lab` module).

**Spec:** `docs/superpowers/specs/2026-09-26-idm-diagnostic-lab-design.md` rev 2: §5.1 (SSH CA row, SELinux row, Kanidm server row "valid-from/expire"), §5.2 (`ACCOUNT_EXPIRED`, `SSH_USER_CERT_EXPIRED`, `SSH_CA_NOT_TRUSTED`, `SELINUX_AVC(component)`), §5.4 rows `account-unexpire`, `selinux-restorecon`, `ssh-user-cert-reissue`, `ssh-ca-trust-restore`, §6 rows L5, L6, C3, C4, §8.

## Global Constraints

- All Plan 6 Global Constraints hold (≤ 2k-token findings prompt, allow-list, approval outside test mode, read-only collector, secrets only in `~/idm-lab-secrets`, 3× green from golden, public-repo scan, no web tools, US/EU models).
- **Faillock:** at most **one** failed password login per scenario run (the reset restores the tally). Prefer SSH-certificate probes (a refused public key never reaches PAM).
- **Measured lab facts (2026-09-29)** this plan relies on:
  - `kanidm person validity expire-at <u> now|clear` exists in 1.11.2; expiry is enforced **at once** (lab06: login OK → `expire-at now` → DENIED in 2 s → `clear` → OK). The read-only collector token sees `attrs.account_expire` (a list with one RFC3339 string).
  - lab05 has **no** credentials; use lab06 for L5.
  - Mislabelling `/run/kanidm-unixd` (`chcon -R -t var_run_t`) makes Kanidm logins fail **with no AVC logged** (none even with dontaudit off). `restorecon -n -v -R /run/kanidm-unixd` reports the three wrong labels read-only; `restorecon -R` fixes it; logins work again. The lab module `kanidm_lab` supplies the file context `/var/run/kanidm-unixd(/.*)? → kanidm_unixd_var_run_t`.
  - SSH CA: `/etc/ssh-ca/user_ca` on srv1, fingerprint `SHA256:fnyFGHP/iyOJEEzyd52gwSdf9GJuJZAEnS5z2hxGgmE`; client2 `/etc/ssh/sshd_config.d/10-kanidm.conf` line 5 `TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys` (file holds the same key); `sshd -T` shows `trustedusercakeys /etc/ssh/trusted_user_ca_keys`.
  - lab02's key/cert live on the Mac (`~/idm-lab-secrets/lab02_ecdsa{,.pub,-cert.pub}`); a certificate login is `ssh -i …lab02_ecdsa -o CertificateFile=…-cert.pub lab02@192.168.100.13`. `lab/srv1/sign-user-cert.sh` leaves root-owned `/tmp/<u>-sign*` on srv1 (its trap `rm` lacks sudo), so a second signing fails.

## Spec deviations (decided here, from measurement — review them)

1. **L6 finding:** the spec names `SELINUX_AVC(kanidm_unixd)`. Measured: the mislabel produces **no AVC**, so an AVC-based finding would never fire. The finding is **`SELINUX_LABEL_WRONG(<path>)`** from a read-only `restorecon -n` dry run over a fixed path list. The collector keeps its AVC count as context.
2. **C3 evidence:** a user's certificate lives with the user, not on any server. The SSH CA will **record every certificate it issues** (public data) under `/var/lib/ssh-ca/issued/<user>-cert.pub`, and the server collector reads the newest record. This is also what dc2 needs (row in the ISO log).
3. **`account-unexpire` is guarded:** expiry is usually deliberate (off-boarding). The approval text says so, and the runbook default is `none` (the model may still propose it). Human review is REQUIRED.

## Review Focus

1. **Undoing a deliberate security control:** `account-unexpire` must never be the default suggestion, the approval must say "expiry may be intentional", and it must only clear expiry for the named, validated user.
2. **Relabelling outside the identity paths:** `selinux-restorecon` must only touch the fixed path list, never a path from a report or the model, and must be undoable (record previous labels).
3. **Trusting the wrong CA:** `ssh-ca-trust-restore` must install only a key whose fingerprint equals the pin, must validate the sshd config (`sshd -t`) before reloading, and must restore the previous drop-in if verification fails (never leave sshd unable to start).
4. **Issuing credentials:** `ssh-user-cert-reissue` signs only the user's **registered** public key (never one from a report), with principals `user,user@realm` and a short validity; the private key never leaves the Mac.
5. **Time-based findings with an unknown clock:** `ACCOUNT_EXPIRED` and `SSH_USER_CERT_EXPIRED` must be suppressed when the host clock is skewed or unverified (as `TLS_CERT_EXPIRED` is).

---

## File Structure

| Path | Responsibility |
|---|---|
| `collector/idm-collect` | (modify) `kanidm_user.account_expire/valid_from`; `ssh_ca` (server); `sshd` (client); `selinux.relabel` (both); Plan 6 minors |
| `engine/findings.py` | (modify) `ACCOUNT_EXPIRED`, `ACCOUNT_NOT_YET_VALID`, `SSH_USER_CERT_EXPIRED`, `SSH_CA_NOT_TRUSTED` (+ cross-host fingerprint), `SELINUX_LABEL_WRONG(path)` |
| `runbooks/*.md` | 5 new runbooks |
| `engine/repairs.py` | `AccountUnexpire`, `SelinuxRestorecon`, `SshUserCertReissue`, `SshCaTrustRestore`; SSH-CA helpers |
| `engine/interpret.py`, `engine/cli.py` | (modify) Plan 6 minors: allow-list per finding host role; findings ordered by severity before the 12-cap |
| `lab/srv1/55-ssh-ca-record.sh` | register user public keys + issuance record dir on srv1 |
| `lab/srv1/sign-user-cert.sh` | (modify) record the issued cert; trap cleanup with sudo |
| `lab/trust/ssh-user-ca.sha256` | pinned SSH CA fingerprint |
| `scenarios/l5.py`, `l6.py`, `c3.py`, `c4.py` | scenarios |
| `lab/client/ssh-cert-login.sh` | one certificate login probe (never a password) |
| `lab/plan7/` | read-only proofs, regression report, sample cases |
| `lab/iso-requirements.md` | rows 32+ |

---

### Task 1: Plan 6 deferred minors

**Files:** `collector/idm-collect`, `engine/interpret.py`, `engine/cli.py`, `lab/srv1/sign-user-cert.sh`; tests `tests/test_collector_script.py`, `tests/test_interpret.py`, `tests/test_runner_status.py`.

**Interfaces:** Produces `interpret.order(findings) -> list[Finding]` (severity `error` before `warning`, then id); `cli.allowed_for_findings(fl: dict[str, list[Finding]], reps) -> set[str]` (roles of hosts that **have** findings).

- [ ] **Step 1: Failing tests.**

```python
# tests/test_interpret.py
def test_prompt_keeps_errors_before_warnings_when_capped():
    many = [Finding(f"A_WARN_{i:02d}", "x", ("w",), "warning") for i in range(15)] + [Finding("Z_ERR", "x", ("e",))]
    msgs = interpret.build_messages("s", many, [], ALLOWED)
    assert '"Z_ERR"' in msgs[-1]["content"]
```

```python
# tests/test_runner_status.py
def test_allow_list_only_covers_roles_with_findings():
    from engine.cli import allowed_for_findings
    from engine.findings import Finding
    reps = {"srv1": {"role": "server"}, "client2": {"role": "client"}}
    got = allowed_for_findings({"srv1": [], "client2": [Finding("NSS_ORDER_WRONG", "nss", ("x",))]}, reps)
    from engine.repairs import REGISTRY
    assert got and all(REGISTRY[r].host_role == "client" for r in got)
```

```python
# tests/test_collector_script.py
def test_group_names_are_not_globbed():
    text = SCRIPT.read_text()
    assert "set -f" in text and "timeout 15 id -Gn" in text
```

Run → 3 FAIL.

- [ ] **Step 2: Implement.** `interpret.order = lambda fs: sorted(fs, key=lambda f: (f.severity != "error", f.id))`; `_data` uses `order(findings)[:12]`. `cli.allowed_for_findings` = `interpret.allowed_for({reps[h]["role"] for h, fs in fl.items() if fs})`; `run_scenario` uses it. Collector: `set -f` right after `set -eu` (no globbing anywhere in the script: it never needs it — confirm with `grep -n '\*' collector/idm-collect` that no command relies on a glob), and `$(timeout 15 id -Gn "$user" 2>/dev/null)`. `sign-user-cert.sh`: `trap 'sudo rm -f /tmp/$u-sign*' EXIT`. Suite + shellcheck → green.

- [ ] **Step 3: Commit** `Plan 7 Task 1: Plan 6 minors (severity-ordered prompt cap, per-role allow-list, no globbing + id timeout, sign script cleanup)`.

---

### Task 2: Collector — validity window, SSH CA, sshd trust, SELinux dry run; findings; runbooks

**Files:** `collector/idm-collect`, `engine/findings.py`, `runbooks/{ACCOUNT_EXPIRED,ACCOUNT_NOT_YET_VALID,SSH_USER_CERT_EXPIRED,SSH_CA_NOT_TRUSTED,SELINUX_LABEL_WRONG}.md`, `lab/srv1/55-ssh-ca-record.sh`, `lab/srv1/sign-user-cert.sh`, `lab/trust/ssh-user-ca.sha256`, fixtures, `lab/plan7/readonly-proof-{srv1,client2}.txt`; tests `tests/test_findings.py`, `tests/test_collector_script.py`, `tests/test_runbooks.py`.

**Interfaces (report additions, all optional keys):**
- server `kanidm_user.account_expire: str | null`, `kanidm_user.valid_from: str | null` (RFC3339, first value of the attr list; `null` = not set).
- server `ssh_ca: {"fingerprint": str, "issued": null | {"user": str, "valid_to": str | "forever", "valid_from": str, "principals": [str]}}` (`issued` only with `--user`, from the newest `/var/lib/ssh-ca/issued/<user>-cert.pub` via `ssh-keygen -L`).
- client `sshd: {"trusted_ca_path": str | "none", "trusted_ca_fingerprints": [str]}` (from `sshd -T` and `ssh-keygen -lf` on that file).
- both `selinux.relabel: [{"path": str, "have": str, "want": str}]` from `restorecon -n -v -R` over the **fixed** list `/run/kanidm-unixd /var/cache/kanidm-unixd /var/lib/kanidm-unixd /etc/kanidm /etc/ssh/trusted_user_ca_keys /etc/pki/ca-trust/source/anchors` (paths that don't exist are skipped).
- Findings: `ACCOUNT_EXPIRED` (server; `account_expire <= collected_at`), `ACCOUNT_NOT_YET_VALID` (`valid_from > collected_at`), `SSH_USER_CERT_EXPIRED` (server; `issued.valid_to != "forever"` and `<= collected_at`), `SSH_CA_NOT_TRUSTED` (client; `trusted_ca_path == "none"` or no fingerprints; **cross-host** also when the server's `ssh_ca.fingerprint` is not in the client's list), `SELINUX_LABEL_WRONG(<path>)` one per path. The three time-based ones are **suppressed when `_skewed` or `_clock_unknown`** (Review Focus 5).

- [ ] **Step 1: SSH CA issuance record (lab setup, before the collector can read it).** Create `lab/srv1/55-ssh-ca-record.sh` (runs on srv1 via `lab/srv1/run.sh`): `install -d -m 0755 /var/lib/ssh-ca/issued /var/lib/ssh-ca/keys`. Modify `sign-user-cert.sh` to, after signing, `sudo install -m 0644 /tmp/$u-sign-cert.pub /var/lib/ssh-ca/issued/$u-cert.pub` and `sudo install -m 0644 /tmp/$u-sign.pub /var/lib/ssh-ca/keys/$u.pub` (the registered public key). Pin: `lab/trust/ssh-user-ca.sha256` = `SHA256:fnyFGHP/iyOJEEzyd52gwSdf9GJuJZAEnS5z2hxGgmE`. Run: `lab/srv1/run.sh 55-ssh-ca-record srv1` and `lab/srv1/sign-user-cert.sh lab02 ~/idm-lab-secrets/lab02_ecdsa.pub +8h > ~/idm-lab-secrets/lab02_ecdsa-cert.pub`; check `ssh -n srv1 ls -l /var/lib/ssh-ca/issued /var/lib/ssh-ca/keys`.

- [ ] **Step 2: Failing findings tests** (fixtures: copy `healthy-srv1-lab01.json`/`healthy-client2-lab01.json` into the tests with the new keys added in-test):

```python
def test_expired_account_is_found_and_suppressed_on_a_bad_clock():
    s = pair()[0]; s["kanidm_user"]["account_expire"] = "2026-09-01T00:00:00Z"
    assert "ACCOUNT_EXPIRED" in cids(s)
    s["time"].update(synced=False, offset_s=None)
    assert "ACCOUNT_EXPIRED" not in cids(s)


def test_not_yet_valid_account_is_found():
    s = pair()[0]; s["kanidm_user"]["valid_from"] = "2099-01-01T00:00:00Z"
    assert "ACCOUNT_NOT_YET_VALID" in cids(s)


def test_expired_issued_ssh_cert_is_found():
    s = pair()[0]
    s["ssh_ca"] = {"fingerprint": "SHA256:x", "issued": {"user": "lab01", "valid_from": "2026-09-01T00:00:00Z",
                                                          "valid_to": "2026-09-01T01:00:00Z", "principals": ["lab01"]}}
    assert "SSH_USER_CERT_EXPIRED" in cids(s)
    s["ssh_ca"]["issued"]["valid_to"] = "forever"
    assert "SSH_USER_CERT_EXPIRED" not in cids(s)


def test_client_without_trusted_ca_is_found_and_so_is_a_foreign_ca():
    s, c = pair()
    s["ssh_ca"] = {"fingerprint": "SHA256:good", "issued": None}
    c["sshd"] = {"trusted_ca_path": "none", "trusted_ca_fingerprints": []}
    assert "SSH_CA_NOT_TRUSTED" in cids(c, s)
    c["sshd"] = {"trusted_ca_path": "/etc/ssh/trusted_user_ca_keys", "trusted_ca_fingerprints": ["SHA256:other"]}
    assert "SSH_CA_NOT_TRUSTED" in cids(c, s)
    c["sshd"]["trusted_ca_fingerprints"] = ["SHA256:good"]
    assert "SSH_CA_NOT_TRUSTED" not in cids(c, s)


def test_each_wrong_label_is_its_own_finding():
    c = pair()[1]
    c["selinux"]["relabel"] = [{"path": "/run/kanidm-unixd", "have": "var_run_t", "want": "kanidm_unixd_var_run_t"},
                               {"path": "/run/kanidm-unixd/sock", "have": "var_run_t", "want": "kanidm_unixd_var_run_t"}]
    got = cids(c)
    assert "SELINUX_LABEL_WRONG(/run/kanidm-unixd)" in got and "SELINUX_LABEL_WRONG(/run/kanidm-unixd/sock)" in got
```

Add the 5 bases to `BASES` in `tests/test_runbooks.py` and `ssh-user-cert-reissue`, `ssh-ca-trust-restore`, `selinux-restorecon` to `FUTURE_REPAIRS`. Run → FAIL.

- [ ] **Step 3: Implement the rules** in `engine/findings.py` (reuse `_t`, `_skewed`, `_clock_unknown`; the cross-host SSH-CA check goes in `evaluate` next to `cache_stale` as `ca_not_trusted_cross(server, client)`; the single-host part (`none` or empty list) is a normal rule). Runbooks (default repairs): `ACCOUNT_EXPIRED` → `none` ("Expiry is usually deliberate (off-boarding, a contractor's end date). Confirm with the account owner's manager before re-enabling; the repair `account-unexpire` exists for mistakes."), `ACCOUNT_NOT_YET_VALID` → `none`, `SSH_USER_CERT_EXPIRED` → `ssh-user-cert-reissue`, `SSH_CA_NOT_TRUSTED` → `ssh-ca-trust-restore`, `SELINUX_LABEL_WRONG` → `selinux-restorecon` ("Files carry the wrong SELinux type, so confined services are refused silently: denials for this are not audited, so there may be no AVC at all. restorecon puts back the labels the policy defines."). Suite → green.

- [ ] **Step 4: Collector sections** (marker-block tests like Plan 6 for the parsers): `validity_json` (extract the first value of `account_expire` / `account_valid_from` from the REST JSON, `null` when absent; only `[0-9TZ:.+-]` allowed, else `null` + error); `ssh_ca` (server: `ssh-keygen -lf /etc/ssh-ca/user_ca.pub | awk '{print $2}'`; with `--user`, parse `ssh-keygen -L -f /var/lib/ssh-ca/issued/$user-cert.pub`: `Valid: from A to B` → `valid_from`, `valid_to` (`forever` when "forever"), principals lines); `sshd` (client: `sshd -T 2>/dev/null | awk '$1=="trustedusercakeys"{print $2}'`, then `ssh-keygen -lf` on that path, one fingerprint per key); `relabel` (both: `restorecon -n -v -R <existing paths>` lines `Would relabel P from A to B` → objects, types only: strip `system_u:object_r:` and `:s0`). Parser tests with real line shapes:

```
Would relabel /run/kanidm-unixd/sock from system_u:object_r:var_run_t:s0 to system_u:object_r:kanidm_unixd_var_run_t:s0
        Valid: from 2026-09-29T05:00:00 to 2026-09-29T06:01:42
```

(ssh-keygen prints local time without zone: convert with `date -u -d "<value>" +%Y-%m-%dT%H:%M:%SZ` on the host, as `iso()` already does.) `shellcheck -s sh` clean.

- [ ] **Step 5: Install, prove read-only, capture fixtures, re-take golden.** `lab/host/diag-access.sh srv1 client2`; `lab/tools/readonly-proof.sh srv1 --user lab02` and `client2 --user lab02` → no file changes (extend the hashed set with `/var/lib/ssh-ca/*` and `/etc/ssh/sshd_config.d/*`); save to `lab/plan7/`; capture `tests/fixtures/reports/healthy-{srv1,client2}-lab02.json`, secrets-scan them, and assert both give `[]` findings as a pair (new test). Then reset → reinstall → findings `[]` → re-take golden (as in Plan 6).

- [ ] **Step 6: Commit** `Plan 7 Task 2: collector validity/SSH CA/sshd/SELinux dry run + findings + runbooks; SSH CA issuance record; golden re-taken`.

---

### Task 3: L5 — expired account → `account-unexpire`

**Files:** `engine/repairs.py`, `scenarios/l5.py`, tests.

- [ ] **Step 1: Failing tests:** `AccountUnexpire` (server) refuses invalid user names (precheck, before any call); `describe()` contains "expiry may be intentional"; `apply` runs `admin_login` then exactly `kanidm person validity expire-at <user> clear -D idm_admin` on `ctx.host`; `verify_present` requires `kanidm_user.account_expire is None` (and `exists`).
- [ ] **Step 2: Implement** (pattern of `KanidmCredResetToken`: `stage(ctx)`, `admin_login(ctx)`; backup records the current expiry string so `undo` can put it back with `expire-at <user> <that value>`).
- [ ] **Step 3: Scenario** `scenarios/l5.py`: `USER="lab06"`, `EXPECT={"srv1": {"ACCOUNT_EXPIRED"}}`, `HOSTS=["srv1", "client2"]`, `REPAIRS=[("srv1", "account-unexpire")]`, `PARAMS={"user": "lab06"}`; `inject`: `stage`, `admin_login`, `expire-at lab06 now`, then **one** password probe that must be an explicit `RESULT: DENIED` (Plan 5 L1 `probe()` pattern); `final_probe`: posix login OK.
- [ ] **Step 4: Live 3×.** Record whether the model proposes `account-unexpire` or null (either is acceptable: runbook default is none). Note: `agrees` is computed against `REPAIRS`; for L5 record agreement but do not treat a null answer as wrong — adjust `run_scenario`'s `agrees` to accept `None` when the scenario sets `MODEL_MAY_DECLINE = True`.
- [ ] **Step 5: ISO row** `| 32 | Accounts | account-expiry changes must go through an approved change (re-enabling is a security decision); decide who may approve account-unexpire | Plan 7 L5 | D |`. Commit.

---

### Task 4: L6 — unixd socket mislabelled → `selinux-restorecon`

**Files:** `engine/repairs.py`, `scenarios/l6.py`, tests.

- [ ] **Step 1: Failing tests:** `SelinuxRestorecon` (client) `PATHS` constant = the collector's fixed list; `apply` runs `restorecon -R -v` on **only** the paths from the fresh report's `relabel` entries that are **inside** `PATHS` (a report path outside the list → precheck refuses); `backup` records `ls -dZ` of each path to be changed; `undo` re-applies the recorded contexts with `chcon`; `verify_present` requires `selinux.relabel == []`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Scenario** `scenarios/l6.py`: `USER="lab01"`, `EXPECT={"client2": {"SELINUX_LABEL_WRONG(/run/kanidm-unixd)"}}`, `REPAIRS=[("client2", "selinux-restorecon")]`; `inject`: `sudo chcon -R -t var_run_t /run/kanidm-unixd`; `final_probe`: posix login for lab01 OK (no probe before the repair: a failed login would count toward faillock).
- [ ] **Step 4: Live 3×.**
- [ ] **Step 5: ISO rows** `| 33 | SELinux | ship the unixd socket file context in the ISO's policy module (the lab module kanidm_lab provides it) and run restorecon on the identity paths at first boot; a mislabel fails logins with **no AVC** (dontaudited), so monitor `restorecon -n` output, not AVCs | Plan 7 L6 + measurement | R |`. Commit.

---

### Task 5: C3 — user SSH certificate expired → `ssh-user-cert-reissue`

**Files:** `engine/repairs.py`, `scenarios/c3.py`, `lab/client/ssh-cert-login.sh`, tests.

- [ ] **Step 1: Probe script** `lab/client/ssh-cert-login.sh USER [HOST]` (Mac): one `ssh -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -i ~/idm-lab-secrets/USER_ecdsa -o CertificateFile=~/idm-lab-secrets/USER_ecdsa-cert.pub USER@HOST id -un`, prints `RESULT: OK <name>` or `RESULT: DENIED`. shellcheck.
- [ ] **Step 2: Failing tests:** `SshUserCertReissue` (server) signs **only** `/var/lib/ssh-ca/keys/<user>.pub` (the registered key) with `-n <u>,<u>@idm.kanidm.lab.test -V +1h`, records to `/var/lib/ssh-ca/issued/<u>-cert.pub`; refuses (precheck) when no registered key exists or the user name is invalid; `wait_for_user` in lab stand-in mode copies the new certificate (public) to `~/idm-lab-secrets/<u>_ecdsa-cert.pub`, otherwise asks the operator to deliver it; `verify_present` requires `ssh_ca.issued.valid_to` in the future.
- [ ] **Step 3: Implement** (signing command runs on `ctx.host` as `sudo sh -c` with the validated user name only; the Mac never sends key material).
- [ ] **Step 4: Scenario** `scenarios/c3.py`: `USER="lab02"`, `EXPECT={"srv1": {"SSH_USER_CERT_EXPIRED"}}`, `REPAIRS=[("srv1", "ssh-user-cert-reissue")]`, `PARAMS={"user": "lab02", "lab_standin": True}`; `inject`: sign lab02's registered key with `-V -2m:-1m` (already expired), record it, copy it to the Mac, then `ssh-cert-login.sh lab02` must print `RESULT: DENIED`; `final_probe`: `RESULT: OK`.
- [ ] **Step 5: Live 3×. ISO row** `| 34 | SSH CA | the SSH CA records every certificate it issues (public) and registers each user's public key; short validity + a renewal path users can run themselves | Plan 7 C3 | R |`. Commit.

---

### Task 6: C4 — sshd lost `TrustedUserCAKeys` → `ssh-ca-trust-restore`

**Files:** `engine/repairs.py`, `scenarios/c4.py`, tests.

- [ ] **Step 1: Failing tests:** `SshCaTrustRestore` (client): precheck fetches `/etc/ssh-ca/user_ca.pub` from `srv1` and refuses unless its fingerprint equals `lab/trust/ssh-user-ca.sha256`; `backup` copies `/etc/ssh/sshd_config.d/10-kanidm.conf` and `/etc/ssh/trusted_user_ca_keys`; `apply` (one root script, key via **stdin**): write the key file 0644 + `restorecon`, add `TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys` to `10-kanidm.conf` if absent, **`sshd -t` must pass before** `systemctl reload sshd` (else exit non-zero → the runner undoes); `undo` restores both files, `sshd -t`, reload; `verify_present` requires the pinned fingerprint in `sshd.trusted_ca_fingerprints`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Scenario** `scenarios/c4.py`: `USER="lab02"`, `HOSTS=["srv1", "client2"]`, `EXPECT={"client2": {"SSH_CA_NOT_TRUSTED"}}`, `REPAIRS=[("client2", "ssh-ca-trust-restore")]`; `inject`: re-sign a **valid** lab02 cert (the C3 helper, `+1h`) so the probe tests trust, not expiry; then `sed -i '/^TrustedUserCAKeys/d' /etc/ssh/sshd_config.d/10-kanidm.conf && sshd -t && systemctl reload sshd`; probe → `RESULT: DENIED`; `final_probe` → `RESULT: OK`.
- [ ] **Step 4: Live 3×. ISO row** `| 35 | sshd | TrustedUserCAKeys in a drop-in the ISO owns, the key file pinned by fingerprint; config-management drift check with sshd -T | Plan 7 C4 | R |`. Commit.

---

### Task 7: Regression (11 scenarios × 3) and finish

- [ ] **Step 1:** `regress.DEFAULT` += `l5, l6, c3, c4`; `IDM_TEST_APPROVE=1 uv run python -m engine regress --runs 3 --out lab/plan7/regression-<date>.md` → **11 of 11 green in every run** (≈ 70 min). Curate one case per new scenario into `lab/plan7/cases/` after a secrets scan.
- [ ] **Step 2:** Suite, shellcheck, secrets and pre-publication scans; final whole-branch review (most capable model) with this plan's Review Focus; fix Critical/Important test-first; confirmation regression ×1; PR.

## Self-review notes
- **Spec coverage:** §5.1 SSH CA row (fingerprint consistency, user cert validity/principals) → Task 2 (+ issuance record, deviation 2); SELinux row (`getenforce`, AVCs, labels) → Task 2 (dry-run relabel, deviation 1); Kanidm valid-from/expire → Task 2; §5.2 ids → Task 2; §5.4 four repairs → Tasks 3–6; §6 L5/L6/C3/C4 → Tasks 3–6; §8 3× green → Tasks 3–7.
- **Not covered (and why):** `ACCOUNT_SOFTLOCKED` (spec §5.2 example id, no §6 scenario) — Plan 8 if wanted; the unixd/sshd journals from §5.1 (no scenario needs raw journals; the model must not see them anyway).
