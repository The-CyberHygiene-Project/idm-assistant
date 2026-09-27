# Identity Diagnostic Assistant — Lab, Probe, and Collector (Parts A–C)

**Date:** 2026-09-26 · **Status:** awaiting user review · **Owner:** D. Shannon (System Owner / ISSO)
**Related:** `DIWAI-MFR-2026-08-20` (Local Assistant Viability), RAG library (`~/rag-library`)

## 1. Purpose

Build and **prove**, in an isolated lab, the diagnostic loop for the highest-pain area of
system administration: **Linux identity (FreeIPA / 389-ds)**, starting with
**logins & MFA** and **certificates**.

> **Symptom → "here's what's going on" → "let's confirm it" → targeted diagnostics →
> approved repair → verified → recorded.**

This is the first slice of a larger system (five parts, A–E). This spec covers
**A (model probe), B (lab), and C (collector + playbooks)**, run **end to end from the
command line**. The browser workbench (D) and the separate sysadmin knowledge library
(E) follow once this works.

### Success criteria
1. Each of the six lab faults (§6) is **injected → detected by the collector → explained
   correctly → repaired by an approved ticket → verified**, from a clean snapshot, in a
   repeatable run.
2. The model probe produces a **measured** answer to MFR open actions #2 and #4: which
   local model, if any, reliably interprets findings and calls tools at realistic prompt
   sizes. That answer becomes the **acceptance criterion for buying the in-boundary
   compliance server**.
3. Nothing in development touches dc1, the CyberInaBox boundary, or CUI.

### Constraints (from the user)
- **No connection to dc1** during development. The Mac cannot reach the Linux
  environment. The end state is a **new compliance server inside dc1's boundary**, so
  the code must be portable to it.
- **No web tools** in the local AI environment; no internet egress from lab machines.
- **aero** (the lab host) stays at the user's **standard workstation build**:
  FIPS, SELinux enforcing, RHEL **NIST 800-171 (CUI)** hardening, `sudo` requires a
  password. Deviations are reported, never "fixed" unasked; **no NOPASSWD** on aero.
- **Accessibility:** minimal typing on aero. Every privileged step is a staged script
  started with `sudo sh <name>`; files move from the Mac with `curl -o <name>
  192.168.100.2/<name>` (no port number, no pipe characters).
- Model origin: US/EU models only (no PRC-origin models).

## 2. Architecture

```
 Mac Studio (dev stand-in for the future compliance server)
   ├─ LM Studio (local model, :1234, localhost only)
   ├─ idm-assistant/            this repo
   │    probe/        A  model probe
   │    lab/          B  kickstarts, host-prep scripts, fault injectors
   │    collector/    C  read-only collector (runs on IPA hosts)
   │    engine/       C  findings rules, interpreter, repair runner
   │    runbooks/     C  playbooks (symptom → checks → repairs)
   └─ en0 192.168.100.2 ──── direct cable ──── aero enp49s0 → br-lab 192.168.100.1
                                                  KVM/libvirt
                                                  ├─ ipa1    192.168.100.10  (IPA + CA + DNS)
                                                  ├─ ipa2    192.168.100.11  (replica + CA + DNS)
                                                  └─ client1 192.168.100.12  (SSSD client)
```

- **Design principle (from MFR F-6/F-9):** *code runs the loop, the model interprets.*
  Checks, parsing and repairs are deterministic code. The model receives a **short
  findings summary** (target ≤ 2k tokens per call, fresh context per call) and returns
  an explanation plus the **id** of a proposed repair from an allow-list. It never
  writes shell commands and never runs anything.
- **Portability:** the Mac plays the role of the future compliance server. It reaches
  lab hosts over SSH exactly as that server would reach dc1 from inside the boundary.

## 3. Part A — Model probe (Mac only; can start immediately)

`probe/` drives LM Studio's OpenAI-compatible API. It is repeatable, with **n ≥ 20 per
point**.

1. **Tool-call reliability vs prompt size** (repeats MFR F-6 on this host). A fixed
   five-tool schema, with padding context at **1k / 4k / 8k / 15k / 25k** tokens. Score
   = the first response is a *structured* tool call with a **valid tool name and a
   schema-valid argument object**. Per MFR correction #2, each tool is validated
   against **its own** schema, never one hard-coded field.
2. **Interpretation quality.** Twelve golden cases: a findings JSON taken from the lab
   (§6) plus the expected cause and repair id. Score = the cause keywords are present,
   the correct repair id is chosen, and no invented clause, command or fact appears
   (checked against the input).
3. **Candidates** (all permitted origin):
   - Gemma 4 26B A4B (MLX 4-bit, installed)
   - Devstral Small 2 (4-bit, installed)
   - **Llama 3.3 70B Instruct (4-bit MLX, ~40 GB)**: to download; tested alone, with no
     other model loaded.
4. **Output:** `probe/results/<date>.md`, with a table per model, raw logs kept, and
   the machine state (other models loaded, memory pressure) recorded for each run.
   Runs happen only when the user isn't using LM Studio.

**Acceptance bar (proposed):** ≥ 90% structured tool calls at 15k tokens **and** ≥ 10/12
interpretation cases. A model that meets it is the compliance-server sizing target. If
none does, the architecture falls back to *model interprets only, code does all tool
calling*. That already is the design of Part C, so C succeeds either way.

## 4. Part B — The lab on aero

### 4.1 Host preparation (staged scripts, run on aero as `sudo sh <name>`)
| Script | Does | Verifies |
|---|---|---|
| `b1-media` | copies the Rocky 9.8 DVD ISO (fetched and **checksum-verified on the Mac**) to `/data/iso/`, loop-mounts it, and defines a **local-only dnf repo** (BaseOS + AppStream) | `dnf repolist` shows only the local repo in use |
| `b2-kvm` | installs `qemu-kvm libvirt virt-install` from the local repo and enables `virtqemud` | `virt-host-validate` passes the KVM checks |
| `b3-storage` | creates `/data/libvirt/images`, labels it `virt_image_t` (`semanage fcontext` + `restorecon`), and makes it the default libvirt pool | the pool is active; `ls -Z` shows the label |
| `b4-net` | creates bridge **`br-lab`** on `enp49s0` with 192.168.100.1/24 via `nmcli`, applied as one step (a fallback timer restores the old profile if the link drops) | the Mac can ping 192.168.100.1 again |
| `b5-time` | makes aero's `chronyd` **serve time to 192.168.100.0/24** (`local stratum 10`), so the lab has one consistent clock without internet. aero's own RTC setting is reported and left unchanged | a VM can sync to 192.168.100.1 |
| `b6-scap-report` | runs `oscap` with the **cui** profile in **report-only** mode | an HTML report is copied back to the Mac |

Every script starts with **`--check`** (dry run) and is idempotent.

### 4.2 Lab VMs (built by kickstart; no clicking)
| VM | vCPU | RAM | Disk (qcow2, thin) | Role |
|---|---|---|---|---|
| ipa1 | 4 | 8 GB | 40 GB | FreeIPA server + CA + integrated DNS (first master) |
| ipa2 | 4 | 6 GB | 40 GB | replica with CA + DNS (for renewal-master and failover cases) |
| client1 | 2 | 2 GB | 20 GB | enrolled client (SSSD, PAM, OTP logins) |

The total is 16 GB of aero's 30 GB, so there's headroom for the host and later scenarios.

- **Domain / realm:** `idm.lab.test` / `IDM.LAB.TEST` (the reserved `.test` TLD, so it
  can never collide with a real domain).
- **Kickstart:** the `fips=1` boot argument, the OpenSCAP **cui** profile applied at
  install (`%addon com_redhat_oscap`), SELinux enforcing, a static IP on `br-lab`,
  chrony pointed at 192.168.100.1, packages only from the local DVD repo, and no
  internet route.
- **IPA install:** unattended `ipa-server-install` (ipa1), `ipa-replica-install --setup-ca
  --setup-dns` (ipa2), `ipa-client-install` (client1). Admin credentials are generated
  on the Mac and stored in the Mac keychain, never in the repo.
- **Test data:** five lab users (two with OTP tokens), one host group, HBAC and sudo
  rules like a typical build. All fictitious.
- **Golden snapshots:** `golden` taken after install + data. Every scenario starts with
  `lab reset` (revert all three).
- **Diagnostic account:** an IPA **`diag-reader`** role (read-only permissions for
  users, lockout status, OTP tokens, certificates). The collector runs as a local
  `diag` user whose **only** sudo right is to run the root-owned collector:
  `diag ALL=(root) NOPASSWD: /usr/local/sbin/idm-collect`. That is acceptable in the
  lab; **whether dc1 permits the same narrowly scoped rule is an ISSO decision**,
  recorded in §9.

## 5. Part C — Collector, findings, interpreter, repairs

### 5.1 Collector (`collector/idm-collect`, POSIX sh, read-only)
It runs on an IPA server or client. It writes **one JSON report** (with each section's
raw text included) and prints its path. It **never changes state**.

| Area | Commands |
|---|---|
| Health | `ipa-healthcheck --output-type json --failures-only` (servers), `ipactl status` |
| Certificates | `getcert list` (parsed: status, CA, expiry, key/cert paths), expiry of the httpd/LDAP/KDC/PKI certs via `openssl x509 -enddate`, the healthcheck `ipahealthcheck.ipa.certs` / `dogtag` sources |
| Logins & MFA | `sssctl domain-status`, `sssctl config-check`, `faillock --user <u>`, `ipa user-status <u>` and `ipa user-show <u> --all` (lockout, `krbloginfailedcount`, auth types), `ipa otptoken-find --owner <u>`, `authselect current` |
| SELinux | `getenforce`, `ausearch -m avc -ts recent` (denials only), `ls -Z` for known auth paths |
| Kerberos & time | `chronyc tracking`, clock offset vs 192.168.100.1, `klist -k` (keytab principals, no keys), recent `krb5kdc` "clock skew" lines |
| Logs | the last N lines of `journalctl` for `sssd`, `krb5kdc`, `ipa-otpd`, `dirsrv@*`, `httpd`, `pki-tomcatd@*`, filtered to warnings and errors |
| Host | `df -h`, `free -m`, failed systemd units, uptime |

**Redaction (mandatory, before the file is written):** password hashes, keytab key
material, private keys, OTP secrets, and any line matching a configurable deny-list are
removed. Usernames and hostnames are kept in the lab. For dc1 a **pseudonymization
option** is included (and is an ISSO decision).

**Parameters:** `--user <name>` (focus a login case) and `--since <minutes>`. The
report is capped at about 200 KB.

### 5.2 Findings engine (`engine/findings.py`, deterministic)
It parses the report into **findings**: `{id, severity, summary, evidence[]}`, such as
`CERT_EXPIRING(days=5, nickname=…)`, `CERT_EXPIRED`, `CA_SUBSYSTEM_EXPIRED`,
`USER_LOCKED_IPA`, `USER_LOCKED_FAILLOCK`, `OTP_TOKEN_DISABLED`, `SELINUX_AVC(auth path)`,
`SSSD_OFFLINE`, `CLOCK_SKEW(seconds)`, `SERVICE_DOWN(name)`. Every rule is unit-tested
against captured lab reports.

### 5.3 Interpreter (`engine/interpret.py`)
It sends the model **only**: the user's symptom text (or text read from a screenshot),
the findings list (not raw logs), and the matching runbook excerpt. The prompt is
≤ 2k tokens and each call starts a fresh context. It asks for:
1. **What's going on:** plain-language explanation, citing finding ids.
2. **Confirmation:** which evidence supports it, and what would rule it out.
3. **Next step:** either one extra read-only check (from a fixed list) or one
   **repair id** from the allow-list.

The response is JSON that is validated. An invalid or unknown repair id is rejected
and shown as "model unsure". The system then falls back to the runbook's default
recommendation.

### 5.4 Repairs (`engine/repairs/`, allow-listed)
Each repair has five parts, run in this order: **precheck → backup → apply → verify →
undo**. It runs over SSH via `sudo`, only after the user types `y`, and every step is
logged to the case file.

| Repair id | Apply | Verify | Undo / backup |
|---|---|---|---|
| `ipa-user-unlock` | `ipa user-unlock <u>` | `ipa user-status` shows 0 failures | none needed |
| `faillock-reset` | `faillock --user <u> --reset` | `faillock` is clean | none needed |
| `selinux-restorecon` | `restorecon -Rv <path>` | the file context matches policy; no new AVC | the prior contexts are saved to the case file |
| `sssd-refresh` | `sss_cache -E; systemctl restart sssd` | `sssctl domain-status` is online; `id <u>` resolves | none needed |
| `time-resync` | `chronyc makestep` | offset < 1 s; `kinit` works | none needed |
| `cert-resubmit` | `getcert resubmit -i <id>` | status MONITORING; new expiry | the old cert/key are copied first |
| `ipa-cert-fix` | `ipa-backup` first, then `ipa-cert-fix` | healthcheck certificate sources are clean | restore from `ipa-backup` |

### 5.5 Case file
Each case is `cases/<timestamp>-<slug>/`. It holds the symptom, the reports, the
findings, the model's exchanges (prompt and response), approvals, and the output of
each repair step. It is the audit record, and it doubles as the **hand-off brief for
Claude Code** when escalating.

## 6. Scenarios (fault injection → expected outcome)
Each has `lab/faults/<id>.sh` (inject, run from the Mac over SSH) and an expected
`{finding ids, repair id}`.

| Id | Inject | Expected finding | Expected repair |
|---|---|---|---|
| **L1** | wrong OTP entered past the lockout threshold for `user2` | `USER_LOCKED_IPA` and/or `USER_LOCKED_FAILLOCK` | `ipa-user-unlock` (+ `faillock-reset`) |
| **L2** | mislabel an auth file on client1 (`chcon -t user_home_t` on a file PAM must read) and attempt a login (the **dc1 MFA lockout** pattern) | `SELINUX_AVC` | `selinux-restorecon` |
| **L3** | stop network reachability from client1 to both IPA servers, then restore it with a stale cache | `SSSD_OFFLINE` | `sssd-refresh` |
| **L4** | move client1's clock +10 min (and stop chronyd) | `CLOCK_SKEW` | `time-resync` |
| **C1** | issue a short-lived service cert via certmonger, then advance time past its expiry | `CERT_EXPIRED` / `CERT_EXPIRING` | `cert-resubmit` |
| **C2** | advance the whole IPA server clock past the CA subsystem cert expiry (the classic "IPA won't start after 2 years") | `CA_SUBSYSTEM_EXPIRED`, `SERVICE_DOWN(pki-tomcatd)` | `ipa-cert-fix` |

A **scenario runner** (`lab/run <id>`) performs reset → inject → collect → findings →
interpret → (auto-approve in test mode only) repair → verify. It records pass/fail for
each stage. Running all six in a row gives the lab's **regression report**.

## 7. Build order (milestones)

| M | Deliverable | User action |
|---|---|---|
| M0 | repo skeleton; probe scripts; probe results for the two installed models | none (runs when LM Studio is idle) |
| M1 | Rocky 9.8 DVD downloaded + verified on the Mac; host-prep scripts `b1`–`b6` | run 6 × `sudo sh <name>` on aero |
| M2 | kickstarts; ipa1, ipa2 and client1 built; golden snapshots | one `sudo sh b7-build-lab` (long, unattended) |
| M3 | collector + findings + repairs for **C1 and L1** end to end | none |
| M4 | L2–L4, C2; interpreter wired in; the scenario runner's regression report | none |
| M5 | probe re-run incl. Llama 3.3 70B; **compliance-server acceptance criteria** written up | approve the 40 GB download |

## 8. Testing
- **Unit:** findings rules against captured reports; redaction (secrets never appear);
  the interpreter's JSON validation (unknown repair id rejected); the repair runner's
  order (verify runs after apply, undo on verify failure).
- **Integration:** the scenario runner in the lab. Each scenario is green from `golden`
  three times in a row before it counts.
- **Non-negotiables:** the collector changes no state (checked by comparing
  before/after `ipa-healthcheck` and file hashes in the lab); no repair runs without
  approval outside test mode.

## 9. Decisions recorded, and decisions deferred to the ISSO
- **Recorded:** no internet for aero or the VMs (a local DVD repo instead); lab realm
  `IDM.LAB.TEST`; the model never emits shell; allow-listed repairs only.
- **Deferred (ISSO):**
  1. May a narrowly scoped `NOPASSWD` rule for a root-owned, read-only collector exist
     on dc1?
  2. Is pseudonymization of usernames/hosts required in reports on the compliance
     server?
  3. Case-file retention and audit-log placement (AU family).
  4. Hardware of the compliance server, decided **by** the M5 probe results.

## 10. Out of scope (this slice)
The browser workbench (D); the sysadmin RAG library (E); directory/replication and
DNS/service scenarios; any access to dc1; Thunderbolt networking; automatic (unapproved)
repairs.
