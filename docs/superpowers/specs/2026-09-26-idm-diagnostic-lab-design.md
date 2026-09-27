# Identity Diagnostic Assistant: dc2-Stack Lab, Probe, and Collector (Parts A–C)

**Date:** 2026-09-26 (rev 2: retargeted from FreeIPA to the dc2 stack) · **Status:** APPROVED by the user 2026-09-26 (incl. passwordless sudo on aero as a recorded lab deviation)
**Owner:** D. Shannon (System Owner / ISSO)
**Related:** ADR 0001 *Replace FreeIPA with four independent identity components* (Accepted
2026-08-14; dc2 only); dc2 `TURNOVER.md`; `DIWAI-MFR-2026-08-20` (Local Assistant Viability)

## 1. Purpose

Build and **prove**, in an isolated FIPS lab, the diagnostic loop for the **dc2 identity
stack** defined by ADR 0001:

| Function | Component |
|---|---|
| Authentication / identity (PAM/NSS via `kanidm_unixd`) | **Kanidm** |
| TLS / ACME (internal PKI) | **step-ca** |
| SSH certificate authority | **separate SSH CA** (OpenSSH `ssh-keygen -s`, its own key and unit) |
| DNS | **standalone BIND** |

> **Symptom → "here's what's going on" → "let's confirm it" → targeted diagnostics →
> approved repair → verified → recorded.**

FreeIPA and 389-ds are **out of scope**. They were set aside for complexity, and dc1 gets
no playbooks (user decision).

The lab also answers two of ADR 0001's **blocking** open questions, as an
**independent cross-check**:
- **Q1:** can `kanidm_unixd` (and Kanidm generally) be built and packaged for Rocky 9,
  **offline**?
- **Q2:** does Kanidm operate correctly on a **FIPS-enabled** Rocky host, and which of
  its cryptographic operations fall outside the OS FIPS provider?

It also gives dc2 the disposable "lab capacity" and "client estate" that TURNOVER lists
as gaps, and it produces **operational data for ADR Q4**: every case is timed and logged.

### Success criteria
1. Kanidm is built, packaged (RPMs) and installed **offline on FIPS Rocky 9.8**, with
   every step, defect and workaround recorded (Q1 report).
2. A written **FIPS behaviour report** (Q2): what works, what fails, and which operations
   use crypto outside the OS FIPS module. The compliance judgment is the ISSO's.
3. Each lab scenario (§6) is **injected → detected → explained → repaired → verified**
   from a clean snapshot, three times in a row.
4. The model probe gives a measured answer to MFR open actions #2/#4, which becomes the
   compliance-server acceptance criterion.
5. Nothing touches dc1, dc2, the CyberInaBox boundary, CUI, or the internet.

### Constraints
- **aero has no network except the lab cable.** Wi-Fi is off (verified 2026-09-26). All
  inputs are fetched on the Mac, checksum or GPG verified there, then carried over the
  cable.
- **aero is a disposable lab asset** (user, 2026-09-26): it may be wiped or reconfigured
  at will. **Fidelity settings stay** because they make the lab behave like dc2: FIPS,
  SELinux enforcing, the 800-171 (CUI) profile. **Lab-convenience changes are allowed and
  recorded in `lab/aero-deviations.md`**, for example passwordless `sudo` for `itadmin`
  (so the Mac can drive setup without typing on aero) and RTC in UTC. aero holds no CUI
  and has no network except the lab cable.
- **Independent cross-check of Jeff's acceptance test.** The lab's Kanidm build notes live
  **only in this repo** (`lab/adr0001-*.md`), never in the dc2 repository documentation,
  until Jeff has completed his documentation-only build-and-package.
- **Lab domain is throwaway:** `kanidm.lab.test` (the reserved `.test` TLD). Kanidm's
  domain/origin is a one-way door in production; in the lab it is reset freely. This
  says nothing about DC20's future domain.
- **No web tools** in the local AI environment. Models are US/EU origin only.
- **Accessibility:** minimal typing on aero. With passwordless sudo approved, the Mac runs
  host-prep steps over SSH. Otherwise they're staged scripts run as `sudo sh <name>`, with
  files fetched via `curl -o <name> 192.168.100.2/<name>` (no port, no pipes).

## 2. Architecture

```
 Mac Studio (dev stand-in for the future in-boundary compliance server)
   ├─ LM Studio (localhost only) · idm-assistant repo (probe/ lab/ collector/ engine/ runbooks/)
   ├─ offline input store: Rocky 9.8 DVD ISO, Kanidm source + vendored crates,
   │  step/step-ca RPMs, extra RPMs if the DVD lacks them. All verified, with a manifest.
   └─ en0 192.168.100.2 ── cable ── aero br-lab 192.168.100.1  (KVM, chrony time source)
                                      ├─ build1  .20  compile + package Kanidm (never a server)
                                      ├─ srv1    .10  Kanidm · step-ca · SSH CA · BIND (4 separate units)
                                      ├─ client1 .12  CHP-built client (chp-build.sh), then kanidm_unixd
                                      └─ client2 .13  minimal reference client with kanidm_unixd
```

- **Principle (MFR F-6/F-9): code runs the loop, the model interprets.** Checks,
  parsing, and repairs are deterministic. The model gets ≤ 2k tokens of **findings**
  (never raw logs), in a fresh context each time. It returns an explanation plus a
  **repair id** from an allow-list. It never writes or runs commands.
- **One server, four independent services** mirrors dc2's "1 server, 5–7 workstations"
  shape. No shared state between the services, so faults can be injected into each one
  separately.
- **Portability:** the Mac reaches lab hosts over SSH, as the compliance server would
  reach dc2 from inside its boundary.

## 3. Part A: Model probe (Mac only; can start now)

Unchanged in substance from rev 1:
- **Tool-call reliability** at 1k / 4k / 8k / 15k / 25k tokens of context, n ≥ 20 per
  point, each tool scored against **its own** schema (MFR correction #2).
- **Interpretation quality** on 12 golden cases, drawn from the §6 scenarios once they
  exist.
- **Candidates:** Gemma 4 26B, Devstral Small 2 (installed); Llama 3.3 70B 4-bit
  (download, ~40 GB, tested alone).
- **Bar:** ≥ 90% at 15k tokens and ≥ 10/12 interpretation cases. If no model meets it,
  the design still works, because code already does all tool calling (§5).
- Runs only when LM Studio is idle. Results go to `probe/results/`.

## 4. Part B: The lab

### 4.1 Offline inputs (prepared on the Mac; the M1 deliverable)
| Input | Source | Verification |
|---|---|---|
| Rocky 9.8 x86_64 **DVD** ISO | Rocky mirror | SHA-256 against the signed CHECKSUM |
| Kanidm source, one **pinned** release tag | upstream release tarball | upstream checksum/signature; recorded in the manifest |
| Kanidm Rust dependencies | `cargo vendor` on the Mac | `Cargo.lock` hashes, vendored tree tarballed |
| Rust toolchain | **Rocky AppStream** `rust`/`cargo` from the DVD if new enough for the pinned Kanidm; otherwise a pinned upstream toolchain tarball | the MSRV check is recorded |
| Build dependencies (openssl-, pam-, sqlite-, systemd-devel, …) | DVD first; anything only in **CRB** is fetched as individual RPMs | Rocky GPG signature |
| step-ca + step CLI | Smallstep release RPMs | upstream checksums |
| BIND, OpenSSH, chrony | DVD | n/a |

`lab/inputs/MANIFEST.txt` lists every file, its version and hash. It is part of the Q1
evidence.

### 4.2 Host preparation (staged scripts on aero, `sudo sh <name>`, each with `--check`)
| Script | Does | Verifies |
|---|---|---|
| `b1-media` | copies the inputs to `/data/lab-inputs/`; the DVD becomes a local-only dnf repo; the lab RPMs become a second local repo | `dnf repolist` shows only local repos |
| `b2-kvm` | installs `qemu-kvm libvirt virt-install` | `virt-host-validate` passes the KVM checks |
| `b3-storage` | `/data/libvirt/images`, labelled `virt_image_t` | the pool is active |
| `b4-net` | bridge `br-lab` on `enp49s0`, 192.168.100.1/24, applied as one step with automatic rollback | the Mac can ping .1 |
| `b5-time` | aero's chronyd serves 192.168.100.0/24 (`local stratum 10`); aero's own RTC setting is reported and left as is | a VM syncs |
| `b6-scap-report` | `oscap` **cui** profile, report-only | the HTML report is copied to the Mac |

### 4.3 VMs (kickstart; FIPS `fips=1` + OpenSCAP cui profile at install; SELinux enforcing; no route off the lab)
| VM | vCPU | RAM | Disk (thin) | Role |
|---|---|---|---|---|
| build1 | 6 | 8 GB | 80 GB | Offline Kanidm compile + RPM packaging. Holds compilers; **never runs identity services** |
| srv1 | 4 | 6 GB | 60 GB | Kanidm server · step-ca · SSH CA · BIND, as four separate systemd units with separate data dirs |
| client1 | 2 | 4 GB | 512 GB *virtual* (PARTITIONS_3) | **CHP-built** (4.5), then `kanidm_unixd` |
| client2 | 2 | 2 GB | 30 GB | minimal Rocky + `kanidm_unixd`; the reference client |

The total is 20 GB of aero's 30 GB. After a clean build, `golden` snapshots of all four
are taken; `lab reset` reverts them.

### 4.4 Stack build (the Q1/Q2 work)
1. **build1:** compile the pinned Kanidm **offline** (`cargo build --offline --release`
   with the vendored tree), for the server, CLI, `kanidm_unixd` and `kanidm_unixd_tasks`.
   Package them as RPMs from a spec file in `lab/kanidm-rpm/`, including systemd units
   with the correct `StateDirectory` (known spike defect #2). The RPMs go to the local
   lab repo.
2. **srv1:** BIND (zone `kanidm.lab.test`); step-ca (internal root and intermediate;
   ACME and a renewal timer); SSH CA (its own key, `TrustedUserCAKeys` published to the
   clients); Kanidm server with a step-ca-issued TLS certificate; domain
   `kanidm.lab.test`.
3. **Clients:** install the unixd RPM, trust the step-ca root, and set nsswitch
   ordering correctly (known spike defect #3). The **separate POSIX password** is set
   for each lab user (spike finding #4).
4. **Lab data:** 6 fictitious users (TOTP for 4, one with a WebAuthn-only primary
   credential to exercise that path), POSIX groups, SSH user certificates with a short
   lifetime.
5. **Reports (this repo only, until Jeff's test is done):**
   `lab/adr0001-q1-packaging.md` (every step, defect and workaround) and
   `lab/adr0001-q2-fips.md`. The FIPS report covers: TLS through OpenSSL (the FIPS
   provider applies); password hashing, TOTP and WebAuthn (are they Rust crypto
   outside the FIPS module? observed and documented, not assumed); step-ca's Go crypto
   under FIPS; and any failures or refusals seen **with FIPS on**.
6. **SELinux:** the custom-built Kanidm daemons have no packaged policy. Denials are
   recorded, and **the option of a minimal policy module vs running confined as a
   generic service is reported to the ISSO**, not decided here.

### 4.5 client1 is built with the user's CHP build kit (a test of the kit)
`chp-build.sh` (CHP-SPEC v0.1, `~/Desktop/chp-build`) runs from a **copy**; the kit is
never modified.
1. A kickstart installs **Server with GUI**, FIPS, and the **PARTITIONS_3.md** 512 GB
   layout (the kit's preconditions).
2. A lab `PLACEHOLDERS.md` (`CHP_DOMAIN=kanidm.lab.test`, lab names, `CHP_OFFLINE_TARGET=none`)
   is applied with `chp-apply-placeholders.sh`.
3. `preflight → plan → harden → verify → evidence` runs **without `--safe`** (snapshots
   make disruptive negative tests safe).
4. **Known conflict to observe and record:** the kit configures **SSSD +
   pam_google_authenticator** (sshd, login, gdm-password, sudo; no `nullok`), while ADR
   0001's client path is **`kanidm_unixd` + Kanidm TOTP**. Adding `kanidm_unixd` to a
   CHP-hardened host shows exactly where the two collide: authselect, PAM stack order,
   double MFA prompts, and `verify_identity` results.
5. Everything about the kit (failures, wrong assumptions, the SSSD-vs-unixd conflict)
   goes to `lab/chp-findings.md` for the user.

## 5. Part C: Collector, findings, interpreter, repairs

### 5.1 Collector (`collector/idm-collect`, POSIX sh, **read-only**)
It runs on srv1 or a client and writes one redacted JSON report (≤ 200 KB).

| Area | Evidence |
|---|---|
| Kanidm server | `systemctl status kanidmd`, the server log (errors/warnings, `--since`), TLS expiry of its certificate, and a **read-only service-account** CLI query of the person or group in question (valid-from/expire, credential types present, **POSIX password set?**, account status) |
| Clients / unixd | `kanidm-unix status` (online/offline), `getent passwd/group <u>`, nsswitch order, `authselect current` / PAM stack for sshd, login, gdm and sudo, the unixd and unixd-tasks journals |
| Certificates | step-ca health and its renewal timer, expiry and chain of the Kanidm TLS cert, client trust store contains the step-ca root |
| SSH CA | `sshd -T` TrustedUserCAKeys, `ssh-keygen -L` for the user's certificate (validity, principals), CA public key fingerprint consistency |
| DNS | `named-checkconf`, `named-checkzone`, `dig` for the Kanidm host from the client |
| Time | `chronyc tracking`, offset vs 192.168.100.1 (TOTP window, TLS not-before/not-after) |
| SELinux | `getenforce`, recent AVCs for kanidm, sshd and named, `ls -Z` of the unixd socket and state dirs |
| Host | disk, memory, failed units |

**Redaction:** private keys, tokens, TOTP secrets, credential-reset tokens, and a
configurable deny-list are removed. Pseudonymization is available (an ISSO decision for
production).

**Access:** the Mac reaches hosts by SSH public key. The collector runs through a
root-owned wrapper with a single-command sudo rule, `diag ALL=(root) NOPASSWD:
/usr/local/sbin/idm-collect`. That's allowed in the lab; for dc2 it's an ISSO decision.
On client1 the rule must be proven to bypass the kit's sudo MFA (M3).

### 5.2 Findings engine (deterministic, unit-tested)
Example ids: `POSIX_PW_MISSING`, `UNIXD_OFFLINE`, `NSS_ORDER_WRONG`, `ACCOUNT_EXPIRED`,
`ACCOUNT_SOFTLOCKED`, `TOTP_TIME_SKEW`, `TLS_CERT_EXPIRED(kanidm)`, `ACME_RENEWAL_STOPPED`,
`CLIENT_MISSING_CA_ROOT`, `SSH_USER_CERT_EXPIRED`, `SSH_CA_NOT_TRUSTED`, `DNS_RECORD_MISSING`,
`SELINUX_AVC(component)`, `SERVICE_DOWN(unit)`.

### 5.3 Interpreter
Unchanged from rev 1: symptom + findings + runbook excerpt, ≤ 2k tokens, validated JSON
out; an unknown repair id means "model unsure", and the runbook default is shown instead.

### 5.4 Repairs (allow-listed; precheck → backup → apply → verify → undo; typed approval)
| Repair id | Apply | Verify |
|---|---|---|
| `kanidm-cred-reset-token` | the admin issues a credential-reset token for the user (the user sets their POSIX password or TOTP themselves; **no password is ever set by the tool**) | `POSIX_PW_MISSING` is cleared after the user completes the reset |
| `unixd-refresh` | clear/invalidate the unixd cache; restart unixd + tasks | `kanidm-unix status` online; `getent` resolves |
| `nsswitch-restore` | restore the known-good nsswitch/authselect profile from backup | `getent` + a test login |
| `time-resync` | `chronyc makestep` | offset < 1 s; TOTP accepted |
| `kanidm-cert-renew` | `step ca renew` for the Kanidm cert; reload kanidmd | new expiry; the client TLS handshake is OK |
| `acme-timer-restore` | re-enable and start the renewal timer | the timer is active; next-run time shown |
| `client-ca-trust` | install the step-ca root; `update-ca-trust` | TLS to Kanidm verifies |
| `ssh-user-cert-reissue` | sign a new short-lived user cert with the SSH CA | `ssh-keygen -L` shows it valid; SSH works |
| `ssh-ca-trust-restore` | restore `TrustedUserCAKeys` from backup; reload sshd | `sshd -T` shows it; SSH works |
| `selinux-restorecon` | `restorecon -Rv <path>` | no new AVC; the service works |
| `account-unexpire` | extend or clear the account validity for the user | the account is valid; login works |

Exact Kanidm CLI verbs are confirmed against the pinned version in M4. Anything that
can't be done read-only or reversibly becomes a *guided* ticket (instructions only)
rather than an automated repair.

### 5.5 Case file
`cases/<timestamp>-<slug>/` holds the symptom, reports, findings, model exchanges,
approvals, repair output, and **wall-clock time per step**. It is the audit record, the
ADR Q4 operational-data source, and the Claude Code hand-off brief.

## 6. Scenarios (fault → expected finding → expected repair)
| Id | Inject | Finding | Repair |
|---|---|---|---|
| **L1** | a user exists with a primary credential but **no POSIX password** (spike finding #4); try SSH/console login | `POSIX_PW_MISSING` | `kanidm-cred-reset-token` (guided) |
| **L2** | put kanidm in the wrong position in nsswitch (spike defect #3) | `NSS_ORDER_WRONG` | `nsswitch-restore` |
| **L3** | cut client2 → srv1 reachability, then restore it with a stale cache | `UNIXD_OFFLINE` | `unixd-refresh` |
| **L4** | move a client clock +10 min | `TOTP_TIME_SKEW` (+ TLS not-yet-valid) | `time-resync` |
| **L5** | expire a user's account validity on the server | `ACCOUNT_EXPIRED` | `account-unexpire` |
| **L6** | mislabel the unixd state dir/socket, or relabel after an update | `SELINUX_AVC(kanidm_unixd)` | `selinux-restorecon` |
| **C1** | issue the Kanidm TLS cert with a short lifetime, stop the ACME renewal timer, let it expire | `TLS_CERT_EXPIRED` + `ACME_RENEWAL_STOPPED` | `kanidm-cert-renew` + `acme-timer-restore` |
| **C2** | remove the step-ca root from client2's trust store | `CLIENT_MISSING_CA_ROOT` | `client-ca-trust` |
| **C3** | let a user's SSH certificate expire | `SSH_USER_CERT_EXPIRED` | `ssh-user-cert-reissue` |
| **C4** | remove `TrustedUserCAKeys` from a client's sshd config | `SSH_CA_NOT_TRUSTED` | `ssh-ca-trust-restore` |

Also **observed, not staged:** whatever the CHP-kit-vs-unixd collision produces on
client1 (4.5) becomes additional scenarios.

## 7. Build order (milestones)
| M | Deliverable | User action |
|---|---|---|
| M0 | repo skeleton; probe on the two installed models | none (LM Studio idle) |
| M1 | offline inputs fetched + verified + manifest; host prep `b1`–`b6` | approve passwordless sudo on aero (one command), else 6 × `sudo sh <name>` |
| M2 | build1 up; **Kanidm compiled + packaged offline on FIPS** → **Q1 report** | one `sudo sh` to build the VMs |
| M3 | srv1 stack + client2; FIPS behaviour → **Q2 report**; golden snapshots | none |
| M4 | client1 via CHP kit + unixd → `chp-findings.md` | enrol TOTP for lab users when the kit asks |
| M5 | collector + findings + repairs for **L1 and C1** end to end | none |
| M6 | remaining scenarios, interpreter, regression runner | none |
| M7 | probe re-run incl. Llama 3.3 70B → compliance-server acceptance criteria | approve the 40 GB download |

## 8. Testing
- **Unit:** findings rules against captured reports; redaction (no secret survives); the
  interpreter rejects unknown repair ids; the repair runner's order (undo on verify
  failure).
- **Integration:** the scenario runner. Each scenario must be green from `golden` three
  times in a row.
- **Non-negotiables:** the collector changes no state (verified with before/after hashes
  and service state); no repair runs without approval outside test mode; build1 never
  runs identity services; srv1 never has compilers.

## 9. Decisions recorded, and decisions for the ISSO
**Recorded:** dc2 stack only; independent cross-check (lab notes stay in this repo until
Jeff's test is done); throwaway lab domain; no internet anywhere in the lab; the model
never emits shell; allow-listed, human-approved repairs.

**For the ISSO:**
1. Is Kanidm's non-OS-module crypto (if Q2 confirms any) acceptable for dc2, and how is
   it documented for 800-171A (3.13.11)?
2. Should the Kanidm daemons get a custom SELinux policy module, or run as a generic
   confined service?
3. The single-command NOPASSWD collector rule on dc2.
4. Pseudonymization in reports; case-file retention; audit-log placement.
5. How the CHP kit should treat identity once the SSSD-vs-unixd findings are in.
6. The compliance-server hardware, **per the M7 results**.

## 10. Out of scope (this slice)
The browser workbench (D); the sysadmin RAG library (E); FreeIPA/389-ds; Nextcloud and
public TLS (Let's Encrypt DNS-01); DC20's real domain; any access to dc1, dc2, or the
internet from the lab; automatic (unapproved) repairs.
