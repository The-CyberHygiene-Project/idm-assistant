# CLAUDE.md — cyberhygiene-dc2

Context file for Claude Code sessions in this repository. Read this before
proposing changes, writing documentation, or executing build steps.

> **Provenance note.** This file was drafted 2026-09-14 from the dc2 README and
> the dc2 planning inventory. Items marked `TODO(Don)` were inferred or are
> unresolved and need a human decision before they are treated as settled.

---

## 1. What this repository is

`cyberhygiene-dc2` is the build and documentation repository for **dc2**, a
clean-build successor to dc1 (cyberinabox.net).

dc2 is **not a migration** of dc1. It is a parallel clean build on same or
near-identical server-grade hardware, scoped as an *enhanced* dc1 with the
AI-server role restored — not a re-architected product line.

**The research question**, inherited from dc1 and already answered in the
affirmative there: can an open-source stack, assisted by AI for both
construction and empirical NIST 800-171A assessment, build and hold a CMMC
Level 2 system to genuine, live-verified compliance rigor — not
self-attestation?

dc2 tests a narrower follow-on question: whether the identity layer can be
de-bundled without losing that rigor. See `docs/adr/0001`.

### What this project is not

State this plainly in any document that could be mistaken for a commercial
claim. The CyberHygiene Project is a proof-of-concept and educational
reference implementation. It is **not** a commercial product, **not** a
certified system, and **not** a consulting service. Passing an automated scan
is not compliance; expertise, policy, and third-party assessment remain
required. Never write copy that blurs this.

### Related repositories

| Repo | Contains |
|---|---|
| `cyberhygiene-documentation` | dc1's full documentation, including `dc1_Lessons_Learned_and_Architecture_Retrospective.md` — the evidentiary basis for the dc2 identity pivot |
| `cyberhygiene-evolution` | Manuscript, redacted incident narratives, predecessor publications |
| `cyberhygiene-website` | Project website and dashboards |

---

## 2. Current status

**Early planning / early build.** As of 2026-09-15:

- Kanidm spike **complete and validated** on a throwaway VM (2026-08-21).
  WebAuthn/TOTP login, NSS, and PAM (`kanidm_unixd`) confirmed end-to-end.
- Real dc2 install: **not started.** Only build dependencies are staged
  (`git gcc openssl-devel pam-devel lld` and similar).
- A concrete **9-step install plan** exists (`docs/runbooks/kanidm-install.md`)
  and is the single clearest next piece of executable work, once unblocked
  (see below).
- Boot drive is being re-prepared with Rocky + FIPS as a clean base.

### BLOCKED: Kanidm initialization awaits the Oklahoma City domain

**Do not run a live Kanidm init with real identity enrollment.**

Kanidm's `domain`/`origin` is effectively permanent once initialized — WebAuthn
credentials are cryptographically bound to it, so changing it later re-enrolls
every credential from scratch. dc2 is relocating to Oklahoma City as a
parallel project (dc1/diwai remain in Albuquerque) and will run on a **new
domain**, its own ISP and a new NetGear router — a genuinely separate network,
not a relocated copy of `cyberinabox.net`.

The 9-step install plan's step 4 assumed `dc2.cyberinabox.net`. **That value is
wrong. Do not use it.** If a session proposes running the init, stop and say
why.

Safe to proceed with meanwhile: building and packaging the Kanidm binaries and
systemd units (mechanical, no live enrollment), and the SSH-CA and step-ca
pieces.

### Where dc2 physically is

dc2 is **not** a KVM guest on dc1, whatever older notes say. Confirmed
empirically: `systemd-detect-virt`=none, real `/dev/sda`, no hypervisor CPU
flag. The disk currently sits bare-metal in a chassis **borrowed from
`labrat.cyberinabox.net`** (HPE ProLiant MicroServer Gen10 Plus, 32GB).

**`/dev/sdb` in that chassis is labrat's own boot disk. Do not touch it.**

dc2's permanent home is **DC20** (HP 1U rack-mount, 64GB RAM) in Oklahoma
City. TPM2 and other hardware-binding steps wait for that move — binding to
labrat's TPM would be as wrong as binding to dc1's virtual one.

### Logging

`/var/log/journal` does not exist, so journald retains nothing across reboots
and crashes are undiagnosable. Set `Storage=persistent` in
`/etc/systemd/journald.conf`.

### Open question blocking the build

`kanidm_unixd` has **no official RHEL/Rocky package.** Decide before the real
build starts: build from source, or reconsider the client OS. Do not let a
session drift past this — it is a prerequisite, not a detail.

`TODO(Don)`: record the decision as `docs/adr/0002` once made.

---

## 3. Architecture

dc2 replaces FreeIPA's all-in-one identity/CA/DNS/Kerberos design with four
independent components:

| Function | Component |
|---|---|
| Authentication / identity | Kanidm |
| SSH certificate authority | separate SSH CA |
| TLS / ACME | step-ca |
| DNS | standalone BIND |

The unbundling is the point. Rationale, evidence and consequences are in
`docs/adr/0001-replace-freeipa-with-kanidm.md`. Read that ADR before proposing
any change to the identity layer, and do not re-litigate the decision without
new evidence.

### Settled decisions — do not reopen without new evidence

- **FreeIPA is out.** Operational, evidence-based, documented in ADR 0001.
- **RS#2 (the Mac Mini) was rejected as a dc1-replacement server path** —
  single spindle, no network segmentation. This is settled. A Mac Mini
  appearing in the rack in another role does not reopen it.
  `TODO(Don)`: document the M4 Pro's actual role (AI-server node?) as an ADR
  so the distinction is explicit and the old decision is not accidentally
  revisited.
- **dc2 is a clean build, not a migration.**
- **`chp-build.sh` and CHP-SPEC v0.1 are reference material for a future
  golden-disk effort, not tooling for dc2's current build.** Both exist (see
  the project's private working notes) but are explicitly first-cut drafts
  Don has scoped as post-dc2 reference, not something to adopt now. Don't
  propose retrofitting dc2's build onto either without asking first.

---

## 4. Non-negotiable working rules

### 4.1 This is a public repository

Every commit is world-readable and permanent. Deleting a file does not remove
it from history.

Redaction happens **before** push, via the project's redaction tooling. Never
commit:

- real IP addresses, hostnames, domain or realm names
- passwords, hashes, keys, keytabs, certificates, tokens
- account or group structures that mirror the live environment
- anything identifying a person in an incident narrative

Two subtleties that matter more than the obvious list:

- **A hash is not a redaction.** If a name or IP is replaced by its hash, the
  search space is small enough to exhaust in seconds. Use random tokens mapped
  in a keyfile that never enters the repo.
- **Structure leaks.** Substituting a real subnet with a structurally similar
  one still publishes the segmentation design, which in an incident narrative
  is often the sensitive part.

If you believe something sensitive has already been committed, say so and
stop. Do not "fix" it with a follow-up commit — that does not remove it.

### 4.1a The exception to "put it in the repo"

Most project knowledge belongs in this repository. One category does not.

**`CUI_System_Security_Plan_v3.0.docx` must never enter any repository, public
or private.** It is Don's real production SSP for his government-contracting
business (dc1 + labrat), a separate concern from this project, and it contains
real business identifiers — CAGE, UEI, phone, clearance level. It is a
**format and structure reference only.** Nothing in it is a current fact about
dc2, or a durable description of dc1 or labrat.

Never reproduce its identifier values anywhere. When using it as a model, take
the skeleton — section order, heading structure, level of detail — and nothing
else. The same posture applies to other real crypto/business material that
surfaces during this project's working sessions (PKINIT certificates/CSRs,
SAM.gov/entity-registration records) — private archive only, never a
repository.

This exception matters because the rest of this file pushes hard toward putting
context in the repo. That instruction has a boundary, and this is it.

### 4.2 SCAP scans must target the Rocky-native datastream

**Always `ssg-rl9-ds.xml`. Never `ssg-rhel9-ds.xml`.**

This is not a preference. On this Rocky box, RHEL-targeted CPE data makes
nearly every platform-gated rule report `notapplicable`, so the scan looks
clean because almost nothing was checked. Measured directly on dc2:

- RHEL9 content → **0 pass / 0 fail**
- Rocky-native content → **100 pass / 3 fail**

Any document, script, kickstart, or command a session produces that runs a
compliance scan must use the Rocky-native datastream. Treat a scan result
produced with the wrong content as no result at all.

Approved invocation with the dc2 tailoring:

```
oscap xccdf eval --profile xccdf_net.cyberinabox_profile_cui_dc2 \
  --tailoring-file /etc/scap/tailoring/dc2-cui-tailoring.xml \
  /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
```

### 4.3 Deviations get documented tailoring, not silent edits

Known deviation: `user.max_user_namespaces` was set to `0` by the kickstart's
OpenSCAP "cui" profile (`CCE-83956-3`), which conflicts with `PrivateUsers=`
sandboxing and broke `irqbalance`, `upower`, and GNOME session units with a
misleading "No space left on device" error. Raised to `15000`, which matches
SSG's own rule text for a system with `@container-management` and
`@graphical-server-environment`. Documented in an XCCDF 1.2 tailoring file at
`/etc/scap/tailoring/dc2-cui-tailoring.xml`, schema-validated, and empirically
verified to change exactly that one rule and nothing else.

That is the pattern. A deviation is a documented, validated, scoped tailoring
with evidence it changed only what was intended — never an undocumented
config edit.

### 4.4 Evidence, not assertion

This project's entire credibility rests on the difference between verified and
assumed. In any document or commit message, distinguish:

- **verified** — observed directly, with the command and result recorded
- **expected** — should follow, not yet observed
- **assumed** — taken on faith, flagged as such

Never write a compliance claim that a scan alone supports. Never describe a
control as implemented because it was configured; say how it was checked.

### 4.5 Scope discipline

Detailed SCAP/STIG/NIST remediation work is a **stated future activity, not to
be pursued proactively.** Two real fails are deliberately outstanding:
`grub2_password` and `service_usbguard_enabled`. Do not chase them, do not
"helpfully" remediate them, and do not treat them as defects.

---

## 5. What Claude should not do here

- Do not remediate out-of-scope SCAP findings (see 4.5).
- Do not invent or infer 800-171 control mappings. If a mapping is not in the
  documentation, say it is missing rather than producing a plausible one.
- Do not write self-attestation language or any phrasing implying
  certification.
- Do not run a compliance scan against RHEL content (see 4.2).
- Do not commit anything covered by 4.1 without the redaction step.
- Do not reopen settled decisions (see 3) absent new operational evidence.
- Do not rewrite git history without explicit instruction.

---

## 6. Collaboration

Two researchers in two locations (Albuquerque and Oklahoma City). The
repository is the shared channel — if context is not in the repo, the other
person does not have it.

- Work happens on branches; `main` is protected and requires a PR review
  (`TODO(Don)`: not yet configured as of 2026-09-15 — see the turnover
  checklist).
- With exactly two contributors, neither can approve their own PR, which makes
  every change to a policy, control mapping, or configuration independently
  reviewed and timestamped. That review trail is also the project's
  configuration-management evidence. Treat it as an artifact, not overhead.
- Commit trailers: use `Co-authored-by:` so attribution survives.

### On Claude Code memory

Project context belongs **in this repository**, not in a session memory store.
Memory is per-user and per-machine; it does not survive a handoff and is
invisible to a collaborator. If a session establishes durable project
knowledge — a decision, a rationale, a finding — write it to the repo.

Personal preference memory (working style, accessibility needs, correction
patterns) is the exception: it is individual, it does not belong in the repo,
and it must not be copied between people.

---

## 7. AI use disclosure

AI assistance is part of this project's method and therefore part of its
findings. Record, for work that reaches a publication or presentation: which
model, on which task, and how the output was human-verified. Where AI output
was wrong and how that was caught is itself a result worth publishing.
