# idm-assistant

Identity diagnostics and repair for small, hardened networks — part of **The CyberHygiene Project**.

A small business that must meet federal cybersecurity rules (NIST SP 800-171, the CUI profile) usually has no
identity specialist. When logins break, someone who is not an expert has to decide what to do. This project finds
identity faults with deterministic checks, explains them in plain words, and repairs the known ones — but only after
a person has read a plain-language decision form and typed `yes`.

It targets a Rocky Linux 9 network hardened to the CUI profile (FIPS mode, SELinux enforcing, fapolicyd) with a
Kanidm identity server, a step-ca certificate authority, an SSH certificate authority and BIND, running fully offline.

## How it works

```
hosts ─► collector ─► findings rules ─► runbooks ─► decision form ─► person types yes ─► repair ─► verify
 (read-only)   (code)        (code)        (written by people)  (filled by code)                (code)    (code)
                                   └─► local language model: explains, may pick one repair from an allow-list, or declines
```

| Part | Who decides | What it does |
| --- | --- | --- |
| `collector/idm-collect` | code | Read-only report from each host (shell, run as root through one narrow sudo rule); secrets redacted before anything leaves the host. Shipped as a signed RPM. |
| `engine/findings.py` | code | Turns reports into named findings, each with its evidence. Untrusted strings (addresses, paths, sources) are filtered by code before they reach a person or the model. |
| `runbooks/` | people | One short page per finding. Its header fills the decision form; its body is the short text the model reads. |
| `engine/form.py` | code | The decision form: problem, likely cause (with what was found on this host), proposed action, potential downside, undo, **say no if**, choice. No model writes any line of it. |
| `engine/interpret.py` | local model | Explains the findings and may name **one** repair from an allow-list, or decline. Runs on a local model server; no data leaves the machine. |
| `engine/repairs.py` | code | Each repair: precheck → backup → apply → verify with a fresh report → automatic rollback on failure. Every approval is recorded with the approver's name. |

**The code is the gate.** The allow-list and each repair's own precheck decide what can run; the model only explains
and chooses within what code allows. (In testing, the local model followed a plausible planted instruction when the
gate was deliberately bypassed; on the real path it could not.)

## Safety decisions

Repairs follow decisions made by the project's security officer (ISSO), recorded as requirement rows in
[`lab/iso-requirements.md`](lab/iso-requirements.md). The ones that shape repairs most:

| Row | Decision |
| --- | --- |
| 18 | After restoring from an image or snapshot, restart the time service before anything else. |
| 28 | Revoking access clears every workstation's cache at once; a stale cache means that clear missed a host. |
| 30 | Clocks correct gradually; a person may approve a one-time step. |
| 32 | Only the ISSO or a named delegate re-enables an expired account (with a written reason); the engine never does. |
| 44 | A workstation lockout may be cleared with approval — never while a clock, time or SELinux fault is present. |
| 45 | DNS faults are diagnose only; a name pointing at the wrong address is a possible security incident. |
| 46 | fapolicyd: refresh trust from signed packages only; unpackaged programs and fapolicyd switched off are diagnose only. |

## Runbooks and procedures

- **24 runbooks** in [`runbooks/`](runbooks/), in one format: [`runbooks/README.md`](runbooks/README.md) (the fields,
  how each becomes a line of the decision form, and the rules every runbook follows).
- **Procedures** for situations that are not a single finding:
  [after a power outage](runbooks/procedures/after-power-outage.md),
  [after restoring from a snapshot or image](runbooks/procedures/after-restore.md).

## Lab, scenarios and tests

The lab is a libvirt host (`aero`) running an identity server (`srv1`) and a workstation (`client2`), reset to a
known-good snapshot before every run.

- **19 fault scenarios** in [`scenarios/`](scenarios/): certificates (c1–c4), logins and accounts (l1–l6, l3n),
  DNS (d1, d2), account lockout (f1, f2), fapolicyd (p1–p3), snapshot restore (r1). Each injects a real fault, expects
  specific findings, runs the approved repair (or expects the model to decline), and checks the result with a real
  login.
- **Unit tests:** `python -m pytest -q tests` (Python 3.12+).
- **Run one scenario / a regression:** `python -m engine scenario d1 --runs 3`, `python -m engine regress --runs 1`.
  Regression reports are kept in [`lab/plan8/`](lab/plan8/) (earlier ones in `lab/plan5`–`plan7`).
- Inspect a host read-only: `python -m engine findings client2 --user lab04`.

## Releases

Project packages are signed with a dedicated hardware key and published as a signed repository. Each release has a
record with every package's signer and SHA-256 in [`appliance/release/`](appliance/release/) (current: **0.5.8**,
`idm-collect-0.1.0-9`). The appliance installer (kickstarts, `chp-site`, client and server roles) lives in
[`appliance/`](appliance/).

## Status (October 2026)

Done: the decision form and runbook format; the ISSO decisions above built into code; gap runbooks for account
lockout, DNS faults, fapolicyd, power outage and snapshot restore — each with a spec, a plan, lab scenarios run three
times, and an independent review.

Open:

- **MFA "half-applied kit"** (the build kit turning on the authenticator before anyone has a token): needs an
  ISO-installed host in the regression lab first.
- **Kanidm database backup and restore** (`kanidmd database backup/restore`): not yet tested in the lab.
- **Verify package signatures on the host:** hosts import only the project key, so the fapolicyd check uses the key
  ID a package claims; importing the Rocky and EPEL keys would let the collector verify it.
- **Kanidm's server-side lockout**, separate from the workstation lockout.
- Smaller deferred items are listed at the end of each pull request (#17–#21).

## Design history

Every piece of work has a design spec and an implementation plan in
[`docs/superpowers/specs/`](docs/superpowers/specs/) and [`docs/superpowers/plans/`](docs/superpowers/plans/); the
pull requests carry the review findings and the decisions taken along the way. An earlier experiment with a
write-capable coding agent in the repair path — and why it was kept out — is in [`lab/aider-spike/`](lab/aider-spike/).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
