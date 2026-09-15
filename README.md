# cyberhygiene-dc2

Clean-build successor to **dc1** (cyberinabox.net) — a fresh Rocky Linux install with a SCAP/STIG baseline, piloting **Kanidm** for identity management in place of FreeIPA, then layering the rest of the security stack.

## Why a clean rebuild instead of migrating dc1

dc1 proved the underlying research question: an open-source stack, assisted by AI for both construction and empirical NIST 800-171A assessment, can build and hold a CMMC Level 2 system to genuine, live-verified compliance rigor (not self-attestation). Running it for real also surfaced a clear, evidence-based finding: **FreeIPA's all-in-one identity/CA/DNS/Kerberos architecture is over-specified for a system this size** (1 server, realistically 5-7 workstations) — see [`dc1_Lessons_Learned_and_Architecture_Retrospective.md`](https://github.com/The-CyberHygiene-Project/cyberhygiene-documentation/blob/main/Documentation/Technical_Documentation/dc1_Lessons_Learned_and_Architecture_Retrospective.md) in the main documentation repo for the full retrospective and the concrete incidents behind that finding.

dc2 is not a migration of dc1 — it's a parallel clean build, scoped as an *enhanced* dc1 (same/near-identical server-grade hardware, the AI-server role restored) rather than a full re-architected product line.

## Status

Early planning stage. A Kanidm spike (throwaway VM, not committed hardware) has validated the core WebAuthn/TOTP authentication mechanism end-to-end. One open architectural question flagged from that spike: Kanidm's PAM/NSS client (`kanidm_unixd`) has no official RHEL/Rocky package — needs a decision (build from source, or reconsider client OS) before the real build starts.

## Related

- [`CLAUDE.md`](CLAUDE.md) — working rules and context for AI-assisted sessions in this repo (redaction rules, current build status, what's settled vs. open)
- [`docs/adr/0001-replace-freeipa-with-kanidm.md`](docs/adr/0001-replace-freeipa-with-kanidm.md) — the architecture decision behind this repo, with evidence and open questions
- [`docs/runbooks/kanidm-install.md`](docs/runbooks/kanidm-install.md) — the 9-step production install plan (currently blocked on a domain decision — see the runbook)
- [cyberhygiene-documentation](https://github.com/The-CyberHygiene-Project/cyberhygiene-documentation) — dc1's full documentation, including the lessons-learned doc above
- dc1's capture/inventory tooling (in progress) will classify what carries forward from dc1 into this repo
