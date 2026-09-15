# ADR 0001 — Replace FreeIPA with four independent identity components

- **Status:** Accepted. Spike-validated 2026-08-21. Implementation not started.
- **Decided:** 2026-08-14
- **Deciders:** Donald E. Shannon
- **Applies to:** dc2 (does not retroactively change dc1)

> **Provenance.** Reconstructed 2026-09-14 from `project_kanidm_pivot.md` in the
> dc2 planning set and the dc1 lessons-learned retrospective. Updated
> 2026-09-15 with direct input from a dc1-side session resolving two of the
> open questions below.

---

## Context

dc1 proved the project's core research question: an open-source stack, assisted
by AI for construction and empirical NIST 800-171A assessment, can build and
hold a CMMC Level 2 system to live-verified compliance rigor rather than
self-attestation.

Running dc1 for real also produced a second, unplanned finding. FreeIPA's
all-in-one identity / CA / DNS / Kerberos architecture is **over-specified for a
system of this size** — one server and realistically five to seven workstations.

The cost of that over-specification was not theoretical. dc1 experienced
repeated operational pain attributable to the bundling itself:

- **CA drift** — certificate authority state diverging from expectation
- **Kerberos FAST/OTP bugs** — authentication path failures
- **SELinux relabel bugs** — triggered by FreeIPA's install and update behavior

Each incident consumed disproportionate time relative to the size of the estate
being managed. The full retrospective and the concrete incidents behind this
finding are in `dc1_Lessons_Learned_and_Architecture_Retrospective.md` in
`cyberhygiene-documentation`. A companion, MFA-specific narrative
(`MFA-Lessons-Learned-and-FreeIPA-Overkill-for-VSB.md`) documents the same
pattern in detail for control 3.5.3 specifically — currently held in the
project's private working archive pending a decision on public release.

The generalizable observation — and the one that matters to this project's
audience of very small DIB businesses — is that enterprise-grade bundled
identity infrastructure imposes enterprise-grade operational burden regardless
of how small the environment is. A five-workstation shop inherits the full
operational surface of a product designed for thousands of seats.

---

## Decision

dc2 will **not** run FreeIPA.

The identity layer is de-bundled into four independently operated,
independently replaceable components:

| Function | Component |
|---|---|
| Authentication / identity | **Kanidm** |
| SSH certificate authority | **separate SSH CA** |
| TLS / ACME | **step-ca** |
| DNS | **standalone BIND** |

These are deliberately **not** one bundled product. The separation is the
substance of the decision, not an implementation detail: a failure in the CA
should not be able to take down authentication, and a DNS change should not be
able to disturb Kerberos state, because there is no shared state to disturb.

---

## Evidence

A throwaway spike VM, hosted on dc1, validated the Kanidm mechanism end to end.
Fully resolved 2026-08-21. TOTP login, NSS, and PAM (`kanidm_unixd`) all
confirmed working.

The spike surfaced and resolved five real defects, each of which would
otherwise have been discovered during the production build:

1. A build profile flag error
2. A missing systemd `StateDirectory`
3. An `nsswitch` ordering bug, matching a known upstream issue
4. **POSIX accounts require a separate `person posix set-password`**, distinct
   from the primary credential — the most consequential finding, and
   non-obvious
5. **Likely candidate, per dc1-side input (2026-09-15), not asserted with full
   certainty**: testing PAM/NSS login over SSH/`expect` automation introduces a
   spurious ~15-40s stall that looks exactly like a hang, but isn't — confirmed
   via a VNC console test with real keyboard input showing no such delay. The
   actionable lesson: verify via a real console (`virsh console` + `su -`), not
   scripted SSH automation, or the phantom hang gets chased as if it were a
   real bug.

Every one of these is applied proactively in the 9-step production install
plan (`docs/runbooks/kanidm-install.md`) rather than rediscovered.

### Limit of this evidence

The spike ran on a throwaway VM. **dc2's production base is Rocky with FIPS
enabled.** If the spike VM was not FIPS-enabled, the spike validated the
mechanism but not the target configuration — and Kanidm built from source uses
Rust cryptography that is not covered by the system OpenSSL FIPS policy.

`TODO(Don)`: confirm whether the spike VM ran in FIPS mode. If it did not, a
FIPS-mode re-validation is required before the production install is trusted.
Still open as of 2026-09-15 — see *Open questions*.

---

## Consequences

### Positive

- Operational surface matched to a 1-server, 5-7 workstation estate
- Failure isolation: no shared state across identity, CA, DNS and TLS
- Each component independently replaceable without re-architecting the others
- Eliminates the three recurring dc1 failure classes at their structural source
- Renders moot the golden-disk blocker that FreeIPA cannot be safely
  clone-and-renamed (it embeds install-specific cryptographic material)

### Negative

- **Four components to operate, document and assess instead of one.** The
  operational burden is reduced in kind, not simply in amount — this must be
  demonstrated, not asserted.
- **Kerberos is gone.** Resolved (2026-09-15, dc1-side input) — see *What
  depended on Kerberos*, below.
- **Integration is now the project's responsibility.** FreeIPA's bundling
  provided integration for free; that work moves in-house.
- **Kanidm is younger and less widely deployed than FreeIPA**, with a smaller
  community and less third-party documentation — a real consideration for a
  reference implementation intended for adoption by small businesses without
  dedicated identity expertise.
- **No official RHEL/Rocky package for `kanidm_unixd`.** See below.
- **The identity origin is effectively permanent.** Kanidm binds WebAuthn
  credentials cryptographically to its `domain`/`origin`. Changing it later
  forces every credential to re-enroll from scratch. This makes initialization
  a one-way door and couples the identity layer to a domain-naming decision
  that must be made — and lived with — before any real enrollment. FreeIPA's
  realm carried a comparable constraint, so this is not a regression, but it is
  sharper here because WebAuthn is the primary credential rather than a
  secondary factor.
  **Consequence for dc2:** initialization is blocked until dc2's Oklahoma City
  domain exists (dc2 is relocating there as a parallel project; dc1/diwai
  remain in Albuquerque). The 9-step plan's step 4 value
  `dc2.cyberinabox.net` is void.
- Four components mean four sets of control-implementation statements for
  800-171A assessment.

### Neutral

- The golden-disk "regenerate per deployment" principle still applies to
  `/etc/machine-id`, SSH host keys, and equivalents, independent of this
  decision.

---

## What depended on Kerberos on dc1, and what replaces it

**Resolved 2026-09-15, dc1-side input.** Concretely, on dc1, the things that
depended on Kerberos/GSSAPI (beyond login itself) and caused real operational
cost:

- **`ipa cert-request`** — inherited a project-wide SPNEGO negotiation bug,
  forcing all certificate requests to bypass IPA's own CLI/API entirely and go
  directly to the underlying Dogtag CA using IPA's RA-agent credentials,
  against legacy servlet paths (the modern REST paths don't work with the
  bypass tool).
- **The IPA CLI and WebUI generally** — the same SPNEGO/GSSAPI bug family
  caused a standing "No valid Negotiate header" failure, eventually root-caused
  to two separate stale/missing Kerberos keytabs left out of sync after a disk
  restore.
- **A custom internal admin dashboard's SSO** — authenticated via
  `mod_auth_gssapi` against a principal alias of the main host's HTTP service.
  This worked, but needed its own explicit keytab fetch merged in by hand,
  because GSSAPI does exact name+kvno matching and aliases don't resolve
  automatically at that layer even though they share key material at the KDC.
- **`sudo` via IPA sudo rules** — never actually worked reliably on dc1; the
  practical fix used was a local `/etc/sudoers.d/` rule instead of fighting
  IPA's sudo-rule/API path.

**What replaces it in dc2's design:** Kanidm's `kanidm_unixd` (PAM+NSS) is a
direct SSSD replacement with no Kerberos FAST/OTP preauth path at all — this
retires the whole GSSAPI/keytab-drift/SPNEGO bug class described above at the
root, not by working around it per-service the way dc1 had to. The SSH-CA and
step-ca pieces are dc2's replacements for what Kerberos-backed trust and IPA's
CA were doing for host-to-host and service auth respectively.

---

## Open questions

| # | Question | Blocking? |
|---|---|---|
| 1 | `kanidm_unixd` has no official RHEL/Rocky package. Build from source, or reconsider the client OS? | **Yes — blocks the production install** |
| 2 | Does Kanidm, built from source, operate correctly on a FIPS-enabled Rocky host? Was the spike FIPS-enabled? | **Yes — invalidates spike coverage if unresolved** |
| 3 | ~~What depended on Kerberos in dc1, and what replaces it?~~ | **Resolved 2026-09-15 — see section above** |
| 4 | Does the four-component stack demonstrably reduce operational burden, measured how? | No — but it is the ADR's central claim and should be evidenced |

Question 4 deserves emphasis. The decision rests on a claim about operational
burden. If dc2 does not capture comparable operational data to dc1, the claim
remains an opinion. Deciding *now* what to measure is cheaper than
reconstructing it later.

---

## Relationship to other decisions

- **Supersedes** the dc1 identity architecture, for dc2 only. dc1 is unchanged.
- **Unblocks** the golden-disk concept in `project_server_deployment_golden_disk.md`
  by removing the FreeIPA clone-and-rename constraint.
- **Does not affect** the settled rejection of RS#2 (Mac Mini) as a
  dc1-replacement server path — that rejection was on single-spindle storage
  and absent network segmentation, unrelated to identity.
