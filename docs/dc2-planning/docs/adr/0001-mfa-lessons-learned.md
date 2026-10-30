# MFA Lessons Learned, and Why FreeIPA May Be Overkill for a Very Small Office

Companion document to [`0001-replace-freeipa-with-kanidm.md`](0001-replace-freeipa-with-kanidm.md).
That ADR records the *decision* (Kanidm + three independent components,
not FreeIPA) and the three incident classes that motivated it. This
document is the *evidence*, told as a narrative, with a specific focus on
MFA — the control that, on dc1, took the longest to get from "enrolled" to
"actually, verifiably enforced."

**Audience:** small DIB (Defense Industrial Base) shops evaluating NIST
800-171/CMMC Level 2 MFA (control 3.5.3) at the scale of one server and a
handful of workstations.

---

## Part 1: The core finding, stated plainly

A working MFA login and an *enforced* MFA requirement are different
claims, and the gap between them is where the real operational cost lives
— not in the cryptography, which worked correctly essentially every time
it was actually invoked. On dc1, closing that gap required:

- Multiple distinct, unrelated bug classes (SELinux file-relabeling,
  Kerberos preauth, PKI profile management, GSSAPI/keytab sync)
- A real lockout incident that required break-glass recovery
- A second, independent lockout on a second account, still not fully
  root-caused
- A formally tracked POA&M item that stayed open for over two weeks
  specifically *because* the project would not credit "MFA works" until
  "MFA is enforced" had been proven safe to flip

None of this reflects poorly on FreeIPA as software. It reflects the
operational reality of running an all-in-one identity/CA/Kerberos product,
correctly, at a scale where there is one administrator and no dedicated
identity team to absorb that complexity.

---

## Part 2: The dc1 MFA timeline, as it actually happened

### 2.1 Hardware validation — trust the tool, not the label

Of three YubiKeys believed to be FIPS-validated, only one actually was
(confirmed via `ykman info`). This is a five-minute check that would have
been skipped entirely without the project's "verify, don't assert"
discipline — and a wrong assumption here would have meant enrolling
non-compliant hardware and not finding out until an assessor asked for the
validation certificate.

### 2.2 A real, reproducible hardware bug

A FIPS-validated YubiKey's PIV *management-key* authentication failed on
dc1's own PC/SC/CCID stack — reproduced with two independent tools, two
key resets, and two USB ports — while working correctly with the identical
key and credentials on a Mac. Day-to-day PIN+touch login was unaffected;
only the provisioning step (setting PIN/PUK/management key, generating the
keypair) was blocked. **Workaround:** do all management-key-gated PIV
provisioning on a different machine, then move the already-provisioned key
to the target host. This is the second time in this project that a host's
own USB stack, not the peripheral, was the root cause of an inexplicable
failure — worth remembering as a category, not just an incident.

### 2.3 Two more FreeIPA-coupled bugs surfaced immediately, before MFA was even enrolled

- Certificate requests inherited a known SPNEGO bug, forcing them to go
  around IPA entirely — submitted directly to the underlying Dogtag CA
  using IPA's own RA-agent credentials, against **legacy servlet paths**,
  because the modern REST paths 404 with the tool that actually works
  around the SPNEGO problem.
- Building a certificate with the correct Extended Key Usage for PKINIT
  required a **custom Dogtag certificate profile**, which surfaced two
  genuinely obscure product bugs: the real profile store is an ACI-hidden
  LDAP subtree invisible to the admin account (every official tool that
  appears to manage profiles is actually pointed at the wrong place), and
  a custom profile's policy set silently fails to load unless the
  configuration includes an extra, undocumented trailing policy block
  beyond what's declared. Diagnosing this consumed a full session by
  itself.

**None of this is "MFA." It's the CA and the directory product MFA
happened to be bundled with**, and it had to be debugged before MFA work
could even start. This is the concrete, lived version of ADR 0001's
abstract point about bundling: a failure or complexity spike in the CA
layer directly blocked progress on the authentication layer, because in
FreeIPA they are not separable.

### 2.4 Enrollment succeeded — then a real lockout happened anyway

Full PIV provisioning, cert-to-account mapping, and a real physical-key
GDM login were all completed and confirmed working. Separately, and only
weeks later, a genuine incident occurred: **enforcement was applied to the
account actively in use, causing a lockout**, recovered only because a
break-glass account happened to exist by that point. Enforcement was
immediately reverted. This is documented as a hard rule going forward,
worth stating explicitly for any small shop attempting the same thing:

> **Never flip MFA enforcement on an account without a second,
> independently verified working session already open, and without
> break-glass access confirmed functional first.**

### 2.5 The safeguarded re-enforcement, done right the second time

When enforcement was reattempted, it followed six concrete safeguards, in
order — worth reusing as a checklist regardless of identity backend:

1. Prove the credential works at the real login screen (not just
   screen-unlock), while the old method is still live.
2. Independently test the break-glass account itself, if it has never
   been tested before.
3. Hold multiple verified-working sessions open simultaneously through
   the change (in this case: the account being changed, a second admin
   account, and break-glass — three separate terminals, three separate
   logins).
4. Know exactly what the revert command is *before* running the
   enforcement command, not after something breaks.
5. Clear any cached negative-authentication state immediately after the
   change.
6. Verify success from logs, not from "it seems to work" — a rejected
   old-credential attempt and an accepted new-credential attempt, both
   independently confirmed in the audit trail.

Applied this way, enforcement succeeded cleanly, with an audit-log-confirmed
rejected password attempt followed nine seconds later by a confirmed
successful PIN login.

### 2.6 A second account, a second unresolved intermittent failure

A second user's smartcard login later failed intermittently — PIN
accepted, authentication logged as successful, but no session ever opened,
with no error anywhere in the chain. Two red herrings were chased and
ruled out along the way (a policy-*correct* SELinux denial unrelated to
the failure, and a one-time OCSP race against the CA service on a fresh
reboot) before the problem self-resolved without any configuration change,
on a later retry over an hour after boot. **Root cause was never
conclusively identified.** This is the least satisfying kind of finding —
not a bug you can point to and fix, but a system with enough moving parts
(SSSD, PKCS11, the CA's OCSP responder, Kerberos, GDM's PAM stack) that a
transient failure can occur without leaving enough evidence to explain
itself.

### 2.7 The compliance discipline this forced

The project adopted a firm rule, directly because of this history: **do
not credit MFA (control 3.5.3) as met based on enrollment alone.** "A
working smartcard login exists" and "smartcard login is actually required,
with no fallback" are different claims, and this project had already been
burned once by exactly that gap (MFA that had never once completed a
successful login in the system's history, sitting silently mis-credited as
MET — see Part 3). Credit was withheld and tracked as an open item until
enforcement was applied *and* independently re-verified from logs.

---

## Part 3: The pattern this fits — SELinux and MFA, more broadly

The PKINIT saga above is the most recent instance of a pattern that
recurred **four separate times**, across different MFA mechanisms and
different PAM services:

- File-based SSH MFA had *never once* completed a successful login in the
  system's history, despite being credited as MET — caused by a SELinux
  file-relabeling bug (file rewritten via temp-file-then-rename, the
  rename doesn't preserve the intended label, the write gets silently
  denied).
- The identical bug class hit console/GDM MFA separately, needing its own
  SELinux module fix.
- **The catastrophic instance:** the same bug took down every login path
  simultaneously — GDM, console, and SSH (via a second, compounding
  missing-PAM-substack bug) — with no working break-glass account to fall
  back on at the time. Recovery required physically removing the disk and
  repairing it offline on a different machine.

This is not a one-off misconfiguration. It is **structural** to how
file-based MFA mechanisms interact with SELinux's file-transition model on
this stack, and it recurred despite each prior instance being individually
"fixed." A small shop with one administrator and no dedicated
identity/security team should expect to budget real time for this class of
problem if it adopts a similar bundled stack — not because the stack is
defective, but because nothing about its scale reduces this complexity; a
five-workstation shop inherits the identical failure surface as a
five-thousand-seat enterprise.

---

## Part 4: What this means for dc2's approach

dc2 replaces FreeIPA with four independently operated components — Kanidm
for identity, a separate SSH CA, step-ca for TLS, standalone BIND for DNS
(full rationale in ADR 0001). The MFA-specific implications, drawn
directly from the incidents above:

- **Kanidm's MFA model (WebAuthn-first, TOTP secondary) has no Kerberos
  FAST/OTP preauth path at all** — it directly retires the entire bug
  class in §2.3 and the debugging cost described in the companion
  retrospective's Kerberos-preauth finding (a multi-hour debugging arc
  that came down to a one-line test-format mistake, only reachable by
  reading raw KDC debug logs).
- **No shared CA.** dc2's TLS/PKI is step-ca, entirely separate from
  Kanidm's own listener certificate and from any future SSH CA. The
  Dogtag custom-profile debugging described in §2.3 — the ACI-hidden
  profile store, the undocumented trailing policy block — is a
  Dogtag/FreeIPA-specific cost that a step-ca-based stack does not
  inherit; step-ca's ACME-based model doesn't require hand-authored
  certificate profiles for this kind of client certificate.
- **The safeguarded-enforcement checklist in §2.5 still applies,
  backend-agnostically.** Nothing about switching to Kanidm removes the
  risk of locking yourself out when you flip an enforcement setting. The
  six-step discipline (verify at the real login screen, test break-glass
  first, hold multiple sessions open, pre-write the revert command, clear
  caches, verify from logs not user report) should be treated as a
  standing runbook item for dc2's own Kanidm enforcement rollout, not
  something to rediscover — see `docs/runbooks/kanidm-install.md`.
- **The "enrollment is not enforcement" compliance discipline in §2.7
  carries forward unchanged.** Whatever identity backend dc2 ends up
  asserting 3.5.3 against, the same rule applies: don't credit MFA as met
  until enforcement is applied *and* independently re-verified from logs,
  with no exceptions for "it worked when I tested it."
- **One open question this document does not resolve** (tracked in ADR
  0001's open questions): does Kanidm, built from source, behave
  correctly on a FIPS-enabled host? The incidents above all occurred on a
  FIPS-enabled system using a fully FIPS-covered crypto stack. Kanidm
  built from source uses Rust cryptography not covered by the system
  OpenSSL FIPS policy — this needs its own validation pass on dc2's
  actual FIPS-enabled base, not an assumption that "it worked in the
  spike" is sufficient, given the spike's FIPS status is itself an open
  question in ADR 0001.
