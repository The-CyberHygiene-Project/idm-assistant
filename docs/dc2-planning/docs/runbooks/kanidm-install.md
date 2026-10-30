# Runbook — Kanidm production install on dc2

Applies the lessons from the throwaway spike VM (validated 2026-08-21, see
`docs/adr/0001-replace-freeipa-with-kanidm.md`) directly to dc2's real build,
so they are applied proactively rather than rediscovered.

**Status: step 4 is BLOCKED. Do not run a live init until it is unblocked —
see below.**

---

## Step 4 — BLOCKED: domain/origin

**Do not run a live Kanidm init with real identity enrollment until this
step's value is settled.**

Kanidm's `domain`/`origin` is set once, at first `kanidmd` init, and is
effectively permanent afterward: WebAuthn credentials are cryptographically
bound to it, so changing the value later means every enrolled credential has
to be thrown away and re-enrolled from scratch. This makes the domain choice
a one-way door.

dc2 is relocating to Oklahoma City as a parallel project (dc1 and diwai
remain in Albuquerque, unaffected). The Oklahoma City site will run on a
**new domain name**, its own ISP, and a new NetGear router — a genuinely
separate network, not a relocated copy of `cyberinabox.net`. The domain has
not been registered as of this writing.

**The value this runbook originally used, `dc2.cyberinabox.net`, is void. Do
not use it.** If a session (human or AI) is about to run `kanidmd` init or
otherwise commit dc2 to a domain/origin value, stop and confirm the real
domain has been registered first.

**Safe to do while blocked**: steps 1, 2, 3, 5, 6, 7 below are mechanical
prep — building binaries, packaging systemd units, getting the TLS
mechanics right — and don't commit to a domain value. Do them now if useful;
just don't run the actual init in step 4 or proceed past it into step 8
(real identity enrollment) until the domain exists.

---

## The 9 steps

1. **Install `rustup`/`cargo`.** The system `dnf` cargo package is too old
   (needs 1.93+). Same approach as the spike.

2. **`kanidmd` server via podman container** (`docker.io/kanidm/server`), but
   **systemd-unit-managed this time, not ad-hoc `podman run`.** The spike's
   container died silently on every hard power-cycle (`virsh destroy`) —
   avoid repeating that on dc2 by making it a proper managed service from the
   start.

3. **Generate a properly long-lived TLS cert from the start** — not
   `kanidmd cert-generate`'s 5-day default. The spike's 5-day cert expired
   mid-investigation and produced a confusing "offline" episode that cost
   real debugging time for no reason. Don's own instruction after that
   incident, not just a preference.

4. **Domain/origin.** BLOCKED — see above. When unblocked: set to dc2's real
   registered Oklahoma City domain, matching dc2's real hostname there (the
   spike used a synthetic `kanidm-spike.local`; dc2's real value must be the
   actual production domain, not a placeholder).

5. **Build `kanidm_unix_int` / `nss_kanidm` / `pam_kanidm` from source**, tag
   v1.10.5 (the version already validated end-to-end on the spike — don't
   introduce a version bump as a second unknown alongside the production
   build itself), with **`KANIDM_BUILD_PROFILE=release_linux` set from the
   very first build.** The spike's default build pointed the daemon and PAM
   module at `/tmp/unixd` (a dev-only default) and had to be rebuilt once
   this was discovered — set it correctly from the start on dc2.

6. **Install binaries with `StateDirectory=kanidm-unixd` in the systemd unit
   from the start.** The upstream example unit
   (`examples/systemd/kanidm-unixd.service`) is missing this — the daemon
   needs `/var/lib/kanidm-unixd/hsm-pin` and fails to start without it. The
   spike hit this and fixed it after the fact; don't repeat that on dc2.

7. **`/etc/nsswitch.conf`: put `kanidm` last** in the `passwd` and `group`
   lines, from the start. This is a known upstream recursion bug
   ([kanidm/kanidm#2632](https://github.com/kanidm/kanidm/issues/2632)) — a
   request to `kanidm_unixd` can recursively trigger another NSS lookup that
   routes back through `libnss_kanidm.so` while the first request's worker
   lock is still held, causing a hang, if `kanidm` is listed first. The
   spike hit this; dc2 doesn't need to.

8. **Create real Kanidm identities** (blocked on step 4): primary credential
   (+ WebAuthn/TOTP), POSIX-enable, and **explicitly run
   `person posix set-password`** for each account. This exact step being
   skipped is what cost an entire multi-day debugging thread on the spike —
   `_unix/_auth` (what `su`/PAM actually calls) is a completely separate,
   single-factor mechanism from the primary credential, with its own
   dedicated password. Skipping this step guarantees every PAM login attempt
   is denied regardless of what's typed, with no clear error pointing at the
   real cause.

9. **Verify via real console login** (`virsh console` — or on dc2's real
   bare-metal hardware, the actual physical console — plus `su -`), **not
   SSH/`expect` automation.** The spike's automated PTY-driven `su` tests
   showed a spurious ~15-40 second stall that looked exactly like a hang but
   wasn't — confirmed via a VNC/real-keyboard console test showing no such
   delay (see ADR 0001's evidence section, item 5). Test the real way first;
   don't waste time re-diagnosing that artifact on dc2 too.

---

## Also apply, not part of the numbered sequence

- **MFA enforcement safeguards** (from the dc1 MFA lessons-learned
  narrative, currently in the project's private working archive pending a
  public-release decision): never flip enforcement on an account without a
  second independently-verified working session already open, and without
  break-glass access confirmed functional first. Six-step checklist: prove
  the new credential at the real login screen while the old method still
  works; test break-glass first if untested; hold multiple verified sessions
  open through the change; know the exact revert command before running the
  enforcement command; clear cached negative-auth state immediately after;
  verify success from logs, not from "it seems to work."
- **Don't credit MFA (3.5.3) as met on enrollment alone.** Enrollment and
  enforcement are different claims. Track as open until enforcement is
  applied *and* independently re-verified from logs.
