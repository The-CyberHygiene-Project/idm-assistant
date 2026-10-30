# dc2 Planning & Intent Documents — Inventory

Compiled 2026-09-14. Source of truth for all of this is Claude Code's memory
store at `~/.claude/projects/-home-dshannon/memory/` on dc2 — nothing
planning-related exists anywhere else on this disk (checked `/root`, shared
mounts, and a full filesystem sweep for stray `.md` files).

## Planning / intent — guides future work

### `project_kanidm_pivot.md` (most substantial — the identity-layer plan)

- **Decision** (2026-08-14): dc2 will **not** run FreeIPA. Replaced by four
  independent pieces: Kanidm (auth), a separate SSH CA, step-ca (TLS/ACME),
  standalone BIND (DNS) — deliberately *not* one bundled product, because
  FreeIPA's bundling is what caused repeated operational pain on dc1 (CA
  drift, Kerberos FAST/OTP bugs, SELinux relabel bugs) at a scale (1 server,
  5-7 workstations) that doesn't need enterprise-grade identity
  infrastructure.
- **Spike VM validation** (throwaway, dc1-hosted) fully resolved as of
  2026-08-21 — Kanidm's TOTP login, NSS, and PAM (`kanidm_unixd`) all
  confirmed working end-to-end. Several real bugs found and fixed along the
  way (build profile flag, missing systemd `StateDirectory`, an nsswitch
  ordering bug matching a known upstream issue, and the big one — POSIX
  accounts need a *separate* `person posix set-password`, distinct from the
  primary credential).
- **Real dc2 install: a concrete 9-step plan exists, ready to execute** —
  apply every spike lesson proactively (long-lived TLS cert from the start,
  correct nsswitch order, `StateDirectory` in the unit file, POSIX password
  set explicitly, verify via real console not SSH automation). **Current
  status: only build dependencies installed (`git gcc openssl-devel
  pam-devel lld` etc.) — the actual Kanidm install has not started.** This
  is the clearest "next step" in all the dc2 documentation.
- Open questions never confirmed with Don: narrow "clean dc1 replacement"
  vs. the fuller golden-disk/MSP vision; public repo destination for
  lessons-learned; a stale Synology network check.

### `project_server_deployment_golden_disk.md` (the broader vision dc2 is one instance of)

- Concept: a pre-imaged ~2TB "golden disk" shippable to a technician/MSP,
  with a commissioning script that swaps placeholder business identity for
  real values — server-side counterpart to a workstation enrollment track.
- Important unresolved technical caveat: FreeIPA can't safely be
  clone-and-rename'd (embeds install-specific crypto material) — recommended
  fix was fresh `ipa-server-install` at commissioning time. This constraint
  is now moot for dc2 specifically since Kanidm replaced FreeIPA, but the
  golden-disk concept itself (and the same regen-per-deployment principle
  for `/etc/machine-id`/SSH host keys) still applies.
- **Staged validation plan, still the intended shape**: (1) prototype on
  dc1 — done, this is dc2 itself; (2) deployment test on DC20 — not
  started; (3) production/public release — not started.
- Explains why RS#2 (the Mac Mini) was rejected as a dc1-replacement path
  (single spindle, no network segmentation) — a settled decision, not open.

## Build log — what happened, not what's planned

### `project_dc2_build.md`

The disk's actual history: Rocky 9.8+FIPS kickstart, LUKS layout/
credentials, the physical-relocation-to-DC20 plan and its TPM2 constraint,
root/sudo access pattern, and later findings from a 2026-09-14 boot-test
session (a namespace/sysctl compliance tailoring, a SCAP datastream
mismatch — the kickstart pointed at RHEL9-targeted content instead of the
Rocky-native `ssg-rl9-ds.xml`, silently breaking scan applicability — and
the OnlyOffice Desktop Editors install with its Wayland/XCB fix).

## Context, not planning

`MEMORY.md` (index), `user_risk_philosophy.md`, `user_accessibility.md`,
and four `feedback_*.md` files — these shape *how* to work with Don, not
*what* to build next.

---

## Bottom line

The Kanidm real-install (9-step plan, dependencies already staged) is the
most concrete, ready-to-execute next piece of work on dc2 itself. The
golden-disk DC20 deployment test is the next milestone after that.

---

## Today's session (2026-09-14) — what actually happened

This session started as a USB boot test of dc2's physical SSD (attached to
an HP MicroServer for troubleshooting, DC20's own boot disk left untouched)
after the top GRUB menu entry failed. It turned into several concrete
pieces of work, all live on the disk now:

### Boot failure — root cause and fix
The system was actually reaching `graphical.target` fine; the visible
symptom was a string of `irqbalance.service`/`upower.service`/GNOME-session
failures logged as "No space left on device." Root cause:
`/etc/sysctl.d/user_max_user_namespaces.conf` — installed by the original
2026-08-15 kickstart's OpenSCAP "cui" hardening profile (`CCE-83956-3`) —
had set `user.max_user_namespaces = 0`, which conflicts with `PrivateUsers=`
sandboxing in those units. Fixed by raising it to `15000` (SSG's own rule
text says a non-zero value is expected when containers/desktop apps are
present — dc2 has both `@container-management` and
`@graphical-server-environment`). `systemctl --failed` is clean now.

### SCAP compliance-scan finding (significant, separate from the above)
The kickstart's OpenSCAP addon pointed at `ssg-rhel9-ds.xml` (RHEL-targeted
CPE data), not `ssg-rl9-ds.xml` (Rocky-native content, already installed
alongside it). On this Rocky box that makes nearly every platform-gated
rule silently report `notapplicable` instead of a real pass/fail — a scan
against the wrong file looks "clean" only because almost nothing was
actually checked. Confirmed concretely: RHEL9 content → 0 pass/0 fail;
Rocky-native content → 100 pass/3 fail (now 2, see below). **Any future
compliance scan on dc2 must target `ssg-rl9-ds.xml`.**

An XCCDF 1.2 tailoring file documenting the `max_user_namespaces` deviation
was built, schema-validated, and installed at
`/etc/scap/tailoring/dc2-cui-tailoring.xml` (profile id
`xccdf_net.cyberinabox_profile_cui_dc2`) — empirically verified to change
exactly that one rule's result and nothing else. Usage:
```
oscap xccdf eval --profile xccdf_net.cyberinabox_profile_cui_dc2 \
  --tailoring-file /etc/scap/tailoring/dc2-cui-tailoring.xml \
  /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
```

Two real fails remain, deliberately not chased further (Don's call — SCAP/
STIG/NIST detailed compliance work is a stated future activity, not to be
pursued proactively right now): `grub2_password` (no GRUB bootloader
password set) and `service_usbguard_enabled` (usbguard installed but not
running as a service). A third item Don recalled from SCAP Workbench
("named users") couldn't be matched to any actual rule in scope for the
"cui" profile — worth re-checking with Jeff directly in Workbench rather
than assuming what it was.

### OnlyOffice Desktop Editors installed
Installed via the official OnlyOffice RPM repo (GPG key properly imported,
not bypassed). As anticipated going in: OnlyOffice has no native Wayland
support and crashes with a fatal `QXcbConnection` error on dc2's native-
Wayland GNOME session — a currently open, unresolved upstream issue, not
specific to this box. Fixed with `QT_QPA_PLATFORM=xcb` (forces it through
XWayland), applied via two upgrade-safe overrides that won't be lost on a
package update:
- `~/.local/share/applications/onlyoffice-desktopeditors.desktop` (GUI/
  Activities launches)
- `~/.local/bin/onlyoffice-desktopeditors` + `desktopeditors` symlink
  (terminal launches, ahead of the real binary in `$PATH`)

Confirmed working live (Don launched it directly), and all four "New
document/spreadsheet/presentation/PDF" desktop actions tested clean.

### Succession context (new today)
Don confirmed Jeff Shannon (his son) is taking over as dc2's investigator/
developer. A local `jeffshannon` OS account already exists on dc2. Don
plans to share his Claude account with Jeff but has "clean-up and turnover
to do first" — not yet done as of this writing. See
`project_dc2_succession.md` in the Claude memory store for the full note.
This document itself is turnover-checklist item 1.
