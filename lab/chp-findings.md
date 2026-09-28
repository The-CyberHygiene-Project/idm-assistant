# CHP build kit: findings from the Kanidm lab (Plan 4, client1)

**Kit:** `~/Desktop/chp-build` (CHP-SPEC v0.1, `chp-build.sh` 1.0.0). Run **unmodified** from a fresh copy per command (`lab/client/chp-run.sh`, sha256 guard `lab/client/chp-kit.sha256`). Lab values: `lab/client/chp-placeholders.lab.md`.
**Host:** client1: Rocky 9.8, UEFI + Secure Boot (OVMF, Microsoft keys), swtpm TPM 2.0, FIPS, Server with GUI, PARTITIONS_3 (512 GB layout, thin), LUKS2 over LVM (swap inside), root unlocked by TPM PCR 7. **Not** an HP Elite Mini.
**Logs:** `lab/chp-logs/` (each copied only after the secrets scan passed).

## 1. The kit on a non-HP UEFI VM

| Step | Kit message | Cause | Verdict |
|---|---|---|---|
| apply-placeholders | writes `chp-build.<system-name>.sh` and leaves `chp-build.sh` untouched; running `chp-build.sh` then refuses ("6 placeholder(s) remain") | by design; the README/usage text says `./chp-build.sh …` in places, while the tool's own final message names the generated script | **kit correct**; doc nit: say "run the generated script" everywhere |
| preflight | `WARN not an HP chassis — the firmware checks below may not apply` | lab VM | lab artefact, correctly a warning |
| preflight | OK: Rocky 9, UEFI, Secure Boot enabled, TPM 2.0 present, FIPS (policy FIPS), `/boot/efi`, every data-bearing device under LUKS, SCAP datastream found → **PREFLIGHT PASSED** | kickstart built the kit's preconditions | **kit correct** |
| plan | 37-line change plan (boundary, crypto, identity: sssd + PAM MFA on sshd/login/sudo, break-glass `chpbreak`, perimeter default-deny + egress deny, logging, OpenSCAP baseline, fapolicyd + usbguard, evidence, backup; AIA not implemented), config backup path and a `rollback` command | — | **kit correct**; clear and reviewable |

## 2. Verify results (before Kanidm)

_Task 5._

## 3. Kit vs Kanidm (ADR 0001) collisions

_Task 6._

## 4. MFA at login: Google Authenticator + Kanidm POSIX password

_Task 7._

## 5. SELinux labels on Kanidm homes and `~/.google_authenticator`

_Task 7._

## 6. Proposed kit changes (text only; the kit is not modified)

_Task 8._

## 7. Open questions for the ISSO (spec §9 question 5)

_Task 8._
