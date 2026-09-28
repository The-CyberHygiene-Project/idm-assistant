# Plan 4: client1 Built With the CHP Kit, Then Kanidm: Collisions and Root-Volume TPM Unlock (M4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build **client1** exactly as the CHP build kit expects: UEFI with Secure Boot, Server with GUI, FIPS, the PARTITIONS_3 512 GB layout, and LUKS encryption at rest. Run the kit **unmodified from a copy** (`preflight → plan → harden → verify → evidence`), then add the Kanidm client (unixd). Record exactly where the kit and ADR 0001's Kanidm client path collide, in `lab/chp-findings.md`.

The same machine also answers the question left open by Plan 3's TPM experiment: can the **root** volume unlock automatically through the TPM when Secure Boot makes PCR 7 meaningful?

**Architecture:**
- client1 is a UEFI (OVMF, Secure Boot, enrolled Microsoft keys) q35 VM with a software TPM, on aero's `br-lab`.
- It is installed unattended from the DVD by a kickstart that creates the kit's preconditions, and nothing more. The kit itself applies the CUI baseline.
- The root LUKS volume is bound to the vTPM with clevis in `%post`, so the lab VM boots without a typed passphrase.
- The kit's one package that isn't on the DVD (`google-authenticator`, EPEL) is fetched and GPG-verified on the Mac with a pinned key, then served from `lab-local`.
- The Kanidm client is added with Plan 3's tested enrolment, parameterised by the authselect profile the kit leaves in place.

**Tech Stack:** Rocky 9.8 kickstart + libvirt/OVMF Secure Boot + swtpm (aero); CHP build kit (`~/Desktop/chp-build`, used from a copy); clevis/dracut; kanidm-unixd (Plan 2 RPMs); `expect`; pytest.

**Spec:** `docs/superpowers/specs/2026-09-26-idm-diagnostic-lab-design.md` (rev 2: §4.3 client1 row, **§4.5**, §7 M4)

## Why run this test: what we will know afterwards that we don't know now

| Question | What we know today | What we'll know after Plan 4 | Why it matters |
|---|---|---|---|
| **1. Does the CHP kit build a compliant host in practice?** | The kit exists and was written for an HP Elite Mini; it has never been run end to end in this lab. | Every preflight/harden/verify result on a real (virtual) CHP host, every failure and every wrong assumption, in `lab/chp-findings.md`. | The kit is the CyberHygiene Project's reference build; its defects matter to anyone using it. |
| **2. What happens when a CHP-hardened host joins Kanidm?** | Predicted from reading the kit: it selects authselect `sssd`, inserts `pam_google_authenticator` (no `nullok`) into sshd/login/gdm/sudo, and offers `realm join --client-software=sssd`. ADR 0001's client is `kanidm_unixd` + Kanidm. | The exact collisions: authselect profile fights, PAM order, whether a Kanidm user is locked out without a Google Authenticator token, double prompts, and what the kit's `verify` says afterwards. | This decides how the CHP kit must treat identity once Kanidm replaces FreeIPA (spec §9, ISSO question 5). |
| **3. Does the kit's Google Authenticator give the MFA that Kanidm doesn't?** | Plan 3: a Linux login through Kanidm is **single-factor** (POSIX password). | Whether POSIX password (Kanidm) **plus** a TOTP (Google Authenticator) works as two factors at SSH, console and sudo, and whether the CUI sshd setting (`KbdInteractiveAuthentication no`) blocks it. | A candidate answer to the 3.5.3 gap found in Plan 3. |
| **4. Can the root volume unlock unattended via the TPM, bound to a meaningful PCR?** | Plan 3: a *data* volume unlocks via the TPM, but lab PCRs were all zero (SeaBIOS). | Whether a UEFI Secure Boot VM gives a non-zero, stable PCR 7, and whether clevis unlocks the **root** LUKS volume at boot with it. | The dc2 disk-encryption design (root volume + unattended reboot). |
| **5. Do the SELinux home-directory labels break TOTP logins?** | dc1's MFA lockout was SELinux denying gdm access to `~/.google_authenticator` (wrong label). | The labels on home directories created by Kanidm's unixd, and on `~/.google_authenticator` files in them, plus the AVCs at login. | It's the dc1 failure mode (scenario L2) observed naturally, not staged. |

**What Plan 4 will *not* tell us:**
- a graphical (gdm) login: it isn't automatable here. The console, SSH and sudo paths are tested, and gdm is listed as a manual follow-up;
- the collector and repairs (Plan 5);
- the dc2 installer ISO (a separate project after Plan 4, per the ISSO, 2026-09-28).

## Decisions (ISSO, approved 2026-09-28: "Yes this looks good")

1. **client1's kickstart creates only the kit's preconditions**: FIPS, Server with GUI, PARTITIONS_3 layout, and LUKS2 over LVM with swap inside. It does **not** apply the CUI profile at install (unlike srv1/client2), because the kit's own `harden` applies the baseline. Applying both would hide which one did what.
2. **The root LUKS volume is unlocked by the virtual TPM (clevis, PCR 7)**, so the lab VM reboots unattended. The passphrase slot stays as the fallback. The passphrase is generated on the Mac into `~/idm-lab-secrets/client1-luks.pass`, put into the rendered kickstart, and the rendered kickstart is shredded after install.
3. **Download `google-authenticator` from EPEL 9** on the Mac, verified against the EPEL 9 key with fingerprint `FF8AD1344597106ECE813B918A3872BF3228467C` ("Fedora (epel9)"). It's the only package the kit needs that isn't on the Rocky DVD. Please confirm the fingerprint independently if you wish; it was read from `dl.fedoraproject.org` on 2026-09-28.
4. **Lab values for the kit's six settings:**
   - `CHP_SYSTEM_OWNER` = `CyberHygiene Project Lab`
   - `CHP_ORG_NAME` = `CyberHygiene Lab`
   - `CHP_SYSTEM_NAME` = `Kanidm Lab client1`
   - `CHP_DOMAIN` = `kanidm.lab.test`
   - `CHP_WAN_ADDR` = `none`
   - `CHP_OFFLINE_TARGET` = `none`
5. **The kit runs without `--safe`** (spec §4.5); disruptive steps are safe because of snapshots.
6. **The kit is never modified.** Everything runs from a copy in `lab/chp-run/` on client1. Fixes to the kit are *proposed* in `lab/chp-findings.md`, never applied to the kit.

## Global Constraints

- Offline: packages come only from the DVD and `lab-local` via aero (`http://192.168.100.1:8080/`), with no default route.
- client1: 192.168.100.12 (`client1.kanidm.lab.test`, already in the srv1 zone), **2 vCPU / 4 GB**, **512 GB thin** qcow2 (spec §4.3). The actual space used stays small.
- UEFI + Secure Boot (OVMF `secboot` code, Microsoft keys enrolled, q35, SMM); swtpm TPM 2.0 (`tpm-crb`).
- FIPS (`fips=1`), SELinux enforcing. The CUI baseline comes from the kit (Decision 1).
- Secrets never enter the repo (`lab/tools/secrets-scan.sh` before every commit). The LUKS passphrase, Google Authenticator seeds, break-glass passphrase and lab user secrets all live in `~/idm-lab-secrets` only.
- The kit (`~/Desktop/chp-build`) is read-only. `chp-apply-placeholders.sh` runs against a **copy**.
- The independent cross-check rule still holds: no dc2-repo Kanidm runbooks; findings stay in this repo.

## Review Focus

1. **The kit's harden silently replaces the Kanidm authselect profile** (it runs `authselect select sssd …`), and a later "Kanidm works" claim is really testing a stale state. The collision test re-reads `authselect current`, the rendered PAM files and nsswitch **after every step**, and records the diff. *Task 6, Step 2.*
2. **A lockout of the lab VM** (Google Authenticator required with no `nullok`, plus sshd hardening), leaving only the console. Every PAM/sshd change is preceded by a snapshot. The `itadmin` key login and the break-glass console path are checked before moving on; recovery is `virsh snapshot-revert`, never guessing. *Tasks 5 and 6.*
3. **Root TPM unlock "works" only because the passphrase was cached or typed.** The proof is a cold boot (`virsh destroy` + `start`) with the serial console showing no passphrase prompt, plus a negative test (Secure Boot state changed → the TPM refuses → prompt appears). *Task 3, Steps 4–5.*
4. **A Google Authenticator seed or the LUKS passphrase leaks** into the repo, logs or process arguments. Seeds are generated on client1 by the `google-authenticator` tool itself, copied to the Mac over SSH stdout, and never echoed. The secrets scan runs before each commit. *Tasks 3, 7.*
5. **Kit failures blamed on the lab** (or the reverse). Every kit failure is recorded with the kit's own message and the lab condition that caused it (e.g. "not an HP chassis", no internet) *before* any workaround. Workarounds live outside the kit copy. *Tasks 4–5.*

---

## File Structure

| Path | Responsibility |
|---|---|
| `lab/inputs/fetch-epel.sh` + `MANIFEST.txt` rows | fetch + GPG-verify `google-authenticator` (and any EPEL-only dependency) with the pinned EPEL 9 key |
| `lab/kickstart/client1.ks.in` + `render.sh` entry | client1 kickstart: kit preconditions + clevis root binding |
| `lab/kickstart/test_render.sh` | extended with client1 cases |
| `lab/host/b10-vm-client1.sh` | UEFI Secure Boot + vTPM VM via `create_vm` |
| `lab/client/chp-placeholders.lab.md` | the lab's filled-in `PLACEHOLDERS.md` (no secrets) |
| `lab/client/chp-run.sh` | copies the kit to client1, applies placeholders to the copy, runs one kit command, collects its log/evidence |
| `lab/client/10-enrol.sh` | gains `AUTHSELECT_BASE` (default `custom/hardening`; client1: whatever the kit selected) |
| `lab/client/chp-collisions.sh` | snapshot of identity state (authselect, PAM files, nsswitch, sshd -T, AVCs) to diff between steps |
| `lab/chp-findings.md` | the deliverable: kit findings + kit-vs-Kanidm collisions + proposed kit changes |
| `lab/tpm-luks-experiment.md` | extended: the root-volume + Secure Boot PCR 7 result |

---

### Task 1: Fetch and verify `google-authenticator` from EPEL 9

**Files:** Create `lab/inputs/fetch-epel.sh`; modify `lab/inputs/MANIFEST.txt`, `lab/inputs/verify.sh` (EXPECTED stays 6; the EPEL files are verified with `EXPECTED_OVERRIDE` where pushed)

- [ ] **Step 1: Write the two halves.** The Mac has no `rpm`, so the RPM signature check runs on build1 (Rocky).

`lab/inputs/fetch-epel.sh` (Mac): fetches the key and packages; checks the key's fingerprint.
```bash
#!/usr/bin/env bash
# Fetch EPEL-9 RPMs the CHP kit needs that the Rocky DVD lacks, and the EPEL 9 key (fingerprint pinned).
# The RPM signatures are then checked on a Rocky host by verify-epel.sh (rpm is not available on macOS).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
# shellcheck source=gpgcheck.sh
source "$here/gpgcheck.sh"
fpr_ok() { gpg --batch --with-colons --fingerprint "$1" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}' | grep -qx "$1"; }
EPEL_FPR=FF8AD1344597106ECE813B918A3872BF3228467C
BASE=https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages
PKGS=(g/google-authenticator-1.09-5.el9.x86_64.rpm)
gpg_sandbox
curl -fsSL https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-9 -o "$IN/RPM-GPG-KEY-EPEL-9"
gpg --batch --import "$IN/RPM-GPG-KEY-EPEL-9" 2>/dev/null
fpr_ok "$EPEL_FPR" || { echo "EPEL 9 key fingerprint mismatch"; exit 1; }
for p in "${PKGS[@]}"; do f="$IN/$(basename "$p")"; [[ -s $f ]] || curl -fsSL "$BASE/$p" -o "$f"; echo "fetched $(basename "$f")"; done
```
`lab/inputs/verify-epel.sh` (runs on build1 with the files in `~/inputs`): verifies each RPM against the pinned key in a private rpm database, and prints its dependencies.
```bash
#!/usr/bin/env bash
set -Eeuo pipefail
IN="${IDM_INPUTS:-$HOME/inputs}"; db=$(mktemp -d); trap 'rm -rf "$db"' EXIT
rpm --dbpath "$db" --import "$IN/RPM-GPG-KEY-EPEL-9"
rpm --dbpath "$db" -q gpg-pubkey --qf '%{version}\n' | grep -qx 3228467c || { echo "unexpected key in db"; exit 1; }
for f in "$IN"/*.el9.x86_64.rpm; do
  [[ $f == *google-authenticator* ]] || continue
  rpm --dbpath "$db" -K "$f" | grep -q 'digests signatures OK' || { echo "SIGNATURE FAIL: $f"; exit 1; }
  echo "OK signed by EPEL 9: $(basename "$f")"; rpm -qpR "$f" | grep -vE '^(rpmlib|/)' | sort -u
done
```
Run both (push the files to build1 with `lab/vm/push-build1.sh RPM-GPG-KEY-EPEL-9 google-authenticator-1.09-5.el9.x86_64.rpm`, then `ssh build1 bash ~/scripts/…/verify-epel.sh`).
Expected: the fingerprint matches; `OK signed by EPEL 9`; a dependency list. For every dependency that isn't on the DVD (check `dnf -q repoquery --repo lab-baseos,lab-appstream --whatprovides <dep>` on srv1), add its EPEL path to `PKGS` and repeat.

- [ ] **Step 2: Add MANIFEST rows (name|ver|bytes|sha256|source|verification), copy into aero's `lab-local`, re-index.**
Expected: `dnf -q repoquery --repo lab-local google-authenticator` on srv1 lists `1.09-5.el9`.

- [ ] **Step 3: Commit** (`lab/inputs/fetch-epel.sh`, `MANIFEST.txt`).

---

### Task 2: client1 kickstart (the kit's preconditions + clevis root binding)

**Files:** Create `lab/kickstart/client1.ks.in`; modify `lab/kickstart/render.sh` (client1 entry: IP .12, separate template, `@LUKSPASS@` from `~/idm-lab-secrets/client1-luks.pass`), `lab/kickstart/test_render.sh`

- [ ] **Step 1: Failing render tests** (add to `test_render.sh`): client1 renders; validates (RHEL9); contains `fips=1`; has **no** `com_redhat_oscap` addon (Decision 1); has `@^graphical-server-environment`; every PARTITIONS_3 mount exists (`/boot/efi`, `/boot`, `/`, `/home`, `/tmp`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit`, swap); the PV line has `--encrypted --luks-version=luks2`; swap is a **logical volume** (inside LUKS); the passphrase placeholder is replaced, and **the test's rendered file is removed afterwards**. Run → RED.

- [ ] **Step 2: Write `client1.ks.in`.** It is based on `base.ks.in` with:
  - `bootloader --append="fips=1"`;
  - `part /boot/efi --fstype=efi --size=1024`;
  - `part /boot --fstype=ext4 --size=2048`;
  - `part pv.01 --size=1 --grow --encrypted --luks-version=luks2 --passphrase=@LUKSPASS@`;
  - `volgroup rl_client1 pv.01`;
  - logvols in GiB × 1024 from PARTITIONS_3's 512 GB column: swap 16, `/home` 40, `/tmp` 16, `/var` 60, `/var/tmp` 10, `/var/log` 20, `/var/log/audit` 20, `/` `--grow`;
  - `%packages`: `@^graphical-server-environment`, `clevis clevis-luks clevis-dracut clevis-systemd tpm2-tools mokutil`;
  - the same `%post` as base (sudoers, chrony, lab.repo), **without** the namespace-sysctl lines (the kit, not the kickstart, owns the baseline), plus:

```
# Bind the root LUKS volume to the vTPM (PCR 7 = Secure Boot state) so the lab VM boots unattended; passphrase stays as fallback.
DEV=$(blkid -t TYPE=crypto_LUKS -o device | head -1)
printf '%s' '@LUKSPASS@' > /root/.lp && chmod 600 /root/.lp
clevis luks bind -y -k /root/.lp -d "$DEV" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
shred -u /root/.lp
dracut -f --regenerate-all
```
  Run `test_render.sh` → GREEN.

- [ ] **Step 3: Commit.**

---

### Task 3: Create client1 (b10) and prove root TPM unlock

**Files:** Create `lab/host/b10-vm-client1.sh`; modify `lab/host/push.sh` (render client1; the rendered file is removed from the Mac and aero after install), `lab/vm-deviations.md`, `~/.ssh/config`

- [ ] **Step 1: b10**

```bash
#!/usr/bin/env bash
# b10: client1 = UEFI + Secure Boot (MS keys enrolled) + vTPM, 4 GB, 2 vCPU, 512 GB thin (PARTITIONS_3, CHP kit).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=vm-lib.sh
source "$(dirname "$0")/vm-lib.sh"; need_root
create_vm client1 2 4096 512 /tmp/lab-host/client1.ks \
  --machine q35 --features smm.state=on \
  --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes \
  --tpm emulator,model=tpm-crb,version=2.0
shred -u /tmp/lab-host/client1.ks   # contains the LUKS passphrase
log "b10 done"
```
Add a stub case to `test_vm_create.sh` asserting the UEFI/secure-boot arguments reach virt-install (RED → GREEN).

- [ ] **Step 2: Install** (Server with GUI takes ~15–25 min; run in the background). Expected: `b10 done`. If virt-install rejects the firmware feature syntax, record it and use the `--boot loader=/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd,loader.readonly=yes,loader.type=pflash,nvram.template=/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd` form (ruling).

- [ ] **Step 3: Posture.** Add `Host client1` to `~/.ssh/config`. Run: `ssh client1 'mokutil --sb-state; fips-mode-setup --check; getenforce; lsblk -o NAME,FSTYPE,MOUNTPOINT | head -20; sudo clevis luks list -d $(sudo blkid -t TYPE=crypto_LUKS -o device | head -1); sudo tpm2_pcrread sha256:7'`
Expected:
- `SecureBoot enabled`, FIPS enabled, `Enforcing`;
- every PARTITIONS_3 mount inside the LUKS container, **swap included**;
- a `tpm2` clevis slot;
- a **non-zero** PCR 7.

- [ ] **Step 4: Cold boot, no passphrase** (Review Focus #3). Run: `ssh aero 'sudo virsh destroy client1; sudo virsh start client1'`, wait for SSH. Then check the serial log: `ssh aero 'sudo grep -c "Please enter passphrase" /var/log/libvirt/qemu/client1-install.log'` compared with the count before the boot.
Expected: SSH returns and **no new passphrase prompt** appears. Unattended root unlock is proven.

- [ ] **Step 5: Negative test.** Change the Secure Boot state: disable it with `virsh` NVRAM edit, or boot once with an alternative OVMF_VARS without enrolled keys. Record which method was used. Expected: the PCR 7 value differs, clevis refuses, and the console shows the **passphrase prompt**. Answer it from aero with an `expect` script reading `~/idm-lab-secrets/client1-luks.pass` over stdin. Restore Secure Boot, then confirm the unattended boot again.

- [ ] **Step 6: Snapshot `os-ready`; log the deviations; commit.** Record in `lab/tpm-luks-experiment.md`:
  - the PCR 7 value is non-zero and stable across reboots;
  - root unlock is unattended;
  - the negative-test result.

---

### Task 4: Run the kit: preflight and plan

**Files:** Create `lab/client/chp-placeholders.lab.md`, `lab/client/chp-run.sh`, `lab/chp-findings.md` (skeleton)

- [ ] **Step 1: `chp-placeholders.lab.md`**: the kit's `PLACEHOLDERS.md` table with Decision 4's values (no secrets).

- [ ] **Step 2: `chp-run.sh CMD [args]`** (Mac):
  - rsync a **fresh copy** of `~/Desktop/chp-build/` to `client1:/root/chp-run/` (via `/tmp` + `sudo install`);
  - copy `chp-placeholders.lab.md` in as `PLACEHOLDERS.md`;
  - run `./chp-apply-placeholders.sh PLACEHOLDERS.md chp-build.sh` **inside the copy**;
  - run `sudo ./chp-build.sh CMD args` with the output tee'd to `/root/chp-run/logs/CMD-<ts>.log`;
  - copy that log back to `lab/chp-logs/` **after** `secrets-scan.sh` passes on it.

  Guard: the script refuses to run if `~/Desktop/chp-build` differs from its recorded sha256 list (`lab/client/chp-kit.sha256`, created in this step). That proves the kit was never modified.

- [ ] **Step 3: Snapshot client1 `pre-kit`.** Run `lab/client/chp-run.sh preflight`, then `lab/client/chp-run.sh plan`.
Expected: preflight passes FIPS, mounts and CHP-CRY-02 (encryption), with **warnings** for the HP-specific checks ("not an HP chassis") that are recorded, not fixed. `plan` lists every change the kit intends. For each preflight WARN/ERR, add a row to `lab/chp-findings.md` §1 "Kit on a non-HP UEFI VM": message, cause, kit correct / kit assumption / lab artefact.

- [ ] **Step 4: Commit** the scripts, placeholders, logs and findings skeleton.

---

### Task 5: Run the kit: harden, verify, evidence (before Kanidm)

- [ ] **Step 1: Baseline the identity state.** Write `lab/client/chp-collisions.sh` (on client1, read-only). It prints:
  - `authselect current -r`;
  - sha256 and content of `/etc/pam.d/{system-auth,password-auth,sshd,login,gdm-password,sudo}`;
  - the `passwd`/`group`/`initgroups` lines of `/etc/nsswitch.conf`;
  - `sshd -T | grep -iE 'kbdinteractive|password|pubkey|authenticationmethods|usepam|trustedusercakeys|authorizedkeyscommand'`;
  - `ausearch --input-logs -m AVC -ts boot | grep -c type=AVC`.

  Save it as `lab/chp-logs/state-0-pre-harden.txt`.

- [ ] **Step 2: `lab/client/chp-run.sh harden --yes`** (without `--safe`). Expected: completes. For **every** failure, record the step, message and cause in findings §1 before any workaround. Workarounds live in `lab/client/`, never in the kit. Save the state as `state-1-post-harden.txt`.

- [ ] **Step 3: Access check** (Review Focus #2): `ssh client1 true` still works for `itadmin`, with its key, not a password. If the kit's sshd hardening or `pam_google_authenticator` blocks it, record it: that means an admin using keys needs a Google Authenticator token too. Then restore access through the console (break-glass flow per the kit) or `virsh snapshot-revert client1 pre-kit`, and note the exact fix needed.

- [ ] **Step 4: Enrol Google Authenticator for `itadmin` and the break-glass account** as the kit instructs (`google-authenticator -t -d -f -r 3 -R 30 -W`), run non-interactively on client1. Each secret file's seed goes straight to `~/idm-lab-secrets/client1-ga-<user>.json` over SSH stdout. Never echo it.

- [ ] **Step 5: `verify`, then `evidence`.** Record the verify summary (pass/fail per control family) in findings §2. Snapshot `kit-hardened`.

- [ ] **Step 6: Commit** (logs after secrets-scan, findings, `chp-collisions.sh`).

---

### Task 6: Add Kanidm to the CHP-hardened host, and record the collisions

- [ ] **Step 1: Parameterise `10-enrol.sh`**: `AUTHSELECT_BASE` (default `custom/hardening`; client1 = the profile the kit selected, read from `state-1`). Unit test via the existing patcher tests. Add a fixture of the kit's rendered `system-auth`/`sshd` PAM files from `state-1`, and a test that the patch keeps `pam_google_authenticator` and the kit's features.

- [ ] **Step 2: Enrol client1** with Plan 3's flow: service-account token `unixd-client1` (srv1 script with the host name as a parameter), root CA, `10-enrol.sh`, the SELinux module (`15-selinux.sh`).
  Then capture `state-2-post-kanidm.txt` and **diff state-1 → state-2** (Review Focus #1). Findings §3 records, for each of authselect, PAM (sshd/login/sudo/gdm-password), nsswitch and sshd: what changed and who "won".

- [ ] **Step 3: Re-run the kit's `verify` and `harden` (idempotency check).** Record:
  - whether `verify` now reports identity failures because Kanidm is present;
  - whether a second `harden` **reverts** Kanidm's authselect profile.

  Save `state-3-post-reharden.txt` and diff it against state-2.

- [ ] **Step 4: Snapshot `kanidm-added`; commit.**

---

### Task 7: Login matrix (which factors are asked, who is locked out)

**Files:** extend `lab/client/ssh-login.exp` to answer a Google Authenticator "Verification code" prompt from a named secrets file; create `lab/client/login-matrix.sh` (Mac) → `lab/chp-logs/login-matrix.md`

- [ ] **Step 1: Kanidm user without a GA token** (lab02): SSH with the POSIX password. Expected: **refused**, because `pam_google_authenticator` has no `nullok`. Record the prompts and the sshd/PAM log lines.
- [ ] **Step 2: Kanidm user with a GA token** (lab03). Create the home directory by one su as root (unixd-tasks creates it). Run `google-authenticator` as lab03 non-interactively; the seed goes to secrets. Then SSH with POSIX password + code. Record whether **both factors** are asked and accepted; this is the 3.5.3 candidate.
  - If the CUI sshd `KbdInteractiveAuthentication no` prevents the second prompt, record it.
  - Then test once with keyboard-interactive enabled **in a snapshot only**. That's a documented experiment, not a lab change.
- [ ] **Step 3: sudo and `su`** for lab01 (in `lab_admins`, with a sudoers drop-in for `%lab_admins@idm.kanidm.lab.test`). Record the prompts.
- [ ] **Step 4: SELinux labels** (question 5): `ls -Z` of Kanidm-created home directories and `~/.google_authenticator`, `matchpathcon`/`restorecon -nv` differences, and AVCs from Steps 1–3. Compare with the dc1 lockout pattern (`xdm_t` → `user_home_t`).
- [ ] **Step 5: Console login** (`virsh console` via an `expect` script on aero) for lab03: POSIX password + code. Break-glass account: console only; SSH refused, per `DenyUsers`.
- [ ] **Step 6: Write the login matrix** (user × path × prompts × result) into `lab/chp-logs/login-matrix.md`; commit.

---

### Task 8: Findings, reports, reset

- [ ] **Step 1: `lab/chp-findings.md`**, the deliverable for the ISSO and the kit's owner:
  - §1 kit on a non-HP UEFI VM (preflight and harden failures, wrong assumptions);
  - §2 verify results;
  - §3 kit vs Kanidm collisions (authselect, PAM, nsswitch, sshd, re-harden reverts);
  - §4 the MFA answer (Google Authenticator + Kanidm POSIX password as two factors, or not);
  - §5 SELinux home/GA labels;
  - §6 **proposed kit changes** (text only; the kit is not modified): e.g. a `CHP_IDENTITY=kanidm` mode, and `nullok` handling for directory users;
  - §7 open ISSO questions (spec §9 question 5).
- [ ] **Step 2: Extend `lab/tpm-luks-experiment.md`** with the root-volume + Secure Boot PCR 7 result, and `lab/adr0001-q1-packaging.md` §8 with any new unixd defects on a CHP host.
- [ ] **Step 3: `lab/reset.sh` learns client1** (snapshot `golden` = `kanidm-added`, taken after Task 7's clean-up). Test the reset: marker file, clock, served certificate.
- [ ] **Step 4:**
  - secrets scan;
  - full test suite;
  - shellcheck;
  - final whole-branch review;
  - pre-publication scan;
  - PR.

## Self-review notes
- **Spec §4.5 coverage:**
  - step 1 (kickstart: GUI, FIPS, PARTITIONS_3) → Task 2;
  - step 2 (lab PLACEHOLDERS, `CHP_DOMAIN=kanidm.lab.test`, `CHP_OFFLINE_TARGET=none`) → Task 4;
  - step 3 (`preflight → plan → harden → verify → evidence` without `--safe`) → Tasks 4–5;
  - step 4 (SSSD + GA vs unixd collisions: authselect, PAM order, double MFA prompts, `verify_identity`) → Tasks 6–7;
  - step 5 (`lab/chp-findings.md`) → Task 8.
- **§7 M4 user action** ("enrol TOTP for lab users when the kit asks") is automated in Tasks 5 and 7, with seeds going to `~/idm-lab-secrets`. The ISSO doesn't need to type.
- **Carried from Plan 3:** root-volume TPM unlock with a meaningful PCR 7 (Task 3); MFA gap candidate (Task 7); dc1 SELinux pattern (Task 7).
- **Not covered by design:** gdm login automation (listed as a manual follow-up).
