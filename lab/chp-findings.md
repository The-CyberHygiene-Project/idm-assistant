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
| harden (crypto) | writes `/etc/ssh/sshd_config.d/50-chp-spec.conf`: `PasswordAuthentication no`, `KbdInteractiveAuthentication yes`, `AuthenticationMethods keyboard-interactive:pam`, then **reloads sshd**, before the identity step installs/enrols Google Authenticator | kit ordering | **K0 (lockout):** SSH public keys stop being accepted at all. An admin with only a key (the normal build-time path) is locked out the moment sshd reloads. When harden then aborted (K1), nobody could log in: root locked, and the admin had no password and no token. Recovery: snapshot revert. **Fix:** enrol admins (password + GA) *before* the sshd step, or order the identity step first and refuse to reload sshd until at least one admin is enrolled |
| harden (identity) | `authselect feature enable with-pwhistory` → prints authselect usage; `aborted at line 274` | **K1:** authselect ≥1.5 syntax; Rocky 9.8 ships authselect 1.2.6 (`authselect enable-feature …`). Also redundant: the `select … with-pwhistory` just before already enables it | **kit bug.** Lab shim `lab/client/chp-shims/authselect` (logged). Fix: `enable-feature` or delete the line |
| harden (perimeter) | `firewall-cmd --permanent --set-log-denied=all` → "Can't use stand-alone options with other options"; `aborted at line 1096` | **K2:** `--set-log-denied` is stand-alone (always permanent) | **kit bug.** Lab shim `chp-shims/firewall-cmd` (logged). Fix: drop `--permanent` |
| harden (logging) | `mv: cannot move … to '/etc/systemd/journald.conf.d/50-chp-spec.conf': No such file or directory`; `aborted at line 309` | **K3:** `write_file()` never creates the parent directory; `journald.conf.d` doesn't exist on a fresh Rocky 9.8 | **kit bug.** Lab prep `lab/client/chp-prep-dirs.sh`. Fix: `install -d` the parent in `write_file` |
| harden (identity) | "Enrol every interactive account NOW … `su - <user> -c 'google-authenticator -t -d -f -r 3 -R 30 -W'`" | `google-authenticator` asks "Enter code from app (-1 to skip)" and fails without a terminal | doc/automation nit: pass `-1` on stdin or document `--no-confirm`-style use; also run it **before** the sshd step (K0) |
| first GA login (sshd) | correct code + password **refused**; AVC `denied { create } comm="sshd-session" name=".google_authenticator~XXXXXX" scontext=sshd_t tcontext=user_home_dir_t` | pam_google_authenticator saves replay/rate-limit state (`-d -r`) by creating a temp file in `$HOME` and renaming it; the random suffix defeats name-based labelling; `sshd_t` may not create `user_home_dir_t` files | **K7: the dc1 MFA-lockout pattern** (gdm/`xdm_t` there, `sshd_t` here), reproduced naturally on a kit-hardened host. The kit gives no SELinux handling. Lab: ISSO-approved narrow module `lab/selinux/chp_ga_lab.te` (temp file gets `auth_home_t`; sshd may create/rename only those). Then code + password login works, 0 AVCs |
| verify | `aborted at line 1982` after CRY-01 | **K5:** `last_offhost="$(grep -v '^#' "$ledger" | grep -v '^$' | tail -1)"` without `|| true` (the other three ledger reads have it); harden creates the ledger as a comments-only stub, so under `set -e` + `pipefail` verify always dies here | **kit bug.** Lab workaround `lab/client/chp-verify.sh` moves the stub aside for the run (nothing fabricated) |
| verify | CHP-CRY-01 and CHP-IDA-03 always **NOT MET** ("non-FIPS cipher: NEGOTIATED-OR-INCONCLUSIVE"; "single-factor sshd attempt was not clearly refused"), although sshd *does* refuse ("Unable to negotiate … no matching cipher found"; "Permission denied") | **K4:** `if timeout 10 ssh … 2>&1 | grep -qi …` under `pipefail`: ssh's own exit (255) becomes the pipeline status even when grep matched | **kit bug:** both negative tests can never pass. Fix: capture the output, then grep it |
| verify | `aborted at line 2214 (exit 1)` in the credential-policy test | **K6:** the ERR trap (`trap 'on_err $LINENO' ERR`) fires even inside the `set +e` block where the kit *deliberately* expects `pwtest.py` to fail (the weak password being rejected) | **kit bug:** verify can never complete on a host whose password policy works. Fix: `trap - ERR` around the block |

**Proposed fixes K1–K6** are one patch, `lab/client/chp-proposed-fixes.patch` (8 hunks). It was applied only to an **evaluation copy** built on the Mac (`CHP_PATCHED=1`, logs prefixed `patched-`); the kit on the Desktop is checksum-guarded and unchanged.

## 2. Verify results (before Kanidm)

Two runs, same host state (after harden, `itadmin` and `chpbreak` enrolled, GA module loaded):
- **Unmodified kit** (`verify-20260928T181042Z.log`): BND-01 NOT MET, BND-02 MET, **CRY-01 NOT MET (K4)**, CRY-02 NOT MET, CRY-03 MET, IDA-01 NOT MET, IDA-02 MET, **IDA-03 NOT MET (K4)**, then **aborts (K6)**. Nothing after IDA-03 is evaluated.
- **Evaluation copy with the proposed fixes** (`patched-verify-20260928T181201Z.log`): the whole suite runs, and **CRY-01 and IDA-03 become MET** (the K4 fixes). A trailing `aborted at line 2668` appears after the full result list and was not investigated.

| Control | Patched-copy result | Reading |
|---|---|---|
| BND-01 | NOT MET: undeclared hosts .1/.10/.2 | correct: the lab boundary file is a stub (operator task) |
| CRY-01 | **MET** | K4 fixed; host FIPS correct |
| CRY-02 | NOT MET: off-host mount test absent | correct: a physical test the operator must record |
| IDA-01 | NOT MET: undocumented account `itadmin` | correct: lab admin not in the kit's account register |
| IDA-02 | MET: directory=sssd (inactive) | the kit accepts an *inactive* sssd as the directory. Doubtful; see §3 |
| IDA-03 | **MET**: all four paths require GA, no nullok, single-factor refused | K4 fixed |
| IDA-04 | NOT MET: "compliant: REJECTED" | the kit's own compliant test password (`Tr0ub4dor&3-Xylo-Quilt`) is rejected via its `passwd` harness although `pwscore` gives it 98. Cause not isolated (candidate **K8**) |
| IDA-05 | NOT MET: recovery path never exercised | correct (operator task) |
| NET-01 | NOT MET: unexpected reachable port 631 | correct: CUPS from the Server-with-GUI install; the kit reports it but doesn't remove it |
| NET-02, LOG-02, LOG-03 | NOT MET: no alert reached the log platform / NO-ALERT | alert path not wired (no log platform in the lab) |
| NET-03, LOG-01, END-01, EVD-01..04, AIA-05, CHG-01 | MET | — |
| END-02 | NOT MET: one retained scan | correct (history builds over time) |
| END-03 | NOT MET: fapolicyd permissive (untrusted binary executed) | correct: the kit deliberately starts permissive for a week |
| BAK-01/02 | NOT MET: no restoration recorded; offline target unset | correct (operator tasks; `CHP_OFFLINE_TARGET=none`) |
| CHG-02 | NOT MET: stub created | correct (operator task) |
| AIA-01..04 | N/A | peer planned |

## 3. Kit vs Kanidm (ADR 0001) collisions

Kanidm was added to the CHP-hardened client1 with the Plan 3 enrolment (`lab/client/10-enrol.sh client1 sssd`), based on the profile the kit selected. Evidence: `lab/chp-logs/state-1b-…`, `state-2-post-kanidm.txt`, `state-3-post-reharden.txt`.

| Area | Kit (after harden) | After Kanidm enrolment | Collision / finding |
|---|---|---|---|
| authselect | `sssd with-faillock with-pwhistory with-mkhomedir` | `custom/kanidm` (a copy of **stock sssd**) with the **same features**; `pam_kanidm` before `pam_unix` in auth/account/session | no conflict at enrolment; the enrolment carries the kit's features over and verifies them |
| `pam.d/sshd`, `login`, `sudo`, `gdm-password` | `pam_google_authenticator` (no `nullok`) inserted at line 1 | unchanged (authselect doesn't manage these files) | GA stays in front of Kanidm: **the two factors are GA code + password** (see §4) |
| nsswitch | `files sss systemd` | `kanidm files sss systemd` (group likewise; stock sssd has no `initgroups` line, so glibc falls back to `group`) | none |
| **re-running the kit's harden** | — | **silently reverts Kanidm**: authselect back to `sssd`, every `pam_kanidm` line gone, `kanidm` removed from nsswitch; unixd keeps running, unused; sshd's Kanidm lines stay | **major:** a routine kit re-run (it says it is "idempotent and safe to re-run") turns every Kanidm user off with no warning. The kit needs an identity mode (`CHP_IDENTITY=kanidm`) or must preserve a non-`sssd` profile |
| sshd | `AuthenticationMethods keyboard-interactive:pam`, `PasswordAuthentication no` | `AuthorizedKeysCommand kanidm_ssh_authorizedkeys`, `TrustedUserCAKeys` added | **SSH keys and SSH certificates are never accepted** on a kit host: the dc2 design's separate SSH CA (and Kanidm-published keys) can't be used alongside the kit's sshd policy |
| local accounts | `pam_unix` | `pam_kanidm` answers **first for local users too**: unixd's system provider checks `/etc/shadow` ("Authentication Success, account_id: itadmin" in the unixd log) | behaviour change to note: local-account password checks now go through unixd |
| SELinux | GA module (§1 K7) | the same unixd socket AVCs as client2 (`sshd_t`, `auditd_t`, `init_t`, plus **`setroubleshootd_t`**) until `kanidm_lab` is loaded; **0 AVCs** afterwards | the Plan 3 module covers the CHP host unchanged |
| egress deny (CHP-NET-03) | default-deny egress, test target 8.8.8.8 | dnf from the lab repo, Kanidm (443) and step-ca were all reachable | the kit's egress policy did not block the lab subnet; not a collision here, but dc2 must permit its Kanidm/CA endpoints explicitly if the policy tightens |
| kit `verify` with Kanidm (evaluation copy, `patched-verify-20260928T184035Z.log`) | IDA-02 MET "directory=sssd (inactive)" | **still** IDA-02 MET "directory=sssd (inactive)" | **the kit's verify is blind to Kanidm**: it accepts an inactive SSSD as the directory and never sees unixd |

**Operational lesson (lab, but relevant to dc2 backups/restores):** reverting a PAM-only + GA host to a snapshot made fresh logins fail repeatedly. The causes:
- the guest clock is rewound (the TOTP code no longer matches);
- the rate-limit timestamps inside `~/.google_authenticator` are "just now" (GA fails without prompting);
- faillock counts every failed try.

Recovery needed exact clock arithmetic (`TOTP_OFFSET`) and, in the end, a replay from a key-login snapshot. dc2 restores (image or VM) should expect the same: resync time first, and allow for GA's rate-limit state.

## 4. MFA at login: Google Authenticator + Kanidm POSIX password

Details: `lab/chp-logs/login-matrix.md`.

- **Yes, two factors at Linux login, but only through the kit's Google Authenticator.** A Kanidm user with a GA token logs in over SSH with *Verification code* (GA, SHA-1 TOTP, host-local) plus *Password* (the Kanidm POSIX password). `sudo` asks for both too. This closes the Plan 3 gap (pam_kanidm alone is single-factor) on hosts built with the kit. **3.5.3 candidate.**
- **But the second factor is per host and outside Kanidm.** Each user needs a GA token file on *every* host. Without it, the user is **locked out** (no `nullok`, by kit design). Kanidm's own TOTP (enrolled centrally, HMAC-SHA256) is not used at Linux login at all. Tokens are not revocable centrally, and there's no enrolment flow for directory users. The lab used `lab/client/ga-enrol-kanidm.sh` as root.
- **Patcher bug found and fixed:** in the stock sssd profile, `auth [default=1 …] pam_localuser.so` skips the next line for non-local users, so a `pam_kanidm` line inserted directly before `pam_unix` is **never reached by any Kanidm user**. The patcher now places `pam_kanidm` where no numeric jump can skip it (property test over all four fixtures).
- **Kit finding K9:** the kit's `authselect select sssd with-faillock with-pwhistory with-mkhomedir` omits `without-nullok`, so `pam_unix nullok` (empty passwords) is active in `system-auth`/`password-auth`. GA in front of sshd/login/sudo masks it on those paths, but not on other services that include the stacks.

## 5. SELinux labels on Kanidm homes and `~/.google_authenticator`

- **The dc1 lockout mechanism, reproduced end to end.** pam_google_authenticator rewrites the token file on every use (replay/rate state). The new file's label depends on **who** rewrote it:
  - under sshd, with the lab module, it gets `auth_home_t` (correct);
  - under `sudo`, which runs in the user's unconfined context, it gets `user_home_t`.

  The next **SSH** login is then denied: `avc: denied { unlink } comm="sshd-session" name=".google_authenticator" … tcontext=user_home_t`. **`restorecon` of the token restores login** (the dc1 repair).
- Without the lab module, the very first SSH GA login is already denied (`create` of the temp file, §1 K7).
- **Kanidm homes:**
  - the real home directories are **UUID-named** (`/home/4ba78837-…`);
  - `/home/<name>@idm.kanidm.lab.test` is the SPN alias, labelled `home_root_t`; `restorecon -n` would relabel it `user_home_dir_t`;
  - token files created by the enrolment (user context) start as `user_home_t`, not `auth_home_t`.
- **Proposed robust fix (kit):** keep tokens **outside home folders**, e.g. `secret=/var/lib/google-authenticator/${USER}` in a directory labelled `auth_home_t`. New files inherit the directory's type whoever writes them, so the label can't flip between sshd and sudo.
- There were no other AVCs in the SSH/sudo tests once the Kanidm (`kanidm_lab`) and GA (`chp_ga_lab`) lab modules were loaded.

## 6. Proposed kit changes (text only; the kit is not modified)

**Bugs.** Patch in `lab/client/chp-proposed-fixes.patch` for K1–K6, proven on an evaluation copy:
- **K1** `authselect feature enable` → `authselect enable-feature` (or delete the redundant line).
- **K2** `firewall-cmd --set-log-denied=all` without `--permanent`.
- **K3** `write_file()` creates the parent directory.
- **K4** capture probe output before `grep` (CRY-01 and IDA-03 negative tests).
- **K5** `|| true` on the off-host ledger read.
- **K6** `trap - ERR` around the deliberate-failure block in the credential-policy test.
- **K8 (candidate)** IDA-04: the kit's own compliant test password is rejected by its `passwd` harness (pwscore 98). Investigate the harness.
- **K9** add `without-nullok` to the `authselect select` line.

**Design.**
1. **Ordering (K0):** enrol at least one admin (password + GA) **before** switching sshd to `AuthenticationMethods keyboard-interactive:pam`, and refuse to reload sshd otherwise. A failed harden must never leave a host with no working login.
2. **Identity mode:** add `CHP_IDENTITY=sssd|kanidm`. In `kanidm` mode, harden must **preserve** a non-`sssd` authselect profile (or build its features on top of it) instead of re-selecting `sssd`. Today a re-run silently turns Kanidm off (§3). verify IDA-02 should recognise unixd/Kanidm as the directory, and not accept an *inactive* sssd as one.
3. **SSH keys/certificates:** the dc2 design uses an SSH CA; the kit forbids public-key auth entirely. Consider `AuthenticationMethods publickey,keyboard-interactive:pam` (key **and** GA) so certificates can count as one factor.
4. **Google Authenticator + SELinux (K7, dc1 pattern):** keep token files outside home directories (`secret=/var/lib/google-authenticator/${USER}`, directory labelled `auth_home_t`), so the label can't flip between sshd (`sshd_t`) and sudo/user contexts. Or ship a policy module. Also document restoring a GA host from backup: resync time first, and the rate-limit timestamps and faillock will otherwise block the first logins.
5. **Directory users and GA:** with no `nullok`, every directory user needs a token file on *every* host before first login. The kit needs an enrolment flow for directory users, or should use the directory's own MFA where it exists.
6. **Remove, not just report, services from the GUI install** (CUPS port 631), or document it as operator action.

## 7. Open questions for the ISSO (spec §9 question 5)

1. **Which second factor at Linux login for dc2?** The options:
   - (a) the kit's host-local Google Authenticator + Kanidm POSIX password (works, per-host tokens, not centrally revocable);
   - (b) SSH certificate + GA (needs the kit's sshd policy changed);
   - (c) wait for Kanidm-native MFA in PAM (not available in 1.11.2);
   - (d) accept single factor at Linux login with compensating controls (POA&M).
2. Should the kit gain a **Kanidm identity mode** (design 2 above), or should dc2 hosts not use the kit's identity step at all?
3. Where do **GA token files** live on dc2, and who enrols them for directory users (design 4 and 5)?
4. Is **SELinux confinement** for GA (module vs token location) and for Kanidm (from Plan 3) one decision or two?
5. Should the kit's upstream (The CyberHygiene Project) receive K0–K9 as issues? The kit is public; these findings are, too.
