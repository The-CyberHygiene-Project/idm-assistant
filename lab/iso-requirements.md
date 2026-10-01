# dc2 installer ISO: requirements log

What the dc2 installer (custom Rocky ISO + signed RPM repo + kickstart) should set **by default**, each with the lab evidence behind it. Status: **R** = requirement (evidence in hand), **D** = needs an ISSO decision, **O** = open.

| # | Area | The ISO should… | Evidence | Status |
|---|---|---|---|---|
| 1 | Packages | ship Kanidm as **signed RPMs** in an in-ISO repo (fapolicyd trusts RPM-installed files; keep `gpgcheck=1`) | Plan 2 Q1 D1; Plan 3 (0 fapolicyd denials for RPM installs) | R |
| 2 | Packages | never install compilers on servers; build RPMs elsewhere (fapolicyd blocks compiling *and* packaging) | Plan 2 D1; Plan 2 review | R |
| 3 | Kanidm server | install `server.toml` 0644 (the DynamicUser must read it; it holds no secrets) | Plan 3 D6 | R |
| 4 | Kanidm server | deliver the TLS key by a root pre-start copy into the RuntimeDirectory (LoadCredential failed in the upstream unit) | Plan 3 D7 | R (root cause open) |
| 5 | Config files | set explicit modes on non-secret config and public certs (the CUI umask leaves root-written files 0600) | Plan 3 D8 | R |
| 6 | Clients | put `kanidm` first on `passwd`, `group` **and** `initgroups` (the CUI profile pins `initgroups: files`) | Plan 3 D9 | R |
| 7 | Clients | place `pam_kanidm` where no numeric PAM jump can skip it (stock sssd's `pam_localuser [default=1]`) | Plan 4 Task 7 (patcher fix + property test) | R |
| 8 | Clients | base the Kanidm authselect profile on the site's CUI profile and **carry its features over** (`with-faillock`, `without-nullok`, …), verified after selecting | Plan 3 Task 8 (my nullok bug); Plan 4 K9 | R |
| 9 | SSH CA | issue user certificates with **SPN principals** (`user@idm.<domain>`), or configure unixd short names | Plan 3 D10 | R |
| 10 | sshd | `AuthenticationMethods publickey,keyboard-interactive:pam`: key/certificate **and** GA code | ISSO decision 3′ (Plan 4 §8) | R |
| 11 | Second factor | `pam_google_authenticator` (no `nullok`) on sshd/login/sudo/gdm; **token files host-local** outside home, e.g. `/var/lib/google-authenticator/<user>` labelled `auth_home_t` | ISSO decisions 1 and 3; Plan 4 K7 + label-flip lockout | R |
| 12 | SELinux | a policy for the unixd socket (typed socket dir, `nsswitch_domain` only), or confine unixd | Plan 3 (360 AVCs), ISSO question 4 | R (decided 2026-09-29, #12: chp_kanidm + chp_ga; unixd unconfined = POA&M) |
| 13 | FIPS | step-ca with `GODEBUG=fips140=on` (upstream Go ignores host FIPS); `only` is impossible (MD5 at start) | Plan 3 Task 6 + review | R |
| 14 | FIPS | an SSP position for Kanidm's non-FIPS-module crypto (TLS: variant build option; Argon2/TOTP: outside) | Plan 2/3 Q2 reports | R (decided 2026-09-29, #14: FIPS TLS variant + POA&M) |
| 15 | Disk | LUKS2 root with swap inside; **bind clevis TPM2 (PCR 7, Secure Boot) on the first real boot**, not in `%post` | Plan 4 Task 3 | R |
| 16 | Disk | **shred `/root/original-ks.cfg`** (it holds the plaintext install passphrase) after binding; never let `/root` backups carry it | Plan 4 review I5 | R |
| 17 | Firmware | UEFI + Secure Boot on; plan re-binding after firmware/Secure Boot changes (the TPM refuses by design) | Plan 4 negative test | R |
| 18 | Time | after any restore from image/snapshot, restart chronyd before anything else (chrony marks the jump "too variable" and won't step) | Plan 3 Task 10; Plan 4 | R |
| 19 | Time + MFA | a restored GA host also needs GA's rate-limit window and faillock to pass: document it; don't retry logins | Plan 4 Task 6/8 lessons | R |
| 20 | CHP kit | run the kit in a **Kanidm identity mode** (`CHP_IDENTITY=kanidm`) so a re-run can't turn Kanidm off; apply the K1–K6 fixes | Plan 4 §3, D-2, patch | R (decided 2026-09-29, #20: kit not a dependency) |
| 21 | Collector | ship `idm-collect` as an **RPM** (fapolicyd trust; shell is allowed, untrusted Python isn't) with its redaction rules | Plan 5 Task 3 | R |
| 22 | Collector | the `diag` account with a **single-command** sudo rule; a key for the collector host | Plan 5 Task 3; ISSO question 3 (dc2) | R (decided 2026-09-29, #22: pinned forced-command key) |
| 23 | Collector | a Kanidm service account `idm-collect` in `idm_service_desk` + `idm_unix_admins` with a **read-only** API token (write proven refused); **residual risk:** both groups are write-capable, so the token's read-only scope is the only barrier: rotate it with the host and alert on any write by idm-collect | Plan 5 Task 4 | R |
| 24 | Monitoring | alert on `cert-renew-kanidm.timer` not active and on the served Kanidm certificate's remaining lifetime | Plan 5 C1 | R |
| 25 | Onboarding | make **setting the POSIX (unix) password part of user onboarding**: a user with only a primary Kanidm credential is refused SSH by PAM on every client, and the collector's `POSIX_PW_MISSING` finding is the check | Plan 5 L1 (3/3: refused with the primary password before, posix login OK after) | R |
| 26 | Kanidm TLS | the renewal unit must **fall back to an ACME re-issue** when the certificate has already expired (`step ca renew` refuses an expired certificate, so a timer outage longer than the lifetime is otherwise unrecoverable without a person) | Plan 5 C1 (repair had to re-issue) | R |
| 27 | Clients | pin the authselect profile **and** its feature set (`custom/kanidm` + `with-faillock`, `without-nullok`) in the ISO and in the repair; alert when `authselect check` fails (hand edits survive until someone looks) | Plan 6 L2 (3/3) | R |
| 28 | Clients | decide the unixd cache lifetime as a **revocation** setting: a removed group keeps working from cache for ~2 min (measured); document it, or lower the cache timeout on sensitive hosts, and make "invalidate the cache" part of the revocation runbook | Plan 6 L3 (3/3; repair cleared it in ~14 s) | R (decided 2026-09-29, #28: default + `chp-site revoke`) |
| 29 | Monitoring | alert on Kanidm TLS reachability **from clients**: `kanidm-unix status` says online until a lookup needs the server, so it is not a health check | Plan 6 L3n (3/3) + measurement | R |
| 30 | Time | the CUI profile's `makestep 1.0 3` means a later clock jump is **slewed for hours** (600 s ≈ 2 h): decide whether dc2 clients may step (`makestep 1.0 -1`) or whether a jump must page someone; either way alert on offset > 30 s | Plan 6 L4 (3/3) + measurement | R (decided 2026-09-29, #30: slew + alert > 30 s) |
| 31 | Trust | install the step-ca root from the ISO with its **pinned SHA-256**; unixd's `ca_path` names that single anchor file, so its loss takes the client offline (unixd crash-loops; `sudo` then logs NSS errors to stdout) — include the anchor in file-integrity monitoring | Plan 6 C2 (3/3) | R |
| 32 | Accounts | account-expiry changes go through an approved change (re-enabling an expired account is a security decision): decide who may approve `account-unexpire`; the tool never suggests it by default (runbook default none; the model declined 4/4) | Plan 7 L5 (3/3) | R (decided 2026-09-29, #32: ISSO / named delegate, logged) |
| 33 | SELinux | ship the unixd socket file context in the ISO's policy module (the lab module kanidm_lab provides it) and run restorecon on the identity paths at first boot; a mislabel fails logins with **no AVC** (dontaudited), so monitor `restorecon -n` over the identity paths, not AVCs | Plan 7 L6 (3/3) + measurement | R |
| 34 | SSH CA | the SSH CA records every certificate it issues (public) and registers each user's public key; re-issue signs only the registered key, short validity (+1h in the lab), and users need a self-service renewal path | Plan 7 C3 (3/3) | R |
| 35 | sshd | TrustedUserCAKeys lives in a drop-in the ISO owns, the key file pinned by fingerprint; drift check with `sshd -T`; any change validated with `sshd -t` before reload | Plan 7 C4 (3/3) | R |
| 36 | GDM | GUI on both roles: `pam_kanidm` + GA on `gdm-password`, tokens host-local (row 11); a scripted PAM test of the `gdm-password` stack (and the token label afterwards) joins the regression | dc1 gdm/`xdm_t` lockout; design 2026-09-29 | R |

Decisions for the former D rows were settled one at a time on 2026-09-29; the full wording is in `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md` §2.
