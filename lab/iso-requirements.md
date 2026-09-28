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
| 12 | SELinux | a policy for the unixd socket (typed socket dir, `nsswitch_domain` only), or confine unixd | Plan 3 (360 AVCs), ISSO question 4 | D |
| 13 | FIPS | step-ca with `GODEBUG=fips140=on` (upstream Go ignores host FIPS); `only` is impossible (MD5 at start) | Plan 3 Task 6 + review | R |
| 14 | FIPS | an SSP position for Kanidm's non-FIPS-module crypto (TLS: variant build option; Argon2/TOTP: outside) | Plan 2/3 Q2 reports | D |
| 15 | Disk | LUKS2 root with swap inside; **bind clevis TPM2 (PCR 7, Secure Boot) on the first real boot**, not in `%post` | Plan 4 Task 3 | R |
| 16 | Disk | **shred `/root/original-ks.cfg`** (it holds the plaintext install passphrase) after binding; never let `/root` backups carry it | Plan 4 review I5 | R |
| 17 | Firmware | UEFI + Secure Boot on; plan re-binding after firmware/Secure Boot changes (the TPM refuses by design) | Plan 4 negative test | R |
| 18 | Time | after any restore from image/snapshot, restart chronyd before anything else (chrony marks the jump "too variable" and won't step) | Plan 3 Task 10; Plan 4 | R |
| 19 | Time + MFA | a restored GA host also needs GA's rate-limit window and faillock to pass: document it; don't retry logins | Plan 4 Task 6/8 lessons | R |
| 20 | CHP kit | run the kit in a **Kanidm identity mode** (`CHP_IDENTITY=kanidm`) so a re-run can't turn Kanidm off; apply the K1–K6 fixes | Plan 4 §3, D-2, patch | D (kit change) |
| 21 | Collector | ship `idm-collect` as an **RPM** (fapolicyd trust; shell is allowed, untrusted Python isn't) with its redaction rules | Plan 5 Task 3 | R |
| 22 | Collector | the `diag` account with a **single-command** sudo rule; a key for the collector host | Plan 5 Task 3; ISSO question 3 (dc2) | D |
| 23 | Collector | a Kanidm service account `idm-collect` in `idm_service_desk` + `idm_unix_admins` with a **read-only** API token (write proven refused); **residual risk:** both groups are write-capable, so the token's read-only scope is the only barrier: rotate it with the host and alert on any write by idm-collect | Plan 5 Task 4 | R |
| 24 | Monitoring | alert on `cert-renew-kanidm.timer` not active and on the served Kanidm certificate's remaining lifetime | Plan 5 C1 | R |
| 25 | Onboarding | make **setting the POSIX (unix) password part of user onboarding**: a user with only a primary Kanidm credential is refused SSH by PAM on every client, and the collector's `POSIX_PW_MISSING` finding is the check | Plan 5 L1 (3/3: refused with the primary password before, posix login OK after) | R |
| 26 | Kanidm TLS | the renewal unit must **fall back to an ACME re-issue** when the certificate has already expired (`step ca renew` refuses an expired certificate, so a timer outage longer than the lifetime is otherwise unrecoverable without a person) | Plan 5 C1 (repair had to re-issue) | R |
