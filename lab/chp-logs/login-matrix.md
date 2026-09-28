# Login matrix: CHP-hardened client1 + Kanidm (2026-09-28)

PAM on client1: the kit's `pam_google_authenticator` (no `nullok`) is line 1 of `sshd`, `login`, `sudo`, `gdm-password`. Below it, `custom/kanidm` (stock sssd + the kit's features) with `pam_kanidm` placed where no jump can skip it. sshd: `AuthenticationMethods keyboard-interactive:pam`, keys not accepted.

| User | Path | Prompts (in order) | Result | Note |
|---|---|---|---|---|
| itadmin (local, GA) | SSH | Verification code, Password | **OK** | before and after Kanidm; `pam_kanidm` answered for the local account via unixd's system provider |
| lab02 (Kanidm, **no GA token**) | SSH | Verification code, Password | **DENIED** | GA without `nullok` refuses users with no token file: Kanidm users are locked out until enrolled on **each host** |
| lab03 (Kanidm + GA) | SSH | Verification code, Password (Kanidm POSIX password) | **OK** (after patcher fix) | **two factors at login**; first attempt DENIED because `pam_localuser [default=1]` skipped `pam_kanidm` (patcher bug, fixed and tested) |
| lab01 (Kanidm + GA, lab_admins) | SSH → `sudo id` | sudo: Verification code, `[sudo] password` | **root** | sudo requires both factors |
| lab01 | SSH **after** the sudo above | Verification code, Password, Password | **DENIED** | sudo (user context) rewrote `~/.google_authenticator` as `user_home_t`; sshd then denied `unlink` → **the dc1 lockout mechanism** |
| lab01 | SSH after `restorecon` of the token | Verification code, Password | **OK** | the dc1 repair |
| lab03 | serial console (`login`) | "Password:" shown first | not completed | automation did not complete; `pam.d/login` has GA first (config level). Listed as a manual follow-up with gdm |
