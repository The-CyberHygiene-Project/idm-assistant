# ISO Plan 4a proof: record

## Task 5: sshd `Match` placement on OpenSSH 9.9 (aero, 2026-09-30)

`lab/iso4/sshd-match-check.sh` builds a Rocky-like tree in a temp dir: a main file with `Include d/*.conf` followed by `X11Forwarding no` and
`MaxAuthTries 3` (as the CUI main file has lines after its Include), plus the two shipped drop-ins (`10-chp.conf`, `99-chp-exceptions.conf`
with `Match User chpadmin,diag,chpcache`). It then asks `sshd -T -C user=…`. aero's sshd was not touched.

```
OpenSSH_9.9p1, OpenSSL 3.5.5 27 Jan 2026
alice: maxauthtries=3 x11forwarding=no authenticationmethods=publickey,keyboard-interactive:pam
chpadmin: maxauthtries=3 x11forwarding=no authenticationmethods=publickey
diag: maxauthtries=3 x11forwarding=no authenticationmethods=publickey
```

**Result: PASS.**
- A `Match` in an included file ends at that file's end.
- The main-file lines after the `Include` apply to every user.
- The key-only exception applies only to the named accounts.
- `MaxAuthTries` is the sentinel (sshd's default is 6; a leak would show 6 for `alice`). `X11Forwarding` defaults to `no`, so it proves nothing here.

## Run 1: repo 0.4.0 + hot-patched policy (2026-09-30)

Hosts: `iso4-srv` (.40), `iso4-cli1` (.41), `iso4-cli2` (.42), site `iso4.lab.test`, a diag key in `site.conf`.

| Stage | Result |
|---|---|
| prep, server | PASS |
| firstboot | 14/16 (the server enrolled as its own client; tokens minted). **FAIL: `chp_kanidm` not loaded → 2044 AVC** (finding 1) |
| reboot (TPM), export | PASS; export moved the server secrets **and both client tokens** to the stick |
| client1, client2 | 15/17 each: pinned anchor = client.conf pin, own token 0600, unixd online, authselect + CUI features, nsswitch, sshd methods, chpcache pin + exact sudo, monitors quiet, TPM reboot. **Same 2 SELinux FAILs** |
| hot-patch, reboot | fixed module loaded on all three; **AVC since boot 0** on all three (incl. a unixd stop/start cycle on the server) |
| ops | **30/30 PASS** (second run; run 1 hit two harness bugs, below) |
| negtrust | **3/3 PASS** |
| cleanup | PASS |

**ops highlights:**
- **Logins:** SSH certificate + Kanidm POSIX password logs in on both clients. A key without the CA certificate is refused.
- **Group revoke:** `revoke --group chp_users` reached both clients, and the user was refused **after 1 s**.
- **Account revoke** reached both clients; refused after **3 s / 2 s** (versus the ~2 min cache).
- **Unexpire:** after unexpire (ISSO) and key re-registration, the user logs in again.
- **Server access:** a `chp_admins` user logs in to the server and runs `sudo` with the Kanidm password; a `chp_users`-only user is refused on the server.
- **diag:**
  - the report comes back from a client, and a `--user` report from the server
  - `bash`, `idm-collect --user x;id` and `sudo -n /bin/sh` are refused
  - the diag key is refused from the server's address (`from=`)
- **chpcache:** its key is refused from anywhere but the server.
- **chpadmin** key-only works on all three hosts.
- **0 fapolicyd denials / 0 AVC** on all three hosts.

**negtrust:** a wrong `CA_ROOT_SHA256` is refused (no anchor installed; the journal says `refusing: step-ca … did not serve a root matching the pinned`). The right pin restores the anchor (SHA-256 matches), and unixd is back online.

**Findings (product). All fixed test-first in `chp-identity-client` 0.1.0-2…4, which is NOT yet in a signed repo:**
1. **`chp_kanidm` did not load at install.** The Anaconda log says `Bad filecon declaration … semodule: Failed!`.
   - **Cause:** the `.fc` used `gen_context()`, a refpolicy m4 macro, with plain `checkmodule`/`semodule_package`. RPM only *warns* on a failed `%post`.
   - **Fix:** a raw context, plus a build-time check (`.pp` → CIL, require a real `filecon`). It is proven to reject the old form.
2. **The context never matched** (the socket directory stayed `var_run_t`).
   - **Cause:** Rocky's `file_contexts.subs_dist` maps `/run` to `/var/run`, so a rule on `/run/...` is never consulted. The lab module used `/var/run`.
   - **Fix:** the rule is on `/var/run/kanidm-unixd(/.*)?`; the duplicate `semanage fcontext` calls were removed.
3. **systemd (`init_t`) was denied `remove_name`/`rmdir`** on the typed runtime directory when unixd stopped.
   - **Fix:** `init_t` may create/remove the directory and unlink its sockets. This is management only; who may *connect* is unchanged (ISSO #12).
   - Proven: reboot plus a unixd stop/start cycle gives 0 AVC.

**Findings (lab harness):**
- The login helper redirected the root-only password file as the ssh user (fixed: the redirect happens in a root shell).
- The enrolment stand-in failed once more with "no Confirm prompt" (as in Plan 3b; 1 of 6 enrolments here). **Hypothesis:** keystrokes arrive before the hidden-input prompt switches the terminal mode. `enrol-user.exp` now waits 400 ms before typing, and the iso4 stage keeps a redacted REPL log on failure. The next 3 enrolments all passed.
- `semodule -i` takes > 3 min on these VMs. The lab hot-patch runs it in the background.

**Still to do:** re-prove everything from a **signed** repo (0.4.1, with `chp-identity-client` 0.1.0-4) on fresh installs.

## Run 2 (the proof of record): fresh installs from SIGNED repo 0.4.1, no hot-patch (2026-10-01)

Repo 0.4.1 = 0.4.0 + `chp-identity-client` 0.1.0-5 (the three SELinux packaging fixes + the final-review fixes).

| Stage | Result |
|---|---|
| prep, server | PASS |
| firstboot | **16/16** (the server is its own client: `chp_kanidm` loaded at install, socket dir labelled, **0 AVC**) |
| reboot (TPM), export | 2/2, 5/5 (server secrets + both client tokens to the stick) |
| client1, client2 | **17/17 each** (pinned anchor, own token, unixd, authselect + CUI features, nsswitch, sshd, SELinux, 0 AVC, chpcache pin, monitors incl. the new 49-client-enrolled quiet, TPM reboot) |
| ops | **30/30**: revoke cut access in **1 s** (group) and **3 s / 3 s** (account) on both clients |
| negtrust | **3/3**. The refusal now names both values: `refusing: step-ca at ca.iso4.lab.test did not serve a root matching the pinned 0000… (it serves a514991111d9…)` |

**Extra checks (final review):**
- **sshd `Match` leak, on an installed appliance VM** (`iso4-cli1`, **OpenSSH_9.9p1**, the same as aero): `sshd-match-check.sh` passes.
  - The live `sshd -T` gives the same `permitrootlogin=no` / `maxauthtries=6` for `alice`, `chpadmin`, `diag` and `chpcache`; only `authenticationmethods` differs, as designed.
  - The review's premise ("Rocky 9 ships 8.7p1") does not hold for Rocky 9.8.
- **The one lab mistake:** I started the two client installs in parallel on the one shared stick image. Client 2's install did not finish.
  - Checked afterwards: `fsck.vfat` clean, every file present, no partial escrow.
  - Client 2 was re-installed alone and passed 17/17. **Client installs stay sequential** (one stick, one writer).

## Plan 4b Task 4: GA stacks measured on an installed client (2026-10-01)

Hosts: fresh `iso4-srv` + `iso4-cli1` from signed repo 0.4.1. The 4b changes were hand-applied on the client (lab only):
- `google-authenticator` (EPEL-signed, from the chp repo)
- the dev `chp-site.pyz` for `authselect-patch` (the GA lines) and `ga-enrol --no-confirm`

Script: `lab/iso4/ga-measure.sh`. **Final run: 21/21 PASS, `AVC since start = 0`.**

| Stack (SELinux domain) | How | Result |
|---|---|---|
| sshd (`sshd_t`) | a real SSH login: key + certificate + code + Kanidm password | LOGIN_OK; prompts `Verification code`, `Password`; **0 AVC** |
| console `login` (`local_login_t`) | a real serial-console login (`console-login.exp`) | logged in; prompts code then password; **0 AVC** |
| `gdm-password`, `login`, `sudo` (stacks) | `chp-site pam-test` (runs as root, `unconfined_t`: proves the stack) | PAM_OK, code then password |
| GDM (`xdm_t`) | policy query (`sesearch` on aero; same `selinux-policy-targeted` 38.1.75-2) | `login_pgm` (incl. `xdm_t`, `sshd_t`, `local_login_t`) has full create/write/rename/unlink on `var_auth_t` files and directories |
| token after logins | `stat`, `ls -Z` | `400 root root`, `var_auth_t` (no label flip) |

**Break-glass (quick check):** all PASS.
- `chpadmin` SSH key-only works.
- `chpadmin` + `su -` (escrowed root password) shows only a Password prompt.
- **Root at the real console: password only, no code prompt.**
- A Kanidm user is always asked for the code (no bypass).

**Decision (rule set before measuring): no `chp_ga` module.** Rocky's policy labels `/var/lib/google-authenticator` `var_auth_t` and already grants the login domains what `pam_google_authenticator` needs. The spec's `auth_home_t` + `chp_ga` (written when the tokens were in home directories) is superseded.

**Findings (fixed test-first or in the harness):**
1. **Product:** `google-authenticator` 1.09 asks the user to **confirm a code from the app** after the QR code. It needs a terminal (`getline(): Inappropriate ioctl for device` otherwise).
   - `ga-enrol` keeps that confirmation by default (it proves the phone is set up).
   - `--no-confirm` (passes `-C`) exists for scripted use.
   - Without a terminal and without `--no-confirm`, it refuses **before** any audit record or change.
2. **Product:** the PAM module rewrites the token as **0400**. `ga-enrol` now writes 0400 too (one mode everywhere), and makes the old token writable before shredding it on `--reset`.
3. **Harness:** `expect`'s literal "gate" ignores `(?i)`, so `console-login.exp` never tried its case-insensitive regexes. It now uses `[Vv]`/`[Pp]`/`[Ll]` classes, and reads `id` through an explicit `RESULT=` marker.
4. **Harness:** the first `idm_admin` login on the server can time out (as in Plan 3a); the harness retries 3×.
5. **Observed:** a user with **no token** on the host is denied on every stack (code asked, then refused; Review Focus 1).
