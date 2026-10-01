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
