# ISO Plan 3a proof: the identity-server role

**Date:** 2026-09-30 · **On:** aero (KVM, UEFI Secure Boot with enrolled keys + vTPM) · **Repo:** 0.3.1 (signed, 10 packages:
chp-site 0.2.1, chp-base 0.1.0-2, chp-identity-server 0.1.0-2, Kanidm FIPS variant, step-ca/step-cli, idm-collect, google-authenticator)
**Harness:** `lab/iso3/prove.sh` (stages), with the Plan 2 helpers and `rootrun.exp` (root through `su` with the escrowed password,
commands sent base64-encoded)

## Final run, on a FRESH install: every stage PASS (12:52 to 13:09)

| Stage | Result |
|---|---|
| prep | 2/2: site validates; stick image made |
| server | 2/2: installed from repo 0.3.1; first boot unlocked with the escrowed passphrase |
| firstboot (unattended) | **15/15:** every step done; one-time bind key gone; LUKS = 2 keyslots (escrowed passphrase + TPM) + 1 clevis token; kickstart copies shredded; DNS `idm`/`ca`; step-ca healthy on the **intermediate only**; **no root CA key under /etc/step-ca**; Kanidm `/status` over TLS verified by the site root; renewal timer active; collector `errors: []`; three recovery secrets pending; the monitor alerts only "secrets still on the server"; fapolicyd 0 denials; SELinux 0 AVCs since boot |
| reboot | **the TPM unlocks the disk**: SSH comes back and this stage never sends the passphrase (a second "no prompt answered" check was removed after the final review: it could not fail) |
| export | 6/6: `export-client` moved the Kanidm admin passwords, the step-ca password and the **root CA key** to the stick (`escrow/iso3-srv-server.txt`); none are left on the server; the monitor is quiet; **USBGuard allowed only the pinned stick, temporarily, then blocked it again**; step-ca still issues without the root key |
| renew | 4/4: an **already-expired** Kanidm certificate is replaced by the renewal unit and served. The unit sees the expiry and goes straight to an ACME re-issue; `step ca renew` is never tried on an expired certificate (row 26) |

The pins exist on the server: `/etc/chp/site-stick.id` (vendor:product, serial, name, recorded at install) and
`/etc/chp/site-stick.hash` (USBGuard's device hash, pinned on first use). **Not demonstrable in the lab:** every QEMU USB disk
has the same identity and descriptors, so "a different stick is refused" is proven by unit tests only
(`tests/test_chp_site_usbstick.py`). Check it on real hardware.

## Findings from proof run 1 (repo 0.3.0), all fixed test-first before 0.3.1

1. `kanidmd recover-account -o json` is not an option in Kanidm 1.11 (usage error). Now `kanidmd scripting -c … recover-account`
   (`{"output": <password>, "status": "ok"}`).
2. Killing the one-time LUKS slot while giving *that slot's own key* as the "remaining" key fails ("No key available"). Now batch
   mode (`-q`) with no key, and a retry skips re-binding when the TPM is already bound.
3. `RemainAfterExit` oneshot units ignore `systemctl start` once active, so the retry hints say `restart`.
4. System services get no `HOME`, and the Kanidm CLI keeps its login token under `$HOME`, so the login timed out. Now `Environment=HOME=/root`.
5. step-ca ACME certificates live **24 h** (renewed at 8 h left), so a 7-day expiry alert fired forever. The threshold is now 4 h.
6. **USBGuard (CUI) blocks the site stick on installed hosts.** ISSO decision: allow **only that stick, temporarily**. Then, at the
   user's request, the stick is **pinned**: its identity is recorded at install, its USBGuard hash on first use, and any other stick is refused.
7. Harness lessons:
   - a multi-pattern `expect { … }` block written on one line is a single literal pattern
   - bash's bracketed-paste escape defeats end-anchored prompt patterns
   - the CUI profile polyinstantiates `/tmp` (use the admin's home directory to hand files to root)
   - `pkill -f` can match its own ssh command

The design change the plan made (TPM binding through a one-time LUKS key whose slot is killed) is proven: after binding, only the
escrowed-passphrase slot and the TPM slot remain.

## Re-proof after the final review: repo 0.3.2, a fresh install (13:35 to 13:43)

- prep 2/2, server 2/2, reboot (TPM unlock), export 6/6, renew 4/4: **PASS**.
- firstboot: **13/15 on the first boot.** The `collector` step's `idm_admin` login timed out 2 s after `recover` (Kanidm still busy;
  the same step passed on the 0.3.1 run, so this is timing). What happened next is Review Focus 1 working on a real install:
  - the new monitor check alerted "chp-server-firstboot failed"
  - the failed step had no `.done` marker
  - **at the next boot the unit resumed at `collector`**, finished `collector` and `ssh-ca`, and marked the server done
  - the collector then reported `errors: []`, and the monitor was quiet
- Fixed afterwards (test-first): the login is retried 5 times, with a 60 s expect timeout each. That change is in
  **chp-identity-server 0.1.0-4**, which the next repo cut (Plan 3b) must include (carry-forward).

## ISO Plan 3b: onboard / revoke / unexpire, repo 0.3.3 (2026-09-30, fresh install)

Repo 0.3.3 (`appliance/release/RELEASE-RECORD-0.3.3.md`): chp-site 0.3.0, chp-identity-server 0.1.0-5 (cache-key step + the
collector login retry carried from 0.1.0-4).

| Stage | Result |
|---|---|
| prep, server (install from 0.3.3 + escrow unlock) | 2/2 + 2/2 PASS |
| firstboot | **15/15 PASS on the first boot**, now including `cache-key.done` (the collector login retry was not needed this time) |
| reboot | PASS (TPM unlock, no passphrase) |
| export | **9/9 PASS**, new: `client.conf` on the stick carries `CACHE_PUBKEY` equal to the server's cache key; the key is `600 root` in a `700` directory |
| ops (new) | **23/23 PASS** (second run; see findings) |
| cleanup | PASS (no iso3 VMs left) |

`ops` checks, all run as root on the installed server. The `idm_admin` password went from the stick to the VM over pipes only (`rs.sh`, `rootrun.exp` line 2):
- **No Kanidm session:** `chp-site onboard` refuses with "run `kanidm login -D idm_admin` first" (exit 2).
- **onboard (new user):** the checklist shows the account, POSIX, SSH key and certificate `[x]`, and the primary credential, unix password and GA `[ ]`.
  - The reset token is **not on the screen**; it is in `/root/chp-onboard/<user>.reset-token.txt` (dir 700, file 600).
  - The user (lab stand-in) completed the reset with password + TOTP + unix password.
  - A re-run shows everything `[x]` but GA, and **writes no new token**.
  - The certificate has principals `<user>` and `<user>@idm.iso3.lab.test`.
- **revoke:**
  - It is refused for `idm_admin`, and for a group the user is not a direct member of.
  - `revoke <user>` expires the account in Kanidm and moves the SSH key to `revoked/`.
  - The hosts table's client `iso3-cli` is **not installed**, so the fan-out could not reach it. The command exits 2 naming it: "the Kanidm change IS in effect, but iso3-cli may keep cached access for up to ~2 min". This is **Review Focus 3 on a real host**.
- **onboard of the expired user is refused** and points to `unexpire` (no bypass of #32).
- **unexpire:** it is refused for a non-approver ("Chris Admin"). Approved by the ISSO (`ISSO_NAME`), it clears the expiry.
- **Audit log:** it has exactly 2 `unexpire` records (request + done) naming the approver and reason, and 2 `revoke` records. The journal (authpriv) has the same.
  - **`auditctl -m` works under the CUI profile** (the one assumption the plan left open).
  - A real record:
    `type=USER … auid=1000 … msg='text=chp-site unexpire user="ops1442" approver="D. Shannon" reason="expired by mistake in the Plan 3b proof" operator="chpadmin" as="idm_admin" exe="/usr/sbin/auditctl" … res=success'`
    `operator` is the **login** identity (`chpadmin`, from the audit login uid), kept through `su -`.
- fapolicyd: 0 denials; SELinux: 0 AVC since boot.

**Not proven here:** clearing the cache on a real client (no clients until Plan 4). The Plan 4 proof must include that, and a client whose host key changed after a reinstall.

**Findings:**
1. **Lab harness only.** The first `ops` run failed 4 checks:
   - My checklist parser kept the notes. It is fixed: item names are cut at the note.
   - The user stand-in (`lab/srv1/enrol-user.exp`, run on the appliance) once reported "no Confirm prompt" after the new password. Run again, it enrolled normally, and the second full run passed. The cause is unknown (a single occurrence).
   - The stage now keeps the REPL log root-only and prints a redacted tail if enrolment ever fails again.
   - The stage is **re-runnable**: a fresh user per run (`OPS_USER`, default `opsHHMM`), and journal counts are measured as increases.
   - The product checks (revoke, unexpire, refusals, audit) passed in both runs.
