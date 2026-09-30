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
| reboot | 2/2: **the TPM unlocks the disk** (no passphrase sent) |
| export | 6/6: `export-client` moved the Kanidm admin passwords, the step-ca password and the **root CA key** to the stick (`escrow/iso3-srv-server.txt`); none are left on the server; the monitor is quiet; **USBGuard allowed only the pinned stick, temporarily, then blocked it again**; step-ca still issues without the root key |
| renew | 4/4: an **already-expired** Kanidm certificate is replaced by the renewal unit (ACME fallback, row 26) and served |

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
