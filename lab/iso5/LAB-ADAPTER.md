# Lab adapter for the appliance regression (ISO Plan 5b)

**What it is.** One sudoers rule on the two regression hosts, `iso5-srv` and `iso5-cli2`:

```
/etc/sudoers.d/99-lab-adapter   (0440, root)
chpadmin ALL=(ALL) NOPASSWD: ALL
```

**Why.** The diagnostic engine's harness injects faults and runs repairs as an admin with password-free sudo, as the old
lab's `itadmin` does. On the appliance, `chpadmin` signs in by SSH key only and has no password, so `sudo` cannot work
for it by design. Without this rule the 11-scenario regression (spec §1 gate 2) cannot run on installed hosts.

**When.** It is added only **after** the final CUI scan of the same install: `lab/iso5/prove.sh adapter` refuses to run
until that install's scan results exist. Gate 3 (`DEVIATIONS.md`) therefore describes the product as shipped, without
the adapter. The golden snapshots used by the regression are taken after the adapter and the fixtures.

**Not part of the product.** It is in no RPM, kickstart or ISO. The release (`cyberhygiene-lab-installer-el9.iso`)
contains nothing of it. A host built from the ISO never has it unless someone adds it by hand.

**Also written by the adapter stage (lab secrets, Mac only, 0600, never committed):**
- `~/idm-lab-secrets/iso5-pins.json`: `CA_ROOT_SHA256` and `SSH_CA_FPR` from the site stick's `client.conf`. These are
  the trust pins the CA-trust and SSH-CA repairs check against.
- `~/idm-lab-secrets/iso5-idm_admin.json`: the `idm_admin` recovery password from the stick's escrow, used by the
  harness's Kanidm admin session.

Decision: assumed default stated in ISO Plan 5a (2026-10-10). Accepted with the Plan 5a rulings (ISSO, 2026-10-11).
