# ISO proof record: install from nothing, from the ISO (gates 1 and 3)

## Core 0.2.0 Plan B: ISO 0.2.0-rc2 (repo 0.7.4), gates 1 and 3 MET (2026-10-24)

**ISO** sha256 `1332d9114c9cd7fdfc7459ab68a529171aaa39f8beea666b097e381499f4d24e` (`appliance/release/RELEASE-RECORD-0.7.4.md`).
The hosts are iso5-srv, iso5-cli1 and iso5-cli2, installed from nothing on 2026-10-20 with the lab `chpadmin` key
rotated. Logs are in `~/idm-lab-secrets/iso5-0.2.0-rc2-run{1,2,3}.log`.

**Gate 1:**
- **Install** (`cleanup prep negrepo server firstboot reboot export client1 client2 quiet quietpoke`): **105 PASS,
  0 FAIL**. On every host:
  - the site stick was blocked at first boot;
  - the AIDE baseline was `first-boot`, built after the role marker;
  - the stick hash was pinned before the baseline;
  - the escrow folder is not in AIDE;
  - the daily timer is enabled;
  - the baselines are pinned (server by `export-client`, clients by `aide-pin`);
  - monitors are quiet.
- **Quiet check:**
  - The window started 2026-10-22T14:46Z, followed by `quietpoke` (a root shell, then a reboot, on every host).
  - The second daily check after that, on 2026-10-24, gave `quietcheck` **ALL PASS**: 0 added, removed and changed,
    `db_match=yes`, and AIDE monitors OK on all three hosts. The window included the 20:01 certificate renewal and
    log rotation.
  - **Unplanned extra evidence:** aero lost power (its battery ran flat, 2026-10-20 ~11:00 to 10-22 07:12). The VMs
    were hard-stopped for about 2 days, and the Kanidm certificate expired while they were down. After restart:
    - every disk unlocked through its TPM;
    - the renewal timer re-issued the certificate over ACME, and clients were online within 2 minutes;
    - the catch-up AIDE checks were clean (0/0/0) on all three hosts, after the reboot, root shell and power loss.
- **`baseline ga negtrust`:** ALL PASS. The diagnostic engine found 0 problems.

**Gate 2 (2026-10-24):** `engine regress --runs 3`, with `IDM_PROFILE=appliance`, on the rc2 golden hosts.
- **Result:** **11 of 11 scenarios green in every run (33/33)**, with model answers 3/3 valid and 3/3 agreeing on
  every scenario (`regression-2026-10-24.md`). Row 36 ×3 also passed: `gdm-password` accepts lab01 with password +
  GA code, and the token label is right.
- **Timing:** the regression ran 10:41–12:01 and did not overlap a daily AIDE check (03:30–04:45).
- **Before it could run:**
  - The lab clock had to be corrected. aero's clock was 92 s slow after its battery ran flat, so every GA code was
    rejected. It was set once from the Mac, and aero stays wired-only by the owner's design.
  - The golden snapshots were retaken after the fixtures, in Plan 5b's order.

**Gate 3:** **108 pass and 2 fail** on every host. The two failures are the AIDE deviations accepted in spec §8;
`deviations.py` exit 0. See `DEVIATIONS.md`.

**What rc1 found (0.2.0-rc1, repo 0.7.3; gate 1 FAILED 2026-10-20):** every host alerted on about 30 paths after the
post-install reboot and root-console use. A reboot test on cli1 found the causes:
- vfat inode numbers under `/boot/efi`;
- fapolicyd resetting ownership on its config (ctime);
- the FIPS-hash rule making Rocky's permissions-only lines hash `random-seed`, `lastlog` and `.bash_history`.

Fixed in `chp-integrity` 0.1.4 (owner decisions 2026-10-20).

**Fixed in the harness during Plan B:**
- `quietcheck` counted a journal line that is not always attributed to the unit.
- The gate-3 tailoring selected the AIDE rules but not their parent groups, which the CUI profile deselects, so a full
  scan reported them "notselected". Plan A's 6-pass/2-deviation figure came from per-rule fix generation, not a
  profile scan; it is confirmed now.

---

## History: ISO 0.1.0 (ISO Plan 5a proof record: install from nothing, from the ISO (gate 1))

**Update 2026-10-11 (ISO Plan 5b): the proof of record is run 4, on ISO 0.1.0-rc5** (sha256
`efcba98a4268ec35ccef0b66b78122b3c78246424f76186cfa45a1ba80ff81b2`, repo 0.6.3), together with **gate 2** below.
Runs 1–3 are history.

## Gate 2: regression on the installed hosts (ISO Plan 5b, 2026-10-11): MET

- **Run 4 on rc5:** install from nothing and the CUI scan, 141/141, the same stages as run 3.
  - Then the lab adapter: 8/8 (`LAB-ADAPTER.md`; added after the scan).
  - Then qcow2 NVRAM 4/4, the scenario users (`fixtures.py`: FIXTURES OK) and the golden snapshots 5/5
    (reset + 0 findings).
- **The regression:** `IDM_PROFILE=appliance`, 3 runs of each scenario, `lab/iso5/regression-2026-10-11.md`.
  **11 of 11 scenarios green in every run (33/33).**
  - Model `mistralai/devstral-small-2-2512`: 33/33 valid explanations, 32/33 agreeing with the expected repair (l4: 2/3).
    Each repair is code-driven, so all were GREEN.
- **Row 36 ×3** (`prove.sh row36`): `chp-site pam-test gdm-password lab01` (Kanidm password + GA code) passed 3 of 3,
  each in a fresh GA window. The token label afterwards was `var_auth_t`.
- **The shakedown before gate 2 found two engine/harness issues**, both fixed with tests:
  - l3: the stale-cache rule was blind to short names. A collector field was added (ISSO option a → repo 0.6.3, rc5).
  - l2: the lab's probe certificates expired inside the CA record. Lab certificates now last 30 days.
- **Snapshots with a vTPM:** proven (`snapspike`), then used for every reset.

**Date:** 2026-10-10 · **Run 2** was on ISO `cyberhygiene-lab-installer-el9.iso` **0.1.0-rc3**
(sha256 `144ec3459b8da5048ac15ef36bc6c21f145d364650db87a3d807774bae822c6b`), repo **0.6.1** (on the ISO).
This is the ISO built after the ISSO's gate-3 fixes: boot-loader password and Rocky key (`DEVIATIONS.md`).
Run 1 (rc2, repo 0.6.0) is kept below as history.
**Script:** `lab/iso5/prove.sh` (from `lab/iso4/prove.sh`; the install steps now boot the ISO) · **Logs:**
`~/idm-lab-secrets/iso5-proof-run{1,2}.log` (secrets-scanned: no escrow values, no private keys)

## Hosts

All are q35 VMs on aero: UEFI with Secure Boot on and Microsoft keys enrolled, a vTPM 2.0, one 120 GB disk. Each boots
the ISO as a CD-ROM; the site stick is a removable USB disk image labelled `OEMDRV`.

| VM | MAC | IP | Role | Menu entry chosen |
|---|---|---|---|---|
| `iso5-srv` | 52:54:00:c4:05:50 | .50 | server | 2: *Install identity server, serial console ttyS0* |
| `iso5-cli1` | 52:54:00:c4:05:51 | .51 | client | 3: *Install client workstation, serial console ttyS0* |
| `iso5-cli2` | 52:54:00:c4:05:52 | .52 | client | 3 |

The entry is chosen like a person would: wait for our menu (serial console), then press Down ×N and Enter (`virsh send-key`).
Nothing else is typed during the install.

## Results (run 3, rc4, ISO Plan 5b, history): 141 PASS, 0 FAIL

Every host was installed fresh from rc4, which carries Plan 5b's two collector fixes (P1, P2; `RELEASE-RECORD-0.6.2.md`).
The stages and counts are the same as run 2, plus one new stage:

| Stage | PASS | What it proves |
|---|---|---|
| baseline | 3/3 | the diagnostic engine finds **nothing** on all three healthy hosts. Before P1, both clients reported `COLLECT_CONF_INVALID` |

The `scan` stage again shows 102 pass and 0 fail on every host (`DEVIATIONS.md`, rc4).

## Results (run 2, rc3): 138 PASS, 0 FAIL

Every host is installed fresh, all three VMs, from rc3. Each stage's counts are the same as run 1's, plus:
- `firstboot` +2, `client1` +2, `client2` +2: each host has its boot-loader password set (`GRUB2_PASSWORD=grub.pbkdf2…` in
  `/boot/grub2/user.cfg`) and Rocky's release key in the rpm database.
- `scan` 4/4: every host passes every selected rule (`oscap` exit code 0).

Two notes on run 2:
- The `scan` check first expected exit code 2 ("some fail") and so marked the clean result as FAIL. The check now accepts
  0 or 2 and rejects 1 (an evaluation error); the stage was re-run and passed.
- The first launch of run 2 was stopped by hand during `prep`/`negrepo` (it had been started under a 2-hour limit) and
  relaunched detached. The leftover test VM and tampered repo were removed, `cleanup` was run, and the run started again
  from `prep`.

## Results (run 1, rc2, history): 132 PASS, 0 FAIL

| Stage | PASS | What it proves |
|---|---|---|
| prep | 2/2 | site validates; stick made |
| negrepo | 5/5 | **row 37**: (a) no network in `%pre` → an `http://` repo can't be read → install stops (fail closed); (b) with early network (`ip=`) a tampered `repomd.xml` → `signature is NOT valid` → stop. In both cases the disk is untouched (first and last MiB zero) and no escrow is written |
| server | 2/2 | installed **from the ISO**: our menu, `inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/server.ks`, `REPO SIGNATURE OK: file:///run/install/repo/chp` in `%pre` (gpgv works in the FIPS installer); first boot unlocked with the escrowed passphrase |
| firstboot | 16/16 | server first boot (Kanidm domain, step-ca, SSH CA, tokens, self-client); 0 fapolicyd denials, 0 AVC |
| reboot | 2/2 | **TPM unlock (PCR 7) under Secure Boot with the ISO's boot chain** (rows 15, 17; spec §9 first verification) |
| export | 5/5 | export-client: secrets + both client tokens to the stick |
| client1 | 17/17 | installed from the ISO; pinned anchor; unixd online; authselect / nsswitch / sshd; 0 denials / AVC; TPM unlock after reboot |
| client2 | 17/17 | same |
| ga | 59/59 | second factor (rows 11, 36, 42, 43): the same count as Plan 4b |
| negtrust | 3/3 | a wrong CA pin is refused; the right one restores the anchor |
| scan | 4/4 | CUI scan on all three pristine hosts: 2 high-severity failures, both decided **fix** by the ISSO and fixed in rc3 (`DEVIATIONS.md`) |

**Run notes (both recorded in the ledger):**
- The first `negrepo` attempt expected the signature refusal but got the fail-closed stop: `%pre` has no network. The
  stage now checks both cases.
- `ga`'s summary line was lost because the script was edited while it ran. Its 59 checks had all passed, and its last
  line (deleting the GA secrets on aero) had run.

## The spec §9 verifications

- **The ISO build keeps Secure Boot working:** yes. `check-iso.sh` shows shim, grub, mm, the kernel and the initrd are
  byte-identical to the DVD's. The TPM unlocked after reboot on all three hosts.
  - The build uses xorriso with the DVD's own mkisofs options, not `mkksiso` (lorax isn't installed on aero).
  - xorriso's `replay` mode was tried first and rejected: rc1, `RELEASE-RECORD-0.6.0.md`.
- **Anaconda finds `OEMDRV` on a VM USB disk:** yes. A real USB stick is not proven here.

## Gate-1 exception for the ISSO

The first boot after each install asks **once** for the escrowed LUKS passphrase. The TPM is bound during that first
boot (Plan 3a design). `unlock.sh` types it over the serial console. Every later boot unlocks by TPM. Gate 1 says "no
console typing beyond choosing the boot entry", so this is an exception for the ISSO to accept or to turn into a design
change.

**ISSO decision (D. Shannon, 2026-10-11): ACCEPTED.** Answering the escrowed LUKS passphrase from the site stick once, on the first start, is acceptable. Also accepted: the ISO size (~15 GB; it is transferred from the Synology share), the executor's rulings for Plan 5a, and deferring the seven minor review findings.

## Not proven here

- Real hardware: physical UEFI/TPM PCR values, a real USB stick, a DVD drive.
- The non-serial menu entries (0 and 1). They differ from 2 and 3 only by `console=ttyS0,115200`.
- The regression on installed hosts (gate 2): Plan 5b.
