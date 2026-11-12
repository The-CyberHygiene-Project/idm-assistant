# Proof record: ISO 0.6.0 (sized disks, /data and /backup volumes, check 76, sign-off fixes) on the iso5 lab

**The release candidate is rc2** (sha256 `0cb27c1497acdd245af74508ab16a8d9f75a57dd10089372ac2ef9a68067cac0`; see "ISO 0.6.0-rc2" at the end). rc1 (below, with its 36 h quiet day) was proved first; rc2 differs from it only in `chp-site` 0.13.0-2 and was re-proved on a fresh install (no second quiet day).

ISO **0.6.0-rc1** = the Rocky 9.8 DVD boot chain + signed repo **0.11.0** (`check-iso.sh`: ISO OK; sha256
`e860c6f6fa9f18a2eceea3414716da5d101e5275693b99e33e112deead250dbb`). Repo 0.11.0 differs from 0.10.0 in three packages:
`chp-site` 0.13.0-1, `chp-base` 0.1.0-4 (monitor check 76, disk space), `chp-security` 0.4.1-1 (rotates `chp-yara.json`).
All three hosts were installed from nothing (2026-11-09) with `SECURITY_ADDONS=yes`, replacing the 0.5.0 lab:

| Host | Disk | Layout |
|---|---|---|
| iso5-srv | 1863 GiB sparse | server layout: `/` 90, swap 29, `/backup` 600, `/data` 350, audit 30, `/var/log` 50, `/var/tmp` 15, `/var` 100, `/tmp` 15, `/home` 238; VFree 343 GiB; Wazuh data at `/data/wazuh` |
| iso5-cli2 | 512 GiB sparse | workstation layout; VFree 304 GiB; no `/data`, no `/backup` |
| iso5-cli1 | 120 GiB sparse | today's layout, VFree 0 |

Size guards (50 GB limit, counted over `iso5-srv-*.qcow2` / `iso5-cli2-*.qcow2`) were running the whole time and never
tripped. Raw logs of every stage below are in `lab/security/iso-0.6.0-logs/`.

## Results

| Gate / proof | Result |
|---|---|
| Install stages (Task 6): prep, server, firstboot, export, client1, client2, wazuh-on | ALL PASS (see the Task 6 notes at the end) |
| **Gate 3:** CUI scan (`prove.sh scan`) | **108 pass / 2 fail on every host**, the two accepted AIDE rules; `deviations.py` exit 0 (run by hand, rc echoed; not in a log file). The new volumes (`/data`, `/backup`, their mount options) caused **no change**: no rule appeared or disappeared, so `DEVIATIONS.md` needed no new entry |
| lab adapter, nvram, snapspike, fixtures (`FIXTURES OK`), golden | ALL PASS (golden: reset + 0 findings on both hosts) |
| **Gate 2:** regression (`lab/iso5/regression-2026-11-10.md`, commit `33223ef`) | **33/33** (11 scenarios x 3 runs, all GREEN), Wazuh, YARA and Suricata running. Model: 33/33 valid, 32/33 agreeing (l4: 2/3, the same as in 0.2.0; each repair is code-driven) |
| **Gate 2:** row 36 | **3/3**; token label `var_auth_t` afterwards |
| Forced weekly YARA scan (`prove-y1.sh full`, cli2, 512 GiB layout) | 112,185 files, 67 s, **1 match (the test file only)**, 0 errors; last-full written; monitor 73 OK |

### Step 1: layout proof (srv)

`findmnt`: `/data` = `rw,nosuid,nodev,...` and `/backup` = `rw,nosuid,nodev,noexec,...`, both on their own LVs;
`/var/ossec` is the bind mount of `chp-data[/wazuh]`. `lvextend -r -L +5G chp/var`, online: `/var` 102,336 M -> 107,456 M
(+5 GiB), VFree 342.98 -> 337.98 GiB; the `MainPID` and start time of kanidmd, sshd and chronyd and the start time of the
Wazuh manager (it shows no PID, only a start time) were identical before and after. Image after the extension: 14 GB by `du -B1G` on aero (limit 50; this was a separate command, its output is not in the step log, the 14 GB at the later quiet-day start is in `quiet-start-state.log`). The trailing bare `0` in `step1-lvextend.log` is the failed-unit count (`systemctl list-units --state=failed --no-legend | wc -l`; the command itself was not captured).
Log: `iso-0.6.0-logs/step1-lvextend.log`.

### Step 2: check 76 catch (cli2)

A lab `ALERT_HOOK` (`/usr/local/sbin/lab-hook` appending to `/var/log/lab-hook.log`) was set on cli2. Baseline: check 76
and the whole monitor were quiet. A 1 GiB LV `chp/t76` was made, formatted XFS and mounted on `/mnt/t76`, then filled to
exactly **90 %** (859 M of 960 M):

- **Run 1** (`systemctl start chp-monitor.service`): exactly **one** `ALERT` reached the hook:
  `/mnt/t76 is 90% full (limit 85%); grow with lvextend -r; 302 GB free in chp`. The state file holds `/mnt/t76 <epoch>`.
- **Run 2** (a manual monitor run, then the unit again): **silent**, hook still 1 line, monitor rc 0.
- LV removed: check 76 prints `OK no XFS file system at or above 85%`, the state file is empty, the hook has still
  1 line, monitor rc 0. VFree back to 303.98 GiB.

An earlier trial at 98 % (before the exact 90 % run) alerted once and went silent in the same way; it was removed and
the hook log cleared before the 90 % run. Logs: `step2-check76*.log`.

### Step 4: review proofs on the fresh install (srv + cli2, cli1 as a third reporting host)

`prove-r1.sh` was updated for 0.6.0 (committed): the expected versions, the sign-off through a scripted pty
(`ssh -tt` with a piped `yes`, not a human at a keyboard), cli1 now reports like the others (installed with the review: all items OK, sysstat
item present, records from three hosts), and the new sign-off checks. The `repo` and `enable` stages do not apply
(security was on from the install); their before-files were made from the boot state.

| Stage | Result |
|---|---|
| `on` | ALL PASS: versions, sysstat and record timers, record log 0640, no new listener, 0 AVCs, 0 fapolicyd denials, agent keys unchanged, build timer, review rules, records from all three hosts |
| `build` | ALL PASS: Suricata catch from srv (inside), YARA test file under cli2, cli1 all OK, certs/keys/scans/repo OK, sysstat on all three, client lenient / server strict, resources |
| `sign` | the ISSO signs **from a pty** (a scripted `ssh -tt` with a piped `yes`, not a human at a keyboard): "signed 1 review(s); recorded in the ledger and the audit log"; an unlisted name is refused; **piped `yes` is refused: "review sign needs a terminal…"**; **bad `--date 2026-13-45` gives "--date must be YYYY-MM-DD" and no traceback**; `review verify` clean; sign-off in the audit log |
| `tamper` | ALL PASS: two entries (so neither refused attempt signed anything); an edited entry and an edited report both fail `review verify`; monitor 75 alerts; restored: clean |
| `export` | ALL PASS: to the stick, `verify --stick` OK; an emptied ledger fails against the stick |
| `soon`, `res` | ALL PASS; record about 2.3 KB (srv) / 1.8 KB (cli2), about 0.4 s CPU per run |

**Log note:** `iso-0.6.0-logs/r1-sign.log` is the run with the wrong check (6 of 7 PASS, 1 FAIL). The re-run of the `sign` stage after the script fix was **not logged** (the output was not captured), and `tamper`, `export` and the later stages ran after the first run, not after a re-run. Indirect evidence that the sign-off itself worked and the refused attempts signed nothing: in `r1-sign.log` the sign, refusal, piped-yes, bad-date, verify and audit-log checks all PASS; `r1-tamper.log` then reports exactly two ledger entries after the two real sign-offs. The fixed ledger-count line itself was not re-proved.

One check of mine was wrong, not the product: "the refused attempts signed nothing" redirected `ledger.jsonl` from a
non-root shell (Permission denied). It is fixed in the script (`sudo cat | wc -l`); the point itself is shown by the
`tamper` stage counting exactly 2 entries after the two real sign-offs.

### Step 3: the backup-drive runbook (`docs/runbooks/move-backup-to-a-second-drive.md`), followed on srv

A new 100 GB sparse virtual disk (`iso5-srv-2.qcow2`, virtio, serial `LABBKP0001`, so `/dev/disk/by-id/virtio-LABBKP0001`)
was attached to the running server (the guard counted it, 1 GB). Steps 1-12 were run as written (commands in
`runbook-step3.log`; the passphrase is masked there):

- Step 3: the passphrase (40 characters) was written to `escrow/iso5-srv-backup-drive.txt` on the lab stick by the "other
  computer" (aero), read back and compared byte for byte: identical.
- Steps 4-6: LUKS2 format, `clevis luks bind ... tpm2 {"pcr_bank":"sha256","pcr_ids":"7"}` (Secure Boot enabled),
  XFS made, mounted under `/mnt/newbackup`.
- Step 7: `/backup` is empty on a fresh install, so the lab put 50 MB, a hard link and an extended attribute in it first
  (a lab addition, not a runbook change): the first copy transferred 2 files, the second **0**; `diff -rq` printed
  `SAME`; the xattr and the hard link (same inode, 2 links) arrived.
- Steps 8-9: one `/backup` line in `fstab`, one `backupdrive` line in `crypttab`; the final `rsync --delete` and `diff` said
  `SAME`; `chattr +i` on the empty mount point (`lsattr` showed `i`); the mount: `findmnt /backup` = `/dev/mapper/backupdrive`,
  `rw,nosuid,nodev,noexec,...`; the probe write worked.
- Step 10: `lvremove chp/backup`; `vgs chp` VFree **342.98 -> 942.98 GiB (+600 GiB)**.
- Step 11: the key file shredded.
- Step 12: `clevis-luks-askpass.path` enabled; **reboot with nobody typing**: the VM came back by itself, `/backup` was
  mounted from `backupdrive` (vdb, TPM unlock), `/backup/lab-test` intact, `systemctl list-units --state=failed` printed nothing (`runbook-step3.log`, "after reboot"), 76 OK. The monitor's only
  alert was the AIDE change.
- Step 13: `chp-site aide-accept` (answered **no**, to leave the lab untouched) listed 15 paths. Beyond the lab's own
  (`99-lab-adapter`, `/root/chp-scan`, the fixture SSH keys) these were the move's:
  `/etc/crypttab`, `/etc/fstab`, **`/etc/fstab.bak`**, **`/etc/lvm/backup/chp`** and **`/etc/lvm/archive/chp_00001-*.vg`**.

**The runbook was wrong in two places (fixed and committed):** step 13 said the list "must list only `/etc/fstab` and
`/etc/crypttab`", which would make every ISSO say no. It now names the five paths the move explains and says anything
else is not from the move. Step 12 now says the journal line "Failed to activate with specified passphrase" before
"Finished Cryptography Setup" is normal (the first unlock attempt fails, then the TPM unlocks it). The top "What changes" note now mentions
the LVM records.

**Order note:** srv was reverted to golden between Step 1 and this runbook (the regression resets it before every run), so `/var` was back to 100 GiB, VFree 342.98 GiB, and `/etc/lvm/archive` held no earlier file: the single archive file in the step 13 list is the one `lvremove` made. Afterwards the second disk was detached (`virsh detach-disk --persistent --live`), `iso5-srv-2.qcow2` deleted, the lab
stick's `iso5-srv-backup-drive.txt` removed, and srv reset to golden (`reset.sh`), so the quiet day runs on the fresh
layout (`/backup` on `chp-backup`, VFree 342.98 GiB).

## Quiet day: PASSED (T0 2026-11-10T01:59:15Z to 2026-11-11T14:23Z, about 36 hours, lab untouched)

srv and cli2 at golden plus a lab `ALERT_HOOK` each; cli1 untouched since install. Logs: `quiet-check.log`,
`quiet-review.log`, `quiet-aide-paths.log`, `quiet-guards-stopped.log`.

- **The real 00:20 builds:** `chp-review-build.service` built `2026-11-09` (2026-11-10 00:20) and `2026-11-10`
  (2026-11-11 00:20); `review verify` rc 0. Both reports: **Needs attention: 0**. 2026-11-09: 1,754 alerts, records
  cli1 34 / cli2 33 / srv 35 (it includes the afternoon's proofs: promiscuous-mode and listening-port alerts from the
  Suricata and `ss` work); 2026-11-10: 413 alerts, records 135 / 138 / 136, four low-level Wazuh items (RBAC auditd
  at 03:31 to 04:30 around the AIDE checks, one listening-port change at 10:58). All three hosts report in the
  status table; keys and the CA certificates OK. The one exception on 11-10 is `iso5-srv` `/etc/pki/kanidm/chain.pem`, **ATTENTION, "10 h left of 24 h"**, owned by monitor 30 and therefore not counted: the Kanidm certificate lives 24 h and is renewed 8 h before expiry (monitor 30 alerts below 4 h), but the report marks a certificate under 90 days ATTENTION when less than half its life is left (`review_rules.py` `cert_state`, 12 h here), so a healthy certificate shows ATTENTION for the 4 h between 12 h and 8 h left, and the 00:20 build fell in that window. Renewal was working (the certificate now served was issued 09:53Z on 11-11, 16 h after the previous one; `cert-renew-kanidm.timer` runs every 15 min). Noted as an observation for review: the report's half-life threshold is higher than the 8 h renewal point. The three `aide_ok` rows read ATTENTION on 11-10 ("changes or mismatch to
  review") but are not counted in "Needs attention", because that item is watched by monitor 60 (a row with an owner
  is excluded by design, `review_report.py` line 247). No monitor 75 "not built" alarm.
- **Hook lines since T0** (recounted from the hook logs at 07:27 on 11-11, `quiet-hooks-recount.log`: srv 111 = 2 + 1 +
  108 AIDE, cli2 110 = 2 + 108 AIDE; the first capture, `quiet-check.log` at 07:23, showed 107 AIDE lines per host and the
  count grows by one every 15 min; cli1 has no hook, its monitor journal, `quiet-cli1.log`, has 102 AIDE lines): srv = 2 YARA lines from the revert at 18:59 (explained above), 1 daily summary ("5 medium alerts (levels 7-9) on
  3 hosts in the last 24 h"), and 108 AIDE repeats; cli2 = the same 2 YARA lines and 108 AIDE repeats. AIDE repeats are
  monitor 60 every 15 minutes until accepted (existing behaviour), for two checks (11-10 and 11-11). The AIDE
  changes are lab-only (`quiet-aide-paths.log`): `99-lab-adapter`, `/root/chp-scan`, `lab-hook`, the three fixture SSH
  keys, `/etc/chp/site.conf` (the hook setting) and their parent directories; srv 8 added / 6 changed, cli2 5 / 5. cli1's
  3 added / 1 changed (`quiet-cli1.log`) could not be listed (no lab-adapter sudo there; its journal and failed units
  are in that log: 0 "% full" lines, no failed units): probably the scan files under `/root` and a parent directory. The
  hook lines are monitor 60's channel for the `aide_ok` rows that the review does not count. Nothing from the new volumes, `/data`, `/backup` or check 76.
- **No false check-76 alerts:** no "% full" line in the `chp-monitor` journal of srv or cli2 since T0 (0), none in the
  hook logs, none in cli1's journal; the state file `/var/lib/chp/monitor/76-disk.state` is empty on both. Mounts at
  the end: srv `/var` 2 %, `/data` 2 %, `/backup` 1 %; cli2 `/var` 5 %. VFree unchanged (342.98 / 303.98 GiB).
- **The 24-hour repeat of check 76** is proved by the unit test `tests/test_chp_base_disk_check.py::test_76_repeats_after_24h`
  (the clock is injected with `CHP_NOW`); the quiet day could not show it, because nothing crossed the limit.
- **Image sizes (`du -B1G`, aero):** at T0 srv 14, cli2 11, cli1 9; at the end srv 14, cli2 12, cli1 9 (limit 50).
  Both guards were active at the end and their journal has no `SIZE-GUARD` line (0), so neither tripped. The "Stopped"/"Started" lines in the srv guard's journal (`quiet-guards-journal.log`) are all before T0 and come from the install phase, not from the guard acting: started 11-09 12:58, restarted 13:17:44 and stopped 13:34:55, started again 15:58:13 (for the server install), and the cli2 guard started 16:44:34; nothing between T0 and my stop at 11-11 07:24:25. Their timing follows Task 6's reinstall steps; I did not watch them live. They were then
  stopped (`quiet-guards-stopped.log`: both `inactive`).
- **Suricata:** RSS 531 MB on srv and cli2, up the whole time, 0 restarts. **YARA:** 0 match lines in `chp-yara.json`
  on both; the weekly scan is not due yet (first Sunday scan: "not due" in the report). **Failed units:** the command
  `systemctl list-units --state=failed --no-legend` printed nothing on srv and cli2 (and on cli1).
- **Monitor 73 transient:** at T0 "the 5-minute YARA scan has not succeeded for 107 minutes" is the snapshot revert's
  stamp, cleared when the timer ran at 19:02; it did not return. The monitors showed rc 1 at the end only for the AIDE
  repeat (the journal shows that line alone).

## Task 6 notes (install stages)

- Script bug found and fixed (`1ede002`): client installs did not pass `DISK_GB`, so the first cli2 came out 120 GB; it was
  reinstalled at 512. `wazuh-on` expected `/srv/wazuh`; on the sized server it is `/data/wazuh` (by design). The check now
  derives the expectation on each host by `wazuh.py`'s rule (`7b81a11`).
- Image sizes after first boot: srv 11 GB, cli1 9, cli2 9 (virtual 1863 / 120 / 512 GiB). No `DISK_NOTE` in any escrow file.

## ISO 0.6.0-rc2 (chp-site 0.13.0-2) - the release candidate

**What changed vs rc1:** one package. The rc1 quiet day showed that the daily review marked the healthy 24 h Kanidm
certificate ATTENTION below half its life (it is renewed at 8 h left, so ATTENTION showed for about 4 of every 16 h).
`chp-site` 0.13.0-2 (`3e72f90`) flags a short-lived certificate (under 90 days) ATTENTION only below **30 %** of its
lifetime (immediate below 25 %); certificates of 90 days or more are unchanged. Repo 0.11.0 was re-signed by the owner with
that package (`REPO OK: 28 packages`; the rc1-signed copy stays at `/data/chp-release/0.11.0/repo-superseded-chp-site-0.13.0-1`,
never published). `chp-base` 0.1.0-4 and `chp-security` 0.4.1-1 are the same as rc1.

**ISO:** `build-iso.sh 0.11.0 0.6.0-rc2` (after `appliance/iso/push.sh`), `check-iso.sh ISO DVD` = **ISO OK**;
sha256 **`0cb27c1497acdd245af74508ab16a8d9f75a57dd10089372ac2ef9a68067cac0`** (`rc2-build-iso.log`, `rc2-check-iso.log`).
The lab installs boot this ISO and read the repo from it, so there is no separate lab copy of 0.11.0 under
`/data/lab-inputs/chp/` to replace (that directory only serves the `negrepo` stage and has no 0.11.0).

All three hosts were reinstalled from nothing from rc2 (2026-11-11, `SECURITY_ADDONS=yes`): server 1863 GiB sparse,
cli2 512, cli1 120; the size guards (50 GB) were active the whole time and never tripped (0 `SIZE-GUARD` lines), then
stopped at the end (`rc2-guards-stopped.log`: both `inactive`).

| Gate / proof | Result | Log (`iso-0.6.0-logs/`) |
|---|---|---|
| Install stages: prep, server, firstboot, export, client1, client2 | ALL PASS | `rc2-install-chain.log` |
| `wazuh-on` | first run **FAIL**: agents Active 1 of 2 (cli2 still reconnecting after its first boot, the same race noted for rc1 and 0.5.0); re-run a minute later: **ALL PASS** | `rc2-install-chain.log`, `rc2-wazuh-on-rerun.log` |
| Layouts | srv: `/` 90, swap 29, `/backup` 600, `/data` 350, audit 30, `/var/log` 50, `/var/tmp` 15, `/var` 100, `/tmp` 15, `/home` 238, VFree **342.98 GiB**; cli2: VFree **303.98 GiB**, no `/data` or `/backup`; cli1 120 GiB: VFree 0, same as rc1. `/data` `rw,nosuid,nodev`, `/backup` `rw,nosuid,nodev,noexec`. No `DISK_NOTE` in any escrow file (0 x3) | `rc2-layouts.log` |
| Image sizes (`du -B1G`, after the proofs) | srv 14, cli2 11, cli1 9 GB (limit 50) | `rc2-guards-stopped.log` |
| Installed packages | `chp-site-0.13.0-2`, `chp-base-0.1.0-4`, `chp-security-0.4.1-1` on srv and cli2; cli1 `chp-site-0.13.0-2` (root console) | `rc2-layouts.log` |
| **Gate 3:** CUI scan | **108 pass / 2 fail on every host**, the two accepted AIDE rules; `deviations.py --decisions decisions.tsv` rc 0, "Gate 3: MET"; no change from rc1 | `rc2-scan.log`, `rc2-deviations.log` |
| adapter, nvram, snapspike, fixtures, golden | ALL PASS (golden: reset + 0 findings on both hosts) | `rc2-adapter.log`, `rc2-nvram.log`, `rc2-snapspike.log`, `rc2-fixtures.log`, `rc2-golden.log` |
| **Gate 2:** regression (`lab/iso5/regression-2026-11-11.md`) | **33/33** (11 scenarios x 3 runs, all GREEN); model `devstral-small-2-2512`: 33/33 valid, **33/33 agreeing** | `rc2-regress.log` |
| **Gate 2:** row 36 | **3/3**; token label `var_auth_t` afterwards | `rc2-row36.log` |
| Review proofs (`prove-r1.sh`) `on`, `build`, `sign`, `tamper`, `export` | **ALL PASS** (the sign-off from a scripted pty as in rc1, not a human; piped `yes` refused; exactly two ledger entries after the two sign-offs; edited entry and report fail `verify`, monitor 75 alerts; stick export verifies) | `rc2-r1-on.log`, `rc2-r1-build.log`, `rc2-r1-sign.log`, `rc2-r1-tamper.log`, `rc2-r1-export.log`, `rc2-s1-hook.log` |

**How the review proofs were run (honest account):** the `prove-r1.sh` before-files (`/root/r1-t0`, `r1-keys-before`,
`r1-ss-before`, normally made by the `repo`/`enable` stages, which do not apply to a security-on install) were gone
with the reinstall; the first `on`/`build`/`sign`/`tamper` pass therefore failed on missing files (and `build` also on
the missing lab hook). They were made by hand from the boot state of each host (`uptime -s`, client key hash, listener list), the lab hook was set
(`prove-s1.sh hook`), and the review store on srv (which that first pass had polluted with an empty-data report) was emptied. The whole chain was then re-run
and passed; the logs under `rc2-r1-*` are that clean second run (the first failing pass was overwritten and is not kept).
`soon` and `res` were not re-run (not in the rc2 scope).

### The fix itself: the Kanidm certificate row

The review's status row on srv (`rc2-cert-row.log`, from the built report's `data.json`):

    item cert /etc/pki/kanidm/chain.pem, owner 30-kanidm-cert, state OK, detail "23 h left of 24 h"

The certificate was fresh (23 h left), so this sample is **not** in the old false-ATTENTION window (12 h to 7.2 h left)
and cannot show the fix by itself; renewal is not stuck (it is a fresh certificate on a freshly reverted lab). The rule
as installed on srv (`chp_site.review_rules.cert_state`, called with a 24 h lifetime) gives: 23 h OK, 12 h OK, **10 h OK**
(this was ATTENTION in rc1's quiet-day report), 8 h OK, 7.5 h OK, 7.2 h OK, 6 h ATTENTION (not immediate), expired
ATTENTION (immediate). So the healthy cycle (renewal at 8 h left) never flags, and a certificate that fails to renew
is still flagged once it is under 7.2 h. This is evidence of the rule on the installed package, not of a live 10 h
sample; the unit tests in the repo cover the same boundaries.

### Not repeated, by ruling
No second quiet day, and not re-run: the backup-drive runbook, the layout `lvextend` proof, the check 76 catch and the
forced YARA scan (none touch `chp-site`'s certificate rule; `chp-base` and `chp-security` are unchanged from rc1).


## rc2: server under 1.9 TB (final-review ruling, 2026-11-11)

Why: until now no server under 1.9 TB was installed from the release candidate, so the `DISK_NOTE` path of `%post`
(under `set -e`) and the mid-tier sized layout had not run live. **iso5-srv was reinstalled from rc2** (sha256
`0cb27c14...cac0`, `SECURITY_ADDONS=yes`) on a **931 GiB sparse disk** (`DISK_GB=931` = 999,653,638,144 bytes, about
1 TB), size guard at 50 GB (active during the install, stopped afterwards: `inactive`). Run: `prove.sh prep` then `server`
(install from the ISO, menu entry chosen, first boot unlocked): **ALL PASS** (`rc2-1tb-install.log`). Evidence:
`rc2-1tb-evidence.log` (escrow: only the two lines named below were extracted with `grep`; nothing else from that file is
printed or committed).

| Check | Result |
|---|---|
| Install finished | yes, "INSTALLED and started iso5-srv" |
| Escrow file: order of the two lines | `DISK_NOTE=disk is 999 GB, smaller than the recommended 2 TB for the server` at line 9, **before** `INSTALL COMPLETED 20261111T180749Z` at line 10 |
| `CHP:` note line | `CHP: disk is 999 GB, smaller than the recommended 2 TB for the server` is in the installer's `/var/log/anaconda/program.log` (17:58:59, first stage). It was **not** mirrored to the lab's libvirt serial log, so the lab does not show it on the serial console; the note has no console path: it is observed only in the install log and the escrow file (the `tee /dev/console` lines in the kickstarts are for the stop messages, not this note) |
| Layout equals `chp_site.layout.plan("server", 999653638144)` | exactly: `/home` 95232 MiB (93 GiB), `/data` 140288 (137), `/backup` 239616 (234), `/` 92160 (90), `/var` 102400 (100), `/var/log` 51200 (50), audit 30720 (30), `/var/tmp` 15360, `/tmp` 15360, swap 29696 (29); `vgs chp` VSize 927.98, **VFree 134.98 GiB** (layout.py: 134 whole GiB) |
| Mount options | `/data` `rw,nosuid,nodev`, `/backup` `rw,nosuid,nodev,noexec` |
| Packages | `chp-site-0.13.0-2`, `chp-base-0.1.0-4` (the security add-on installs at first boot, which was not waited for: not in scope) |
| Image size | 9 GB actual after the install (limit 50) |

**The lab is not at golden.** cli1 and cli2 were not reinstalled; they now point at a server that was reinstalled for this
check (new identity server, new stick: `prove.sh prep` made a fresh stick image, so the clients' escrow files and tokens on
the stick are gone). The rc2 results above were all taken before this check and stand; a re-run of the lab chain from
`prep` is needed before any further lab proof.
