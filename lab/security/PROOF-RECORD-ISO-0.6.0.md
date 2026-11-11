# Proof record: ISO 0.6.0-rc1 (sized disks, /data and /backup volumes, check 76, sign-off fixes) on the iso5 lab

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
Wazuh manager (it shows no PID, only a start time) were identical before and after, Image after the extension: 14 GB by `du -B1G` on aero (limit 50; this was a separate command, its output is not in the step log, but the same 14 GB is in `quiet-start-state.log`). The trailing bare `0` in `step1-lvextend.log` is the failed-unit count (`systemctl list-units --state=failed --no-legend | wc -l`; the command itself was not captured).
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

`prove-r1.sh` was updated for 0.6.0 (committed): the expected versions, the sign-off through a real terminal
(`ssh -tt`, the reviewer types `yes`), cli1 now reports like the others (installed with the review: all items OK, sysstat
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
  status table, certificates and keys OK. The three `aide_ok` rows read ATTENTION on 11-10 ("changes or mismatch to
  review") but are not counted in "Needs attention", because that item is watched by monitor 60 (a row with an owner
  is excluded by design, `review_report.py` line 247). No monitor 75 "not built" alarm.
- **Hook lines since T0** (srv 111, cli2 110, both with the hook; cli1 has no hook, its monitor journal has 102 AIDE
  lines): srv = 2 YARA lines from the revert at 18:59 (explained above), 1 daily summary ("5 medium alerts (levels 7-9) on
  3 hosts in the last 24 h"), and 108 AIDE repeats; cli2 = the same 2 YARA lines and 108 AIDE repeats. AIDE repeats are
  monitor 60 every 15 minutes until accepted (existing behaviour), for two checks (11-10 and 11-11). The AIDE
  changes are lab-only (`quiet-aide-paths.log`): `99-lab-adapter`, `/root/chp-scan`, `lab-hook`, the three fixture SSH
  keys, `/etc/chp/site.conf` (the hook setting) and their parent directories; srv 8 added / 6 changed, cli2 5 / 5. cli1's
  3 added / 1 changed could not be listed (no lab-adapter sudo there): it holds the scan files under `/root` and its
  parent directory. Nothing from the new volumes, `/data`, `/backup` or check 76.
- **No false check-76 alerts:** no "% full" line in the `chp-monitor` journal of srv or cli2 since T0 (0), none in the
  hook logs, none in cli1's journal; the state file `/var/lib/chp/monitor/76-disk.state` is empty on both. Mounts at
  the end: srv `/var` 2 %, `/data` 2 %, `/backup` 1 %; cli2 `/var` 5 %. VFree unchanged (342.98 / 303.98 GiB).
- **The 24-hour repeat of check 76** is proved by the unit test `tests/test_chp_base_disk_check.py::test_76_repeats_after_24h`
  (the clock is injected with `CHP_NOW`); the quiet day could not show it, because nothing crossed the limit.
- **Image sizes (`du -B1G`, aero):** at T0 srv 14, cli2 11, cli1 9; at the end srv 14, cli2 12, cli1 9 (limit 50).
  Both guards were active at the end and their journal has no `SIZE-GUARD` line (0), so neither tripped. They were then
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
