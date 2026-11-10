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
| **Gate 3:** CUI scan (`prove.sh scan`) | **108 pass / 2 fail on every host**, the two accepted AIDE rules; `deviations.py` exit 0. The new volumes (`/data`, `/backup`, their mount options) caused **no change**: no rule appeared or disappeared, so `DEVIATIONS.md` needed no new entry |
| lab adapter, nvram, snapspike, fixtures (`FIXTURES OK`), golden | ALL PASS (golden: reset + 0 findings on both hosts) |
| **Gate 2:** regression (`lab/iso5/regression-2026-11-10.md`, commit `33223ef`) | **33/33** (11 scenarios x 3 runs, all GREEN), Wazuh, YARA and Suricata running. Model: 33/33 valid, 32/33 agreeing (l4: 2/3, the same as in 0.2.0; each repair is code-driven) |
| **Gate 2:** row 36 | **3/3**; token label `var_auth_t` afterwards |
| Forced weekly YARA scan (`prove-y1.sh full`, cli2, 512 GiB layout) | 112,185 files, 67 s, **1 match (the test file only)**, 0 errors; last-full written; monitor 73 OK |

### Step 1: layout proof (srv)

`findmnt`: `/data` = `rw,nosuid,nodev,...` and `/backup` = `rw,nosuid,nodev,noexec,...`, both on their own LVs;
`/var/ossec` is the bind mount of `chp-data[/wazuh]`. `lvextend -r -L +5G chp/var`, online: `/var` 102,336 M -> 107,456 M
(+5 GiB), VFree 342.98 -> 337.98 GiB; the `MainPID` and start time of kanidmd, sshd and chronyd and the start time of the
Wazuh manager were identical before and after, 0 failed units. Image after the extension: 14 GB (limit 50).
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
| `sign` | the ISSO signs **from a terminal**: "signed 1 review(s); recorded in the ledger and the audit log"; an unlisted name is refused; **piped `yes` is refused: "review sign needs a terminal…"**; **bad `--date 2026-13-45` gives "--date must be YYYY-MM-DD" and no traceback**; `review verify` clean; sign-off in the audit log |
| `tamper` | ALL PASS: two entries (so neither refused attempt signed anything); an edited entry and an edited report both fail `review verify`; monitor 75 alerts; restored: clean |
| `export` | ALL PASS: to the stick, `verify --stick` OK; an emptied ledger fails against the stick |
| `soon`, `res` | ALL PASS; record about 2.3 KB (srv) / 1.8 KB (cli2), about 0.4 s CPU per run |

One check of mine was wrong, not the product: "the refused attempts signed nothing" redirected `ledger.jsonl` from a
non-root shell (Permission denied). It is fixed in the script (`sudo cat | wc -l`); the point itself is shown by the
`tamper` stage counting exactly 2 entries after the two real sign-offs. The Mac-side `yes` stand-in for a terminal is
the only difference from the ISSO typing it.

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
  mounted from `backupdrive` (vdb, TPM unlock), `/backup/lab-test` intact, 0 failed units, 76 OK. The monitor's only
  alert was the AIDE change.
- Step 13: `chp-site aide-accept` (answered **no**, to leave the lab untouched) listed 15 paths. Beyond the lab's own
  (`99-lab-adapter`, `/root/chp-scan`, the fixture SSH keys) these were the move's:
  `/etc/crypttab`, `/etc/fstab`, **`/etc/fstab.bak`**, **`/etc/lvm/backup/chp`** and **`/etc/lvm/archive/chp_00001-*.vg`**.

**The runbook was wrong in two places (fixed and committed):** step 13 said the list "must list only `/etc/fstab` and
`/etc/crypttab`", which would make every ISSO say no. It now names the five paths the move explains and says anything
else is not from the move. Step 12 now says the journal line "Failed to activate with specified passphrase" before
"Finished Cryptography Setup" is normal (the empty first try, then the TPM). The top "What changes" note now mentions
the LVM records.

Afterwards the second disk was detached (`virsh detach-disk --persistent --live`), `iso5-srv-2.qcow2` deleted, the lab
stick's `iso5-srv-backup-drive.txt` removed, and srv reset to golden (`reset.sh`), so the quiet day runs on the fresh
layout (`/backup` on `chp-backup`, VFree 342.98 GiB).

## Quiet day: PENDING

**T0 = 2026-11-10T01:59:15Z (2026-11-09 18:59 MST).** srv and cli2 are at golden (reverted at about 18:57 MST) plus a lab
`ALERT_HOOK` on each (`/usr/local/sbin/lab-hook` -> `/var/log/lab-hook.log`); cli1 was not touched after the install.
Guards `size-guard-iso5-srv` and `size-guard-iso5-cli2` are running (limit 50 GB). Image sizes at T0 (`du -B1G`): srv 14,
cli2 11, cli1 9.

At T0 the monitor on both hosts showed one alert, "the 5-minute YARA scan has not succeeded for 107 minutes", an
artefact of the snapshot revert (the stamp is the snapshot's). The timer ran at 19:02 MST and the monitor was clean
(rc 0) on both hosts at 19:03. So each hook log starts with **2 explained lines** (18:59:12 / 18:59:57 on srv,
18:59:14 / 18:59:59 on cli2: that alert, sent by my two monitor runs); anything after them needs an explanation.

To check after at least 24 hours, with the lab untouched:

1. The **real 00:20 build** made the review report for 2026-11-09 and monitor 75 did not raise a "not built" alarm;
   record counts per host, the status table, resources.
2. **No false check-76 alerts** on srv, cli1 or cli2 (journal `chp-monitor` and the hook logs).
3. **Image sizes stable** (`du -B1G` on all three, well under 50 GB), `/data` and `/var` use on srv, VFree unchanged.
4. **Every hook line explained** (AIDE repeats from the lab adapter and fixtures, the daily summary, the review line).
5. Then stop the guards.

## Task 6 notes (install stages)

- Script bug found and fixed (`1ede002`): client installs did not pass `DISK_GB`, so the first cli2 came out 120 GB; it was
  reinstalled at 512. `wazuh-on` expected `/srv/wazuh`; on the sized server it is `/data/wazuh` (by design). The check now
  derives the expectation on each host by `wazuh.py`'s rule (`7b81a11`).
- Image sizes after first boot: srv 11 GB, cli1 9, cli2 9 (virtual 1863 / 120 / 512 GiB). No `DISK_NOTE` in any escrow file.
