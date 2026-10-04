# Snapshot / image restore: design

Date: 2026-10-04. Status: design approved in conversation by the ISSO; this spec awaits review.
Fifth gap item. Policy: requirement rows 18 and 19 (already decided) and ISSO decision #30 (a person may approve a
one-time clock step). Format: `runbooks/README.md`.

## Why: the spike (2026-10-04, throwaway, lab only)

A raw `virsh snapshot-revert … golden --running` of srv1 and client2, with none of `lab/reset.sh`'s fix-ups:

| Observation | Evidence |
| --- | --- |
| Both clocks ~14 h behind (hosts 23:24, real time 13:19) | `chronyc -n sources`: `^~ 192.168.100.1 … -50085s[-50085s]` (`~` = too variable) |
| **The engine reported no findings** on either host | report: `offset_s ≈ 0`, `synced: true`, `source_offset_s: -50085.0`; the rule trusts `synced` |
| **`time-resync` returned OK but changed nothing** | after it, client2 still read 23:26; `chronyc makestep` does nothing while the source is rejected, and its verify read the same stale tracking offset |
| Only `systemctl restart chronyd` fixed it | both `^*`, offsets of microseconds |

So a freshly restored host with a 14-hour clock error looks healthy, and the clock repair claims success without
effect. Requirement row 18 already says: after any restore, restart chronyd before anything else.

## Part 1: detection and repair

**Collector** (`collector/idm-collect`, `source-offset` block): also record the first source's state character, the
one after `^` in `chronyc -n sources` (`*` selected, `+` combined, `-` not combined, `~` too variable, `?`
unusable, `x` falseticker), as `time.source_state` (null when there is no source line).

**Rule** (`engine/findings.py`, `_skewed`): in addition to today's conditions, the clock is skewed when
`source_state == "~"` and `|source_offset_s| > SKEW_S`, whatever `synced` says. A stale pre-step sample after a
legitimate step shows `*`, so the 2026-09-28 protection stands. `TOTP_TIME_SKEW` evidence then adds:
`"chrony rejects its time source as too variable (<offset> s off): typical after restoring a snapshot or image (requirement row 18)"`.
Reports without `source_state` behave exactly as before.

**Repair `time-resync`** (`engine/repairs.py`):
- `apply`: `systemctl restart chronyd` (clears the restored sample history; the CUI `makestep 1.0 3` then steps on the
  first updates), `chronyc waitsync 30 0.5`, then `chronyc makestep`, `chronyc burst 4/4`, `chronyc waitsync 6 1.0`.
- `verify_present`: passes only when `synced`, `|offset_s| < 1`, **and**, when the report carries `source_state`,
  `source_state == "*"` and `|source_offset_s| < 1`. A stale "synchronized" no longer passes.
- `describe`: "restart the time service and step the clock to the time source (chronyc makestep). Not reversible,
  and not meant to be: the old time was wrong".

**Runbook `TOTP_TIME_SKEW.md`** (`decisions: 30`; wording shown to the ISSO before shipping): `repair` becomes
"Restart the time service and set this workstation's clock to the time source now, once, with your approval." The
model text adds the restore case and row 18.

## Part 2: scenario, procedure, tests

**Scenario R1 (`scenarios/r1.py`), restored workstation:** after the normal reset, revert client2 to `golden` again
(`virsh snapshot-revert client2 golden --running` on aero) without restarting chronyd, wait for ssh, then wait (up to
5 minutes, as L4) until `TOTP_TIME_SKEW` is visible. `EXPECT = {"client2": {"TOTP_TIME_SKEW"}}`,
`REPAIRS = [("client2", "time-resync")]`, `HOSTS = ["client2"]`, `USER = "lab04"`. Final probe: a fresh report
shows `source_state == "*"` and `|source_offset_s| < 1`, and lab04's login works.
(The clock error equals the time since `golden` was taken, so it grows; right after a fresh golden it can be under a
minute, hence the wait.)

Regression: R1 3/3; L4 3/3 (the 10-minute jump must still be found and fixed); full 11/11; D1, D2, F1, F2, P1–P3 1/1.

**Procedure `runbooks/procedures/after-restore.md`** (linked from the README):
1. Restart chronyd before anything else (row 18), on the server too: `time-resync` runs on workstations only, so on
   the server this step is by hand (its TOTP_TIME_SKEW now shows the restore case). Check: no clock finding.
2. Check the certificate: an old image can carry an expired Kanidm certificate (TLS_CERT_EXPIRED → existing repair).
3. Authenticator hosts: wait out the code window and do not retry failed logins (row 19); retries feed faillock
   (ACCOUNT_LOCKED).
4. Expect what a restore brings back: account changes made after the image was taken exist only on the server.

**Unit tests:** collector `source_state` for `*`, `~`, `?` and no source line; rule fires on `~` with a large offset
while `synced`, stays quiet on `*` with a stale sample, unchanged without the field; repair `apply` restarts chronyd
before `makestep`; `verify_present` refuses `synced` with `source_state` `~` or a large source offset; runbook wording;
procedure present and linked.

**Release:** idm-collect 0.1.0-8 (this change plus the `uptime_s` field from the power-outage work) in signed repo
0.5.7; lab install; golden re-taken.

## Final review corrections (2026-10-04)

- The collector reads the source chrony **uses** (`^*`) when there is one, else the first `^` line, for both state
  and offset: with several servers the selected one is often not listed first (otherwise verify could never pass on a
  healthy multi-server site). Verify skips the source check when `source_state` is null (refclock/peer-only hosts).
- The precheck refuses when `chronyd -p` cannot parse the configuration (a restart would leave no time service);
  apply starts chronyd again and fails the step if the restart fails.
- The first `waitsync` is bounded explicitly: `chronyc waitsync 15 0.5 0 2` (~30 s, not ~5 minutes).
- A restored clock (`~`) gets no "just started" note: it never clears by itself.

## Out of scope

Kanidm database backup/restore (`kanidmd database backup/restore`): never tested in the lab; a later item.
