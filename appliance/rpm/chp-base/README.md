# chp-base

Common first boot (TPM binding of the root LUKS volume), the monitor framework (`/usr/libexec/chp/monitor`, checks in
`/usr/lib/chp/monitor.d/`) and the fapolicyd `allow_filesystem_mark` mechanism, on every CyberHygiene host.
Build: `build-rpm.sh` (runs on the Mac, builds on aero into `/data/chp-release/built/`).

## fapolicyd allow_filesystem_mark (FSMARK)

- Flag: `FSMARK=0|1` in `/etc/chp/fapolicyd-fsmark.conf`. Shipped **FSMARK=0 (OFF)**: nothing is touched.
- Helper: `/usr/libexec/chp/fapolicyd-fsmark` applies the flag (marker line `# chp-managed: allow_filesystem_mark` in
  `/etc/fapolicyd/fapolicyd.conf`); inside the rpm transaction it only records `/var/lib/chp/fapolicyd-restart-pending`.
- Check 80 (`monitor.d/80-fapolicyd.sh`) alerts when fapolicyd is not active, permissive, a restart is pending, or the
  helper's failure record exists.

**Do not use FSMARK=1 with fapolicyd 1.4.3-3.el9 (Rocky 9.8).** With `allow_filesystem_mark = 1` that version exits
about one second after start ("recvmesg failed", `status=1/FAILURE`): fapolicyd is down and nothing checks file
execution (fail-open). Lab proof: `lab/docs-proof/logs/13-fsmark-fapolicyd-failed.log` (ISO 0.7.0 Plan 2 Task 9, D2).
The same exit was later seen with allow_filesystem_mark = 0 too: 3 of about 18 restarts on the lab in round 3 (D6,
`lab/docs-proof/logs/28-fapolicyd-failed-after-enable.log`). It is intermittent in 1.4.3-3 and not caused by the
setting, so every restart is verified, by this helper and by `chp-site documents enable`.

Safety net: after every restart the helper performs it checks that fapolicyd is still `active` at three samples over
5 s (`CHP_FSMARK_SETTLE`). If not, it reverts its own marked change, restarts fapolicyd again, logs at `crit` to the journal
(`journalctl -t chp-fapolicyd-fsmark`), writes `/var/lib/chp/fapolicyd-fsmark-failed` (check 80 alerts) and exits
non-zero. While that record exists FSMARK=1 is refused. A restart done later for a pending marker (chp-site documents
enable, or the operator) must be followed by `/usr/libexec/chp/fapolicyd-fsmark --verify` (same check, same rollback).
To clear the record: set FSMARK=0 and run the helper by hand (chp-base's own %posttrans run never clears it, so a package
update cannot silently end check 80's alert). With no change of ours to revert (FSMARK=0), a dead fapolicyd is
restarted once more: back up = a warning in the journal; still down = the record, exit 1 (check 80 alerts).
`chp-site documents enable` does the same after its own fapolicyd restart and then runs `--verify`.
