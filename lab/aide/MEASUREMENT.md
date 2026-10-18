# AIDE churn measurement (spec §4.5) — settles §4.4

**Hosts:** iso5 golden `srv1` and `client2`, upgraded to repo 0.7.0 (`chp-integrity` 0.1.0) by `measure.sh start`.
**T0:** Mon 2026-10-12 21:08 MDT (baseline `BUILT_BY=package-install`). **Deliberate actions:** Mon 21:09 MDT
(`measure.sh actions`: row-36 GA logins, `idm_admin` CLI login, onboard + revoke `lab09`, `dnf reinstall chp-site`).
**Daily checks used:** srv1 2026-10-13 03:48 and 2026-10-14 04:17; client2 2026-10-13 03:38 and 2026-10-14 03:58 MDT
(≈22 min each). **Collected:** 2026-10-14 ~21:20 MDT → `measure-paths.txt`, `measure-<host>/`.

Each check compares against the T0 baseline, so a path changed once appears in both checks. "Check 2 only" marks a
path that changed again after check 1: churn by itself.

## srv1

| Path | Checks | Explained by | Decision |
|---|---|---|---|
| `/etc/pki/kanidm/chain.pem` | 1 (check 2 only) | by itself: daily certificate renewal | **exclude** `/etc/pki/kanidm` — 30-kanidm-cert + 31-renew-timer |
| `/etc/step-ca/db/000000.vlog` | 1 (check 2 only) | by itself: CA issuance database written at renewal | **exclude** `/etc/step-ca/db` (owner 2026-10-14) — 30-kanidm-cert |
| `/var/log/aide/init-*.log` | 2 | by itself: AIDE's own init report, written after the snapshot | **exclude** `/var/log/aide` (owner 2026-10-14) — 60/61 |
| `/var/log/audit/audit.log` | 2 | by itself: growing log (sha512 from the FIPS-hash rule) | **stock checks, no hash** (owner 2026-10-14) |
| `/var/log/{messages,secure,cron,boot.log,dnf.log,dnf.librepo.log,dnf.rpm.log,hawkey.log}`, `/var/log/rhsm/{rhsm,rhsmcertd}.log` | 2 | by itself: growing logs | **stock checks, no hash** (owner 2026-10-14) |
| `/root/chp-onboard`, `/root/chp-onboard/lab09.reset-token.txt` | 2 | deliberate: onboard `lab09` | stays watched |
| `/root/.cache/kanidm_tokens` | 2 | deliberate: `idm_admin` CLI login | stays watched |
| `/usr/bin/chp-site`, `/usr/share/chp-site/chp-site.pyz`, `/usr/share/licenses/chp-site/LICENSE`, `/etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene` | 2 | deliberate: `dnf reinstall chp-site` (all owned by chp-site-0.7.0) | stays watched |
| `/etc/chp`, `/etc/chp/site.conf`, `/usr/local/sbin`, `/usr/local/sbin/chp-test-hook` | 2 | lab harness: `prove-aide.sh upgrade` sets the test `ALERT_HOOK` after the baseline | stays watched (not product behaviour) |

## client2

| Path | Checks | Explained by | Decision |
|---|---|---|---|
| `/var/log/hawkey.log` | 1 (check 2 only) | by itself: dnf makecache | **stock checks, no hash** |
| `/var/log/audit/audit.log`, `/var/log/audit/audit.log.2` (added) | 2 | by itself: growing log; one rotation | **stock checks, no hash**; rotation note below |
| `/var/log/{messages,secure,cron,boot.log,dnf.log,dnf.librepo.log,dnf.rpm.log}`, `/var/log/rhsm/{rhsm,rhsmcertd}.log` | 2 | by itself: growing logs | **stock checks, no hash** |
| `/var/log/aide/init-*.log` | 2 | by itself: AIDE's own init report | **exclude** `/var/log/aide` |
| `/etc/chp`, `/etc/chp/site.conf`, `/usr/local/sbin`, `/usr/local/sbin/chp-test-hook` | 2 | lab harness (as srv1) | stays watched |

## Notes

- **No GA-login churn:** `/var/lib/google-authenticator` is not watched (stock), and nothing else changed from the
  row-36 logins.
- **Revoke** produced no file change beyond the onboard's (the Kanidm database is not watched).
- **Rule order:** AIDE uses the **first** rule for an identical path (checked with `aide --path-check` on srv1), so the
  log change is made on the stock lines (`-sha512`), not as later override lines.
- **Audit-log rotation (open):** stock `/var/log/audit PERMS` has no `ANF`/`ARF`, so a rotation reports the new
  `audit.log.N` as *added*. This is kept as stock Rocky intends (a vanished or new audit file is worth seeing); the
  re-proof's quiet check shows whether it fires within a day.

## Quiet check (Task 13 re-proof)

A clean upgrade with no test hook (`NOHOOK=1`), then the pin; nothing touched the hosts afterwards. The verdict comes from
the second daily timer run (24 h or more, including the 20:01 certificate renewal and log rotation).

**Repo 0.7.1 (baseline 2026-10-15 ~01:40 MDT):** srv1 clean in both checks. client2 alerted in both checks:
- added `/etc/chp/site-stick.hash` (and `/etc/chp` changed): the first stick use (`aide-pin`) wrote the USBGuard hash
  35 s **after** the baseline (database 01:39:22, hash 01:39:57). This is a product bug: every new host would alert
  on its first check.
- added `/var/log/audit/audit.log.2`: auditd rotation (the cost predicted for the stock `/var/log/audit` rule).

**Owner decisions 2026-10-16 (gate form):**
- Pin the stick hash before the baseline, and keep the file watched. Fixed in `chp-site 0.7.1` with `stick-pin-hash`:
  the hash is read from `usbguard list-devices` while the stick is still blocked; the stick is never allowed. On
  client2 the blocked listing showed the same hash that was pinned later. `chp-integrity 0.1.2` runs this in
  `aide-baseline` before `aide --init`.
- Exclude `/var/log/audit/audit\.log\.[0-9]+$`; the live `audit.log` and the directory stay checked. In
  `aide --path-check` on client2, `.1` and `.12` hit the negative rule, while `audit.log` and the directory keep `PERMS`.

**Repo 0.7.2 (baseline 2026-10-16: srv1 12:41; client2 hash 12:42, database 13:04 MDT):** the full proof gave 46
PASS and 0 FAIL, including the new check "stick hash pinned before the baseline" on both hosts. The quiet check passed
on both hosts in both timer runs, with **added=0 removed=0 changed=0 and db_match=yes**:
- srv1: Oct 17 04:34 and Oct 18 04:47.
- client2: Oct 17 04:06 and Oct 18 03:58.

The monitor checks 60, 61 and 62 were all OK.

**Gap:** no audit rotation happened inside the window. client2's last rotation was at 12:55, before its baseline. The
audit exclusion therefore rests on `--path-check`, not on a live rotation. Hosts reverted to golden on 2026-10-18.
