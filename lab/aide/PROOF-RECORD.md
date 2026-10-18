# Proof record: core 0.2.0 Plan A (AIDE file integrity)

**Date:** 2026-10-18 · **Hosts:** iso5 golden lab hosts (srv1 = `iso5-srv`, client2 = `iso5-cli2`), upgraded from the
released 0.1.0 · **Packages:** signed lab repo **0.7.2** (`chp-site 0.7.1`, `chp-integrity 0.1.2`, Rocky-signed `aide
0.19.2`; `appliance/release/RELEASE-RECORD-0.7.2.md`) · **Spec:** `docs/superpowers/specs/2026-10-12-core-0.2.0-aide-design.md`
· **Requirement:** `lab/iso-requirements.md` row 47.

## What was proved

Final run of `lab/aide/prove-aide.sh` against repo 0.7.2: **46 PASS, 0 FAIL**.

| Stage | PASS | What it shows |
|---|---|---|
| `upgrade` | 14 | Both hosts install `chp-site` + `chp-integrity` from the signed repo; our `aide.conf`; the baseline is built at package install with that conf; **the site stick's hash is pinned before the baseline**; daily timer active; database 0600 |
| `pin` | 8 | Monitor check 62 alerts until `chp-site aide-pin`, then is quiet; the record `aide/<host>.txt` is on the site stick |
| `catch` | 6 | Three planted changes on srv1 (a new binary, an edit to `/etc/kanidm/config`, a new sshd drop-in) are all reported; check 60 alerts; `ALERT_HOOK` receives the alert |
| `accept` | 5 | A name not in `BASELINE_DELEGATES` is refused; a listed delegate accepts after seeing the summary; new database installed and pinned; audit records before and after; monitor quiet |
| `verify` | 5 | `aide-verify-pin` MATCH; a database replaced by hand gives `DB_MATCH=no`, a check-60 alert and MISMATCH; `aide-accept` refuses to accept over a replaced database |
| `grouping` | 2 | A reinstalled CHP package is listed as "explained" in the accept summary; declining changes nothing |
| `stale` | 2 | A stopped timer and an old last result both alert (check 61) |
| `selinux` | 4 | 0 AVC denials from AIDE, its wrapper or `chp-site`; 0 fapolicyd denials (both hosts) |

**Finding (not from AIDE):** `fapolicyd-rpm-l` AVCs on `kanidm_unixd_var_run_t` (srv1 6, client2 4). This is the known
Kanidm/fapolicyd issue, already tracked as requirements row 49.

**Check duration:** about 21.5 minutes per host for a full `aide --check` (srv1 21m 26s, client2 21m 46s).

## Quiet check (no false alerts over a full day)

After a clean upgrade with no test hook, nothing touched the hosts. Both daily timer runs were clean on both hosts, with
`added=0 removed=0 changed=0` and `db_match=yes`; monitor checks 60, 61 and 62 were all OK.

| Host | Check 1 | Check 2 (24 h or more, incl. the certificate renewal and log rotation) |
|---|---|---|
| srv1 | Oct 17 04:34 | Oct 18 04:47 |
| client2 | Oct 17 04:06 | Oct 18 03:58 |

The quiet check on the earlier repo 0.7.1 failed on client2 and led to two fixes (owner decisions, 2026-10-16):
- **Stick hash pinned before the baseline.** The first use of the site stick wrote `/etc/chp/site-stick.hash` 35 s
  after the baseline, so every new host would alert on its first check. `chp-site stick-pin-hash` now reads the hash
  of the plugged-in, **still blocked** stick and never allows it. `aide-baseline` runs it before `aide --init`.
- **Rotated audit logs excluded.** The exclusion is `!/var/log/audit/audit\.log\.[0-9]+$`. The live `audit.log` and
  the directory stay checked.

Details and timings: `lab/aide/MEASUREMENT.md`.

## Measurement (settles spec §4.4)

The measurement ran 48 h unattended on the upgraded hosts, plus deliberate actions: logins, the daily certificate
renewal, onboard, revoke and a package reinstall. Results are in `lab/aide/MEASUREMENT.md`. The exclusions, each with
the control that covers it instead:

| Excluded | Why | Covered instead by |
|---|---|---|
| `/etc/pki/kanidm` | Kanidm certificate re-issued daily | monitor checks 30 and 31 (chain to the pinned root) |
| `/etc/step-ca/db` | step-ca issuance database, rewritten at each renewal | check 30; step-ca configuration and keys stay content-checked |
| `/var/log/aide` | AIDE's own reports | checks 60 and 61 |
| `/var/log/audit/audit\.log\.N` | auditd rotation | auditd's root-only files (3.3.8); the live log and the directory stay checked |

Growing logs (`/var/log`, `/var/log/journal`, `/var/log/audit`) keep the stock Rocky checks without a content hash
(owner decision 2026-10-14).

## Compliance scan (Task 9)

The 8 SSG AIDE rules are selected in the tailoring. Result: **6 pass and 2 planned deviations, met by equivalent
means** (spec §8):
- `aide_periodic_cron_checking`: AIDE runs daily from a systemd timer, and the staleness alert (check 61) covers it.
- `aide_scan_notification`: notices go to the journal and `ALERT_HOOK`, not to mail.

## Not proved here (carried into Plan B)

- **Fresh install, first-boot baseline.** Everything above was proved on upgraded 0.1.0 hosts. In Plan B the
  kickstarts must:
  - add `chp-integrity` to `%packages`;
  - add `chp-aide-check.timer chp-aide-baseline.service` to the `systemctl enable` line. On a fresh install, the
    package's existing-host branch in `%post` does not run.
- **Plan B gate 1** re-runs a 24 h quiet check on the fresh install. It must also show `site-stick.hash` older than the
  database. On a fresh install, that depends on the stick still being plugged in when first boot finishes.
- **A live audit rotation inside a quiet window was not observed.** client2's last rotation fell just before its
  baseline, so the exclusion was proved with `aide --path-check`. Watch for a rotation in gate 1.
- **Residual:** if the stick is not plugged in when the baseline is built, the first stick use alerts once, and the
  alert is accepted with `aide-accept`. The upgrade note says to leave the stick in during the install. Pinning the
  hash in the kickstart's `%post` is a possible later fix; it is untested.
- The ISO, and gates 2–3 (the full CUI scan) are not covered here.
