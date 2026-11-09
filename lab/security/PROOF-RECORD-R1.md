# Proof record: Plan R1 (the ISSO's daily security review), signed repo 0.10.0 (2026-11-07/08)

Lab: iso5 golden (ISO 0.5.0: FIPS, SELinux enforcing, fapolicyd, USBGuard; Wazuh 4.14.9, YARA and Suricata on).
srv = iso5-srv (manager, builds the review), cli2 = iso5-cli2 (agent); cli1 stays on 0.5.0 with no review (no
lab-adapter sudo) as the mixed-version case and must show STALE. Script: `lab/security/prove-r1.sh`.
Repo 0.10.0 = 28 packages, `REPO OK` (YubiKey `2DE0D71B…3C908F8E`): chp-site **0.12.0-3**, chp-security **0.4.0-2**,
plus `sysstat`, `pcp-libs`, `pcp-conf`, `lm_sensors-libs` (Rocky-signed). Unchanged otherwise from 0.9.2.

The repo was signed three times; only the third (final) one exists. The second signed copy (chp-site 0.12.0-2) is
kept, never published, at `aero:/data/chp-release/0.10.0/repo-superseded-chp-site-0.12.0-2/`.

## Results on the 0.12.0-1/-2 packages (2026-11-07)

| Stage | Result |
|---|---|
| `repo`, `enable srv`, `enable cli2` | RC=0; upgrade = chp-site + chp-security only (dry-run from the unsigned stage first) |
| `on` | ALL PASS: sysstat and record timers; record log 0640; **no new listener**; 0 AVCs; 0 fapolicyd denials; agent keys unchanged; records from both hosts on the manager; build timer; review rules; monitor 75 runs |
| `build` | ALL PASS (after the lab finding below): Suricata catch from srv (inside), YARA test file under cli2, cli1 STALE, certs/keys/scans/repo OK, client lenient / server strict, resources |
| `sign` | ALL PASS: the ISSO signs; `review verify` clean |
| `tamper` | ALL PASS: an edited earlier entry and an edited kept report both fail `review verify`; monitor 75 alerts |
| `export` | ALL PASS: reports + ledger + head on the stick; an emptied ledger fails `review verify --stick` |
| `soon` | ALL PASS: a long-lived test certificate with 5 days left → monitor 75 alerts at once |
| `reboot` | ALL PASS: cold reboot cli2 then srv; review timers active again; records arrive |
| `res` | record about 2 KB, about 0.4 s CPU per 10-minute run (< 0.1 % CPU); review folder 44 KB |

Forced weekly YARA scan before the quiet day: 112,203 files, 1 match (the test file only).

Lab finding (fixed TDD before the final review): a weekly YARA scan that had never run showed STALE on a freshly
enabled host. The host record now carries `security_since`; the report treats "never ran" as OK for 8 days, as monitor
73 does.

Final whole-branch review: 1 Critical (a deleted ledger passed verify) and 12 Important, all fixed TDD (ledger head
witness, recovery steps, all three report files hashed, missing signed report, forged/bad records skipped,
records never reach the hook, incomplete sections, sysstat item, Markdown injection, enable-day alert, logrotate,
Requires). I10 by owner option C: the server is judged strictly at day end; clients show "last seen HH:MM".
Deferred minors are listed in the PR body.

## Quiet day (2026-11-07 13:22 → 2026-11-08 14:00 MST, lab untouched)

- **The real 00:20 build** made `2026-11-07` (`lab/security/r1-quiet-day/report-2026-11-07.md`): 3,342 alerts, 64
  records from srv and 63 from cli2; CPU, memory and network present for both; **1 item needing attention = cli1
  STALE** (expected). cli2 "last seen 23:57". srv's weekly scan "first weekly scan not due yet".
- **Hook lines since T0: 40**, all explained: 1 grouped YARA flush from the re-proof's test file (13:36), 1 review
  line (00:25, cli1 STALE), 1 daily medium summary, 37 AIDE repeats (monitor 60, every 15 minutes until accepted:
  existing behaviour). **No monitor 75 "not built" false alarm.**
- **The real Sunday weekly YARA scan** (03:37/03:43): srv 112,520 files, cli2 112,206 files, **0 matches** on both
  (the 0.5.0 Suricata-rules false alarm stays fixed).
- **AIDE's first daily check:** srv 146 added / 51 changed, cli2 139 added / 45 changed. Every path is owned by the
  six new or upgraded packages, is a link or folder they make, or is lab-only (lab adapter sudoers, `/root` proof
  files, `lab-hook`, fixture SSH keys, srv `site.conf`): `lab/security/r1-quiet-day/aide-unexplained-*.txt`.
  Two corrections to the update notes followed: the sysstat links sit under `sysstat.service.wants/` and
  `multi-user.target.wants/`, and `security enable` from a login shell changes the SELinux user of
  `/etc/suricata/chp-suricata.yaml` and `/etc/sysconfig/suricata` (content unchanged).
- Suricata RSS flat at 531 MB; `chp-review.json` 322 KB/day (srv), 281 KB/day (cli2); no restarts.

**Two display faults found** in the frozen report: the header printed the record counts as a Python dict, and an
alert with no address printed `None` as its source. Owner option A: fixed TDD (`d0b1feb`, chp-site 0.12.0-3), repo
re-signed. The signing first failed because Terminal's **Secure Keyboard Entry** held macOS Secure Input, so the PIN
window got no keystrokes; with it unticked the signing went through (signature counter 771 → 787).

## Re-proof on the final packages (2026-11-08, lab reset to golden)

`repo`, `enable srv`, `enable cli2`, `on` (ALL PASS), `build`: all checks pass except "certs, keys, scans and repo OK",
which showed **ATTENTION `aide_ok` on srv**. Ruling: correct. The golden snapshot's daily AIDE check was overdue,
caught up at 16:37 right after the reset, and found the lab-only files (23 lines, all lab). The report is right to flag
unaccepted AIDE changes. Report text: header `records iso5-cli2 1, iso5-srv 1`, sources without an address `?`,
no Python literals in `report.md` (the only braces in `report.html` are its CSS).

Script fix: the build stage's poll matched its own logged sudo command (`r1-eicar`); it now looks for
`YARA match.*r1-eic[a]r`.

No second quiet day: 0.12.0-3 changes two lines of report formatting only.

## Gates (upgraded lab, new `nvram` + `golden` snapshots: ALL PASS, engine findings `[]` on both)

| Gate | Result |
|---|---|
| 1. Regression (`lab/iso5/regression-2026-11-08.md`, commit `9bf07bd`; the report's own date is UTC) | **33/33** (11 scenarios × 3 runs, all GREEN) |
| 2. Row 36 (desktop login: password + authenticator code) | **3/3** |
| 3. CUI scan | **108 pass / 2 fail on every host** (srv, cli1, cli2), the same two accepted AIDE rules; `deviations.py`: **Gate 3 met** |
