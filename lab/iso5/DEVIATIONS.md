# Gate 3: CUI scan and deviation table (core 0.2.0 Plan B)

**ISO:** `cyberhygiene-lab-installer-el9.iso` 0.2.0-rc2 (repo 0.7.4) · **Scanned:** 2026-10-24, on the three hosts
installed from that ISO (`iso5-srv`, `iso5-cli1`, `iso5-cli2`). The hosts had passed gate 1's quiet check, and the
Plan B lab adapter had not been added.
**Profile:** `xccdf_net.cyberinabox_profile_cui_dc2`. This is the CUI profile plus the dc2 tailoring
(`lab/kickstart/dc2-reference/dc2-cui-tailoring.xml`). The tailoring unselects `sysctl_user_max_user_namespaces` and
selects the 8 SSG AIDE rules **and their parent groups** `software-integrity` and `aide`. The CUI profile deselects
those two groups, so without them the rules come out "notselected"; this was found and fixed on 2026-10-24.
**Results:** `scan-results/*.xml.xz`. Regenerate this table with `unxz -k scan-results/*.xz` and then
`deviations.py scan-results/*.xml --decisions decisions.tsv`.

**Result on every host: 108 pass, 2 fail.** The failures are the two AIDE deviations, met by equivalent means and
accepted by the ISSO (spec §8):
- `aide_periodic_cron_checking`: daily `chp-aide-check.timer`, plus the staleness check `61-aide-stale`.
- `aide_scan_notification`: the monitor reports to the journal and `ALERT_HOOK`; the appliance has no MTA.

The other 6 AIDE rules pass. 102 + 6 = 108, so the group selection brought in no other rules. `deviations.py` exit code
0: **Gate 3 met.**

## Failures

| rule | severity | hosts | decision | decided by | reason | title |
|---|---|---|---|---|---|---|
| xccdf_org.ssgproject.content_rule_aide_periodic_cron_checking | medium | iso5-cli1.iso5.lab.test, iso5-cli2.iso5.lab.test, iso5-srv.iso5.lab.test | accept | D. Shannon (ISSO) | Met by equivalent means (spec §8, 2026-10-12): chp-aide-check.timer daily + 61-aide-stale; the OVAL test accepts only a cron line | Configure Periodic Execution of AIDE |
| xccdf_org.ssgproject.content_rule_aide_scan_notification | medium | iso5-cli1.iso5.lab.test, iso5-cli2.iso5.lab.test, iso5-srv.iso5.lab.test | accept | D. Shannon (ISSO) | Met by equivalent means (spec §8, 2026-10-12): monitor -> journal + ALERT_HOOK (no MTA on the appliance); the OVAL test accepts only /bin/mail on the cron line | Configure Notification of Post-AIDE Scan Details |

## Not evaluated


**Gate 3: MET** (2 failing rules)


---

## History: ISO 0.1.0-rc5


**ISO:** `cyberhygiene-lab-installer-el9.iso` 0.1.0-rc5 (repo 0.6.3) · **Scanned:** 2026-10-11 (run 4; rc3 and rc4 gave the same result), on the three hosts
installed from that ISO (`iso5-srv`, `iso5-cli1`, `iso5-cli2`). The hosts were **pristine**: nothing had been changed
after the install, and the Plan 5b lab adapter had not been added.
**Profile:** `xccdf_net.cyberinabox_profile_cui_dc2`. This is the CUI profile plus the dc2 tailoring
(`lab/kickstart/dc2-reference/dc2-cui-tailoring.xml`), which unselects `sysctl_user_max_user_namespaces`.
**Content and scanner (on the hosts):** `scap-security-guide-0.1.80-1.el9_7.rocky.1.2`, `openscap-scanner-1.3.13-1.el9_7.rocky.0.1`.
**Results:** `scan-results/*.xml.xz`. Regenerate this table with `unxz -k scan-results/*.xz` and then
`deviations.py scan-results/*.xml --decisions decisions.tsv`.

**Result on every host: 102 pass, 0 fail, 35 not applicable, 1 informational** (138 rules selected). `oscap` exit code 0.

## History: run 1 (ISO 0.1.0-rc2) had 2 failures, both fixed by ISSO decision

| Rule | Severity | ISSO decision (D. Shannon, 2026-10-10) | Fix (verified in run 2) |
|---|---|---|---|
| `ensure_redhat_gpgkey_installed` | high | **fix** | kickstart `%post`: `rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9`. The CUI remediation had imported Red Hat's keys, not Rocky's. This also closes row 46's backlog item |
| `grub2_password` | high | **fix** | A per-host random boot-loader password, escrowed on the site stick as `GRUB_PASSWORD`. The kickstart gets only its PBKDF2 hash (`bootloader --iscrypted`; the hash format is checked against `grub2-mkpasswd-pbkdf2`). Why: the TPM unlock (PCR 7) does not cover boot-option edits |

Run 1's results are in git history (commit cb7c425). The decisions are in `decisions.tsv`.

## Generated table (run 4, rc5)

### CUI scan deviations (iso5-cli1.iso5.lab.test, iso5-cli2.iso5.lab.test, iso5-srv.iso5.lab.test)

## Failures

| rule | severity | hosts | decision | decided by | reason | title |
|---|---|---|---|---|---|---|

## Not evaluated


**Gate 3: MET** (0 failing rules)
