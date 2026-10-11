# Gate 3: CUI scan and deviation table (ISO Plan 5a)

**ISO:** `cyberhygiene-lab-installer-el9.iso` 0.1.0-rc3 (repo 0.6.1) · **Scanned:** 2026-10-10, on the three hosts
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

## Generated table (run 2)

### CUI scan deviations (iso5-cli1.iso5.lab.test, iso5-cli2.iso5.lab.test, iso5-srv.iso5.lab.test)

## Failures

| rule | severity | hosts | decision | decided by | reason | title |
|---|---|---|---|---|---|---|

## Not evaluated


**Gate 3: MET** (0 failing rules)
