# Proof record: security bundle Plan Y1 (YARA, 0.3.0-update1) on the iso5 lab

Repo **0.8.0** (signed 2026-11-02, 19 packages: `chp-site-0.10.0`, `chp-security-0.2.0`, `chp-yara-rules-2026.10.29`
(signature-base 36ab704, 748 rule files), `yara-4.5.2` (Rocky AppStream), `chp-identity-server-0.1.2-2`, plus the 0.7.9
set). Hosts: iso5-srv and iso5-cli2 at the ISO 0.3.0-rc3 golden snapshots (Wazuh on), upgraded with
`lab/security/prove-y1.sh repo` and enabled with `chp-site security enable` (server first). iso5-cli1 has no lab-adapter
sudo and stays on 0.3.0 (mixed versions); its agent stays Active with the 0.8.0 manager. Spike: `SPIKE-YARA.md`.

## Design as proved (spec §10, owner amendments 2026-11-02)

Every host scans files changed in `/home /root /tmp /var/tmp /dev/shm /srv /data` every 5 minutes
(`chp-yara-recent.timer`) and every local file system weekly (`chp-yara-fullscan.timer`). Wazuh file monitoring and
active response stay off. Lab finding behind the amendments: the scan-only active response was never sent to a remote
agent, and on a freshly enabled server it did not run for the server's own events either.

## Proof 1: enable (`yara-on`): ALL PASS

On both hosts: yara, chp-yara-rules and chp-security 0.2.0 installed; both timers enabled; Wazuh FIM off; the YARA log
exists before any scan; 0 "No such tag"; 0 YARA/Wazuh AVCs; 0 fapolicyd denials; agent keys unchanged. Server: the YARA
alert rules present; both agents Active; no active response configured.

## Proof 2: catch (`hook`, `catch`): ALL PASS

The EICAR test string in the admin's home folder and in `/tmp` on iso5-cli2, and in `/tmp` on iso5-srv: match lines
on both hosts within the 5-minute window; two rule-100501 (level 12) alerts for iso5-cli2 on the server; the YARA alerts
reached the lab `ALERT_HOOK`; both client files still present and unchanged (alert only).

Found and fixed during proof 2: Wazuh's log collector opens a log that appears after it started from the END, so the
first matches on a new host were lost. `security enable` now creates `/var/log/chp-yara.json` before Wazuh starts.

## Proof 3: weekly scan (`full`): ALL PASS

iso5-cli2, started by hand with an EICAR file in `/var/tmp`: 111,940 files in 64 s, 1 match (the test file), 0 errors;
`last-full` written; monitor check 73 OK.

## Proof 4: quiet day: PASS

T0 = 2026-11-02 10:09 MST, read 2026-11-03 11:22 MST (25 h, no resets):
- **No false alarms:** the only YARA matches on either host are the EICAR test files written before T0; 0 errors.
- The 5-minute scan ran all day on both hosts (about 280 runs each); the weekly timer is next due Sunday 03:30;
  monitor check 73 OK.
- **AIDE** (the first daily check after the update; added / changed): iso5-srv 39 / 43, iso5-cli2 35 / 28. Every entry is
  explained:
  - **added by the update:** the `yara` and `chp-yara-rules` package files, `/usr/lib64/libyara.so.10*`, the
    `chp-yara-recent` and `chp-yara-fullscan` units and their `timers.target.wants` links, monitor check 73, and on the
    server `/var/ossec/etc/rules/chp_yara_rules.xml`;
  - **changed by the update:** the upgraded CHP packages' files (`chp-site`, `chp-security`, and on the server
    `chp-identity-server`), `/etc/chp/security.conf` and `/var/ossec/etc/ossec.conf` (rewritten by `security enable`),
    `/etc/ld.so.cache`, `/etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene` and `RPM-GPG-KEY-WAZUH`, and the parent folders;
  - **lab only:** `/etc/sudoers.d/99-lab-adapter`, `/usr/local/sbin/lab-hook` and the `ALERT_HOOK` line in
    `/etc/chp/site.conf`, `/var/lib/ssh-ca/keys/lab0*.pub` (scenario users), `/root/chp-scan`, `/root/y1-*`.

## Gates on repo 0.8.0 (2026-11-03)

After the quiet day: `prove.sh adapter`, `nvram`, `golden` (ALL PASS, 0 findings; the scenario users were already in the
rc3 golden snapshots, so `fixtures.py` stopped on an existing user, as expected), then:

| Gate | Result |
|---|---|
| 2. Regression (`lab/iso5/regression-2026-11-03.md`) | **33/33 GREEN** with Wazuh and the YARA timers running |
| 2. Row 36 (desktop login: password + authenticator code) | 3/3 |
| 3. CUI scan | **108 pass / 2 fail on every host**, the same two accepted AIDE rules; `deviations.py`: Gate 3 met |

Gate 1 for an update is proofs 1–4 above (the upgrade path); a fresh install with YARA is ISO 0.4.0's gate.

## After the final review (2026-11-03): chp-site 0.10.0-2, chp-security 0.2.0-2, repo 0.8.0 re-signed

The fixes (byte-safe scan lists, names with line breaks scanned one by one, failed runs not recorded as success, the
5-minute-scan monitor check, `/run/user`, unit time limits) were proved by upgrading the golden hosts (which held the
first 0.10.0-1 / 0.2.0-1 builds) and re-running proofs 1–3:
- `yara-on`, `hook`, `catch`, `full`: **ALL PASS**;
- `catch` now also writes two EICAR files with odd names on iso5-cli2, one with a non-UTF-8 byte and one with a line
  break: **both caught**, and monitor check 73 stays OK. The first build crashed on exactly this
  (`UnicodeEncodeError`), which is how the lab showed the stale packages;
- weekly scan: 111,944 files, 65 s, 1 match (the test file), 0 errors.

The quiet day and the gates (regression 33/33, row 36, CUI scan) were not repeated: the fixes touch only the scan
code's error and file-name handling, not identity, authentication or the hardened settings those gates cover.
