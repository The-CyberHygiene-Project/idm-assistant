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

## Proof 4: quiet day (pending)

T0 = 2026-11-02 10:09 MST. No resets until it is read.
