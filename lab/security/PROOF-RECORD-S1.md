# Proof record: Plan S1 (Suricata), signed repo 0.9.0 (2026-11-05)

Lab: iso5 golden (ISO 0.4.0: FIPS, SELinux enforcing, fapolicyd, USBGuard, Wazuh 4.14.9 and YARA on). srv = iso5-srv
(manager), cli2 = iso5-cli2 (agent); cli1 stays on 0.4.0 with no Suricata (no lab-adapter sudo) as the mixed-version
case. Script: `lab/security/prove-s1.sh`. Repo 0.9.0 = 24 packages, `REPO OK` (YubiKey `2DE0D71B…3C908F8E`).

## Two packaging faults found by the proof (fixed before the final signing)

1. **EPEL key missing on the hosts.** dnf refused suricata, hiredis and hyperscan ("Public key … is not installed").
   Fix (`c4f1adc`, chp-site 0.11.0-2): chp-site ships the pinned `RPM-GPG-KEY-EPEL-9`; `security enable` checks the
   Wazuh and EPEL fingerprints, then imports both, before dnf.
2. **Upgrade pulled suricata before the key could be imported.** chp-security 0.3.0-1 required suricata, so
   `dnf upgrade` failed its GPG check as a whole. Fix (`878fb97`, chp-security 0.3.0-2): no Requires on suricata or
   chp-suricata-rules; `security enable` installs them after the key import. Checked from an unsigned copy of the
   stage before re-signing: upgrade = chp-site + chp-security only; after the key import, suricata and its three
   libraries install with gpgcheck on.

The repo was signed three times; only the third (final) one exists.

## Results (final packages: chp-site 0.11.0-2, chp-security 0.3.0-2, chp-suricata-rules 2026.11.04-1, suricata 7.0.17-1)

| Stage | Result |
|---|---|
| `repo` (srv, cli2) | upgraded to chp-site 0.11.0-2, chp-security 0.3.0-2; no EPEL package in the upgrade |
| `enable srv`, `enable cli2` | RC=0; "Wazuh and EPEL 9 signing keys verified and imported"; "Suricata watches enp1s0 (HOME_NET [192.168.100.0/24]); logs kept 90 days"; suricata started on both |
| `on` | **ALL PASS** (36 checks): installed versions; active and enabled; one `-c /etc/suricata/chp-suricata.yaml` (drop-in); `suricata -T` passes; the config's interface holds the host address; **52,859 rules loaded, 0 failed**; eve.json `suricata 640`; logrotate file ours (`rotate 90`) and `logrotate -d` clean; 0 AVCs, 0 fapolicyd denials, 0 "No such tag"; agent keys unchanged; monitor 74 OK; server: rules XML present, 0 Wazuh errors, eve.json read, both agents Active |
| `hook` | ALL PASS |
| `catch` | **ALL PASS**: srv served the S1 test body (SID 2017025, priority 1) on a temporary port; cli2 fetched it; eve alert on **both** hosts; **two rule-100510 alerts at level 12** (srv 10:09:53, cli2 10:09:54); hook lines "Suricata (high): ET ATTACK_RESPONSE Net User Command Response" from both; test port closed after |
| `res` | srv RSS 532 MB, 19 s CPU in 10.5 min, 13,246 packets, 0 drops; cli2 RSS 495 MB, 20 s CPU, 9,707 packets, 0 drops; monitor 74 OK |

Script fixes during the run (lab only): the "rules loaded" check reads `suricata.log` after `suricata -T -v` (the
config logs to the file only, at notice); the catch clean-up uses `pkill -f '[h]ttp.server …'` (the plain pattern
matched its own shell, so the port was left open once; closed by hand, re-run clean).

Test alerts to exclude from the quiet day: 10:09:53–10:09:55 and 10:11:26–10:11:27 (two catch runs; the second was
held back from the hook by the forwarder's 15-minute grouping, as designed).

## Quiet day

- T0 **2026-11-05 10:12 MST**, end ≥ 2026-11-06 10:12. Lab untouched (no reset). Lab hook had 8 " rule " lines at T0.
- Results: _pending_ (every Suricata alert by SID/severity on both hosts, expected no severity 1; first daily AIDE
  check, all changes explained; RSS/CPU at 24 h).
