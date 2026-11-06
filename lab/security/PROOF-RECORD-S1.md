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
- Read 2026-11-06 10:35 MST (24 h 23 min). Results:

| | iso5-srv | iso5-cli2 |
|---|---|---|
| Suricata alerts outside the two test windows | **0** | **0** |
| Packets / kernel drops | 123,861 / 0 | 97,725 / 0 |
| RSS at 24 h (at enable + 10 min) | 532 MB (532 MB): flat | 495 MB (495 MB): flat |
| CPU over 24.6 h | 9 min 39 s (0.65 %) | 13 min 53 s (0.94 %) |
| Monitor 74 | OK | OK |

- **No severity-1 alert, no new SID:** `disable.conf` stays empty; no rebuild.
- **AIDE, first daily check after the update** (03:50 srv, 04:06 cli2; added / removed / changed): iso5-srv
  **190 / 0 / 50**, iso5-cli2 **186 / 0 / 45**. Every entry is explained:
  - **added by the update (packages):** suricata (`/usr/sbin/suricata*`, `suricata-update`, `/usr/lib/suricata` 64,
    `/usr/share/suricata` 24, `/etc/suricata/rules` 23, `/etc/suricata/{suricata.yaml,classification.config,
    reference.config,threshold.config}`, its unit, `tmpfiles.d/suricata.conf`, docs, man pages, licences, build-ids),
    `libhtp`, hiredis, hyperscan, libnetfilter_queue libraries, chp-suricata-rules (8), monitor `74-suricata.sh`,
    `RPM-GPG-KEY-EPEL-9` (chp-site 0.11.0-2);
  - **added by `security enable`:** `/etc/suricata/chp-suricata.yaml`, `/etc/systemd/system/suricata.service.d/chp.conf`,
    the `multi-user.target.wants/suricata.service` link, `/etc/sysconfig/suricata`, `/etc/logrotate.d/suricata`
    (EPEL's, rewritten), and on the server `/var/ossec/etc/rules/chp_suricata_rules.xml`;
  - **changed by the update:** the upgraded chp-site / chp-security files (monitor 70–73, the chp units and drop-ins,
    `wazuh-retention`, licences, `/usr/bin/chp-site`, `/usr/share/chp-site`), the two pinned keys chp-site reinstalls,
    `/etc/passwd|group|shadow|gshadow` (+ backups) for the new `suricata` user, `/etc/ld.so.cache` (new libraries),
    `/var/log` (new `/var/log/suricata`);
  - **changed by `security enable`:** `/var/ossec/etc/ossec.conf` (eve.json localfile), `/etc/chp/security.conf`, and
    on the server `chp_yara_rules.xml` (rewritten, same text);
  - **lab only (not on a real site):** `/etc/sudoers.d/99-lab-adapter`, `/root/chp-scan/*`, `/root/s1-*`,
    `/root/y1-eicar-sums` (cli2), and on the server `/usr/local/sbin/lab-hook`, `/etc/chp/site.conf` (ALERT_HOOK),
    `/var/lib/ssh-ca/keys/lab0{1,2,6}.pub` (`fixtures.py`).
- For the update notes (Task 8): the files **`security enable`** adds or changes are the ones to list as "expected
  after enable".

## Gates on the upgraded lab (Task 6, 2026-11-06)

New golden snapshots taken on the upgraded hosts (0.4.0 + repo 0.9.0, Suricata on): `nvram` and `golden` ALL PASS
(engine findings `[]` on both). The `adapter` stage was not run: it is for a fresh install (its precondition, a CUI scan
newer than the install stamp, does not apply), and what it sets up was already in place from the 0.4.0 lab build (the
sudo rule is in golden; the lab's pin and secret files on the Mac date from 11/04).

| Gate | Result |
|---|---|
| 1. Regression (`lab/iso5/regression-2026-11-06.md`, commit `4254a4c`) | **33/33** (11 scenarios × 3 runs, all GREEN) |
| 2. Row 36 (desktop login: password + authenticator code) | **3/3** |
| 3. CUI scan | **108 pass / 2 fail on every host** (srv, cli1, cli2), the same two accepted AIDE rules; `deviations.py`: **Gate 3 met** |
