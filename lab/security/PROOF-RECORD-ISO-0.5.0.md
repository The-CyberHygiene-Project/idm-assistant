# Proof record: ISO 0.5.0 (Suricata at install) on the iso5 lab

ISO **0.5.0-rc2** = the Rocky 9.8 DVD boot chain + signed repo **0.9.2** (`check-iso.sh`: ISO OK; sha256
`32b6d4b61b8c7a48084401c855a23b9a62361a7fa9e39716f50c2b958c3aba21`). Repo 0.9.2 = 0.9.0 (0.4.0-update1) plus
`chp-templates` 1.3.1 (Rev 2 content 1.2.3) and `chp-site` 0.11.0-4. With `SECURITY_ADDONS=yes`, first boot's `security
enable` installs Wazuh, YARA and Suricata; no installer change was needed. All three hosts were installed from nothing
(2026-11-07), replacing the 0.4.0 lab VMs and golden snapshots.

## rc1 found one product bug (fixed in rc2)

On rc1 (repo 0.9.1), the YARA weekly full scan matched `/usr/share/chp-suricata-rules/chp-suricata.rules`
(`Base64_encoded_Executable`, `Cobaltbaltstrike_Payload_Encoded`, `SUSP_shellpop_Bash`, `TA17_293A_malware_1`): ET Open's
rules quote the attack bytes YARA looks for. On every host with both add-ons, that is a level-12 false alarm every
Sunday, including sites on **0.4.0-update1**, whose 24-hour quiet day did not include a weekly scan. Fix: `chp-site`
0.11.0-4, the weekly scan skips that folder, as it already skips YARA's own rules (signed package, AIDE-watched).
Proved on cli2 before signing (112,080 files, 0 matches). `prove-y1.sh full` now requires the test file to be the only
match. **Owner ruling (option B):** no separate 0.4.0-update2; the kit guide states the known issue for 0.4.0-update1
sites (dismiss, or upgrade `chp-site` from the 0.5.0 repo tarball).

## Results on rc2

| Gate / proof | Result |
|---|---|
| prep, server, firstboot, export, client1, client2, wazuh-on | ALL PASS (agents Active, keys shredded, AIDE baseline includes Wazuh). On rc1 the first `wazuh-on` saw 1/2 agents Active: cli2's agent was still connecting (re-run passed); rc2's chain waits 180 s first. |
| **Gate 3:** CUI scan | 108 pass / 2 fail on every host (the two accepted AIDE rules); Gate 3 met |
| adapter | ALL PASS |
| `prove-y1.sh fresh`, `hook`, `catch` | ALL PASS |
| `prove-y1.sh full` (weekly scan, iso5-cli2) | 112,067 files, 64 s, **1 match (the test file only)**, 0 errors |
| `prove-s1.sh fresh`: Suricata up at first boot (security step marker, then all 36 `on` checks: right interface, 52,859 rules / 0 failed, eve.json, logrotate, 0 AVCs, 0 fapolicyd, monitor 74, both agents Active) | ALL PASS |
| `prove-s1.sh catch` (SID 2017025 → level 12 on both hosts → hook), `reboot` (cold boot of both hosts), `res` | ALL PASS; RSS srv 494 MB, cli2 509 MB; 0 drops |
| nvram, snapspike, fixtures (FIXTURES OK), golden | ALL PASS |
| **Gate 2:** regression (`lab/iso5/regression-2026-11-07.md`) | **33/33**, with Wazuh, YARA and Suricata running |
| **Gate 2:** row 36 | 3/3 |

Lab-check fixes made on rc1 (no product change): the first-boot check reads the step markers (`security.done`,
`client-security.done`), as the journal keeps only the current boot; `logrotate -d` on a fresh host reports a missing
state file (logrotate has not run yet), which the check now ignores.

The upgrade path and the 24-hour quiet day for the Suricata packages are in `PROOF-RECORD-S1.md` (0.4.0-update1).
