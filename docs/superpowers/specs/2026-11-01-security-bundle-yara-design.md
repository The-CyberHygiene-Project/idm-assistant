# Security bundle part 2: YARA malware scanning (design)

**Status:** design approved in conversation (owner, 2026-11-01); written spec awaiting owner review. **Frame:**
`docs/superpowers/specs/2026-10-27-security-bundle-wazuh-design.md` (the bundle's spec: optional add-on, signed repo,
alerts through the Wazuh manager and `ALERT_HOOK`). This spec covers part 2 only.

## 1. Purpose and scope

Malicious-code scanning for the CHP appliance (NIST SP 800-171 3.14.2, 3.14.4, 3.14.5), modelled on RS#2 (diwai),
which runs YARA from Wazuh file events plus a weekly full scan. ClamAV is not an option: it cannot load signatures
under FIPS (RS#2 decommissioned it, 2026-06-12).

It is part of the same optional add-on: a host with `SECURITY_ADDONS=yes` gets YARA as well as Wazuh, on every host
(server and clients). With `SECURITY_ADDONS=no` nothing changes.

**Success:** a test sample (the harmless EICAR string) written to a watched folder on a client raises an alert at
`ALERT_HOOK` within minutes and the file stays where it is; the weekly scan runs and reports; FIPS, SELinux,
fapolicyd, AIDE and the CUI scan stay as clean as in 0.3.0.

### Decisions settled during design (owner, 2026-11-01)

| Topic | Decision |
|---|---|
| On a match | **Alert only.** Nothing is moved, deleted or quarantined; a person decides (the frame spec's "repairs stay human-approved") |
| Rules | **The same source as RS#2: Neo23x0 signature-base** (RS#2 uses it alone, with no rules of its own; confirmed by the RS#2 session, 2026-11-01). Licence: Detection Rule License 1.1, which allows redistribution with attribution |
| Rule updates | **Monthly**, as a small signed update containing only the rules package. The appliance never downloads rules |
| Trigger | **Approach 1 (RS#2's design):** Wazuh real-time file monitoring on a few risky folders starts one scan-only response. Approaches not taken: a CHP watcher service (2), scheduled scans only (3) |
| Packages | `yara` from EPEL (already a source of the signed repo); a new `chp-yara-rules`; `chp-security` gains the scan pieces |

## 2. Packages

- **`yara`** (EPEL 9), signed by EPEL's pinned key, unmodified. The first spike (§7) proves it under FIPS.
- **`chp-yara-rules`** (new, noarch, built offline):
  - signature-base pinned to one upstream commit, recorded in the package;
  - compiled once at build time with `yarac` into a single rules file, so hosts never compile;
  - rules that need inputs only signature-base's own scanners supply (external variables such as `filename` or
    `filepath`), or that fail to compile, are left out. Every rule left out is listed, with the reason, in a skip list
    shipped in the package;
  - rules excluded for false alarms on the appliance (measured in §7) are listed the same way;
  - ships the upstream licence and an attribution notice;
  - version = the upstream commit date, so a monthly update is visibly newer.
- **`chp-security`** gains: the scan script, the weekly timer, the Wazuh settings and alert rules, and a monitor check.

## 3. How a scan is triggered

- **Real-time folders** (Wazuh file monitoring, "realtime", these folders only): `/home`, `/root`, `/tmp`, `/var/tmp`,
  `/dev/shm`, and `/srv` and `/data` where they exist. Wazuh's data folder (bind-mounted at `/var/ossec`) is never
  watched or scanned. AIDE still covers system files; the frame spec's "syscheck off" becomes "syscheck on for these
  folders only".
- **Response:** on a file added or changed (rules 554 and 550), Wazuh runs one local, scan-only command:
  `chp-yara-scan`. Every other automatic response stays off.
- **Weekly full scan:** a systemd timer at a quiet hour runs the same script over every local file system, skipping
  `/proc`, `/sys`, `/dev`, `/run`, Wazuh's data folder, `/var/lib/chp/repo` and files over a size limit.

## 4. The scan script (`chp-yara-scan`)

- **One file (from Wazuh):**
  - refuses anything that is not a regular file inside a watched folder (so it cannot be pointed at the whole disk);
  - scans with the compiled rules, with a time limit per file;
  - repeated changes to the same file within a minute give one scan, not many.
- **Full scan (from the timer):** walks the full-scan list with the same per-file rules.
- **Output:** one line per result to a log Wazuh reads: `match` (rule names, file, hash), `clean` (full scan only, as
  counts) or `error`; the full scan adds a summary line (files, matches, errors, duration).
- **Never** changes, moves or deletes a scanned file. Runs at low CPU and disk priority.

## 5. Alerts

- New Wazuh rules decode the script's lines:
  - a **match** is **level 12**: above the default `SECURITY_ALERT_LEVEL` (10), so it reaches `ALERT_HOOK` at once
    through the existing forwarder;
  - a **scan error** is **level 7**: in the daily summary;
  - the weekly summary is level 3 (recorded, not forwarded).
- The appliance monitor alerts when the weekly scan has not completed in 8 days.
- `chp-site alerts` shows YARA matches like any other rule.

## 6. Safety and supply chain

- SELinux enforcing; fapolicyd trusts only the signed packages; no new network access; no internet.
- The compiled rules file is root-owned and read-only. AIDE watches it, so only a signed update changes it without an
  alert.
- `yara` is EPEL-signed with the pinned key; `chp-yara-rules` and `chp-security` are CHP-signed.
- **Risks and answers:**
  - EPEL's YARA might not work under FIPS → the spike finds out first; any crypto outside the validated module becomes
    a POA&M item, like Wazuh's;
  - signature-base might flag the appliance's own files → measured on a clean lab, excluded by name with the reason;
  - the full scan might take too long → measured, then the limits are set.

## 7. Testing and proof

- **Spike (first task, on the iso5 lab):**
  - EPEL `yara` installs and runs under FIPS, fapolicyd and SELinux;
  - how many signature-base rules compile with plain `yara`, and why the rest fail;
  - full-scan time and false alarms on a clean server and client.
- **Automated tests (written first):**
  - the script's path checks and refusals, its result lines and its rate limit;
  - the Wazuh rule levels;
  - the rules package's skip list, attribution and version;
  - with `SECURITY_ADDONS=no`, nothing is installed or changed.
- **Lab proofs:**
  1. **Catch:** EICAR in `/home` and `/tmp` on a client → an alert at the hook within a few minutes; the file unmoved.
  2. **Weekly scan:** started by hand; its summary checked; a test file caught.
  3. **Quiet day:** no false alarms; AIDE quiet apart from the update's expected changes.
  4. **Gates:** fresh install, regression 33/33 (+ row 36), CUI scan unchanged at 108/2.

## 8. Releases

- **`0.3.0-update1`:** YARA for existing 0.3.0 hosts through `chp-site security enable`; it also carries the folded
  `chp-identity-server` 0.1.2-2 login fix (PR #38).
- **ISO 0.4.0:** YARA at install time with `SECURITY_ADDONS=yes`.
- **Monthly rules updates:** `chp-yara-rules` only, as a signed update folder, with the upstream commit and the skip
  list in its notes.
- **Records:** the release notes list the AIDE changes to expect. SSP text for 3.14.2, 3.14.4 and 3.14.5 goes into
  chp-templates. Any FIPS finding becomes a POA&M item.

## 9. Out of scope

- Quarantine or deletion of matches (owner: alert only).
- Online lookups (RS#2's VirusTotal integration) and any rule download on the appliance.
- Rules of our own.
- Suricata and metrics (parts 3 and 4).

## 10. Amendment (owner, 2026-11-02): clients scan new files every 5 minutes

Lab finding (Plan Y1 Task 6): the Wazuh manager runs the scan-only active response for its OWN file events, but never
sends it to a remote agent (tested: rule IDs, a level threshold, locations `local` and `all`, no white list, agent key
IP `any`, Wazuh 4.14.9 and 4.14.7; `agent_control -b` by hand does reach the agent). RS#2 cannot settle it: it has no
separate client systems. Owner decision: **approach 3 for clients, approach 1 kept on the server.**

- **Server:** unchanged: Wazuh real-time file events on the watched folders start `chp-yara-scan`.
- **Clients:** a systemd timer (`chp-yara-recent.timer`, every 5 minutes) runs `chp-site yara-scan --recent`, which scans
  regular files in the watched folders whose content or metadata changed since the previous run (first run: the last
  5 minutes), with the same path rules, size limit and JSON lines. Wazuh's file monitoring and active response stay
  off on clients (as in 0.3.0); the agent still forwards `/var/log/chp-yara.json` to the manager.
- **Cost:** a new file on a client may wait up to 5 minutes before it is scanned. Success criterion §1 becomes "within
  10 minutes" for clients.

### 10.1 Amendment 2 (owner, 2026-11-02): the 5-minute scan on every host

On a freshly enabled server the scan-only active response did not run for the server's own file events either (alert
554 fired, no scan; it had run once during testing). Owner decision: **every host, server included, uses
`chp-yara-recent.timer`**. Wazuh file monitoring and active response stay off everywhere (as in 0.3.0), and the
active-response wrapper is not shipped. A new file anywhere may wait up to 5 minutes before it is scanned; the weekly
full scan, the JSON lines and the alerts are unchanged.
