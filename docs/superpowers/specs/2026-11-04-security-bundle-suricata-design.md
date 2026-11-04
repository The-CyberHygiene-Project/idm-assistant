# Security bundle part 3: Suricata network intrusion detection (design)

**Status:** design approved in conversation (owner, 2026-11-04); written spec awaiting owner review. **Frame:**
`docs/superpowers/specs/2026-10-27-security-bundle-wazuh-design.md` (the bundle: optional add-on, signed repo, alerts
through the Wazuh manager and `ALERT_HOOK`). Part 2 (YARA): `2026-11-01-security-bundle-yara-design.md`.

## 1. Purpose and scope

Network intrusion detection for the CHP appliance (NIST SP 800-171 3.14.6, 3.14.7, 3.13.1), approximating RS#2 (diwai),
which runs Suricata with the Emerging Threats Open rules. It is part of the same optional add-on: a host with
`SECURITY_ADDONS=yes` gets Suricata as well as Wazuh and YARA. With `SECURITY_ADDONS=no` nothing changes.

**Success:** a harmless test request that ET Open is known to flag, made from a client, raises a Suricata alert that
reaches `ALERT_HOOK` within a minute; a normal day brings no high-severity false alarms; memory and CPU stay within the
measured limits; FIPS, SELinux, fapolicyd, AIDE and the CUI scan stay as clean as in 0.4.0.

### Decisions settled during design (owner, 2026-11-04)

| Topic | Decision |
|---|---|
| Placement | **Every host watches its own traffic** (B). Not the server alone (A: would miss a client talking to a malicious site); not a switch mirror port (C: needs a managed switch and a second NIC; a later option) |
| Rules | **ET Open only.** Extended rule sets (e.g. Snort Community) may be considered later |
| Mode | **Detection only (IDS).** Nothing is blocked or dropped; alerts only |
| Integration | **Wazuh's built-in Suricata support:** each agent reads `eve.json`; CHP rules map severity to alert level. No CHP forwarder |
| Rule updates | Monthly, as a signed `chp-suricata-rules` package (with the YARA rules); the appliance never downloads rules |

## 2. Packages

- **`suricata`** 7.0.x from EPEL 9 (7.0.17 at writing; Rocky has none), signed by the pinned EPEL key, unmodified. Its
  EPEL-only dependencies, if any, come the same way. The first spike (§7) checks FIPS, SELinux and fapolicyd.
- **`chp-suricata-rules`** (new, noarch, built offline):
  - ET Open for Suricata 7, from a dated download pinned by sha256 (the same pattern as signature-base for YARA);
  - checked at build time with `suricata -T`, so hosts never load an untested set;
  - rules disabled because they fire on a clean appliance (measured in §7) are listed by SID with the reason
    (`disable.conf`, shipped in the package), as YARA's `exclude.txt`;
  - ships the ET Open licence and an attribution notice;
  - version = the download date, so a monthly update is visibly newer.
- **`chp-security`** gains: the Suricata settings writer, the Wazuh rules, log rotation and a monitor check.

## 3. Placement and settings

Written by `chp-site security enable` on every host:
- capture with `af-packet` on the host's main interface (the one that holds its site address), **IDS mode** (no
  `copy-mode`, no NFQUEUE, no drop actions);
- `HOME_NET` = the site's network from `site.conf` (the server's address and prefix), `EXTERNAL_NET` = `!$HOME_NET`;
- outputs: `eve.json` with **alert events only** (no flow, DNS, HTTP or file logs; no packet capture); `stats` to
  Suricata's own log only;
- the rule file from `chp-suricata-rules`; `disable.conf` already applied at build time;
- no listening ports, no unix-socket control beyond the default, no rule-update timer on the host.

## 4. Alerts

- Each Wazuh agent (and the server's own) reads `/var/log/suricata/eve.json` (`log_format json`). Wazuh's stock Suricata
  decoders and rules (group `ids,suricata`) decode it.
- CHP rules (child rules on the stock Suricata alert rule) set the level from `alert.severity`:
  - severity **1** → **level 12** (to `ALERT_HOOK` at once through the existing forwarder);
  - severity **2** → level **7** (daily summary);
  - severity **3** → level **3** (recorded only).
- The forwarder's 15-minute grouping already stops one noisy signature from flooding the hook.
- `chp-site alerts` shows Suricata alerts like any other rule.

## 5. Health, logs and safety

- **Monitor check:** alerts if Suricata is not running, or if it runs but `eve.json` (or its stats) has not been updated
  for a set time; alerts if the capture reports heavy packet drops.
- **Log rotation:** daily, keeping the same retention as Wazuh's alert logs (`RETENTION_DAYS`), so Suricata cannot fill a
  disk.
- SELinux enforcing (Suricata's own policy where EPEL provides one; otherwise recorded, as with Wazuh); fapolicyd trusts
  only signed packages; no new listening ports; no internet.
- The rule files are root-owned and read-only; AIDE watches them, so only a signed update changes them without an alert.
- **Risks and answers:**
  - EPEL's Suricata may use cryptography outside the FIPS module (e.g. for file hashing or TLS parsing) → the spike
    checks; any gap becomes a POA&M item, like Wazuh's;
  - memory and CPU on small clients → measured; limits (memcaps, threads) set from the measurements;
  - false alarms → measured over a clean day, tuned in `disable.conf` before release.

## 6. Upgrade path

Re-running `chp-site security enable` on a host enabled under 0.3.0/0.4.0 adds Suricata (packages, settings, Wazuh
rules, rotation, monitor) without touching the agent keys, as part 2 did for YARA.

## 7. Testing and proof

- **Spike (first task, on the iso5 lab):** EPEL Suricata installs and runs under FIPS, SELinux and fapolicyd; which
  crypto it links; how many ET Open rules load (`suricata -T`); memory and CPU at idle and under the regression load on
  the server and a client; which rules fire on a clean appliance.
- **Automated tests (written first):** the generated settings (interface, `HOME_NET`, IDS only, alert-only eve); the
  severity-to-level rules; the rules package's `disable.conf`, attribution and version; the monitor check; with
  `SECURITY_ADDONS=no`, nothing installed or changed; re-running `enable` keeps the agent keys.
- **Lab proofs:**
  1. **Catch:** the standard harmless test: a client fetches a page from a small web server inside the lab whose body
     is `uid=0(root) gid=0(root) groups=0(root)`, which ET Open's rule 2100498 ("GPL ATTACK_RESPONSE id check returned
     root") flags. If that rule's severity is not 1, the proof checks its mapped level instead and a severity-1 test is
     chosen in the spike. Expected: a Suricata alert on the client, at the right level on the server, and at the hook
     for severity 1.
  2. **Quiet day:** 24 h of normal running: no high-severity false alarms; the daily summary is reasonable.
  3. **Resources:** memory and CPU within the measured limits; no heavy packet drops.
  4. **Gates:** fresh install, regression 33/33 (+ row 36), CUI scan unchanged at 108/2.

## 8. Releases

- **0.4.0-update1:** Suricata for existing 0.4.0 hosts through `chp-site security enable`.
- **ISO 0.5.0:** Suricata at install time with `SECURITY_ADDONS=yes`.
- **Monthly rules updates:** `chp-suricata-rules` with `chp-yara-rules`, as signed update folders (`RULES-UPDATE.md`
  gains the Suricata steps).
- **Records:** the release notes list the AIDE changes to expect; SSP text for 3.14.6, 3.14.7 and 3.13.1 goes into
  chp-templates; any FIPS finding becomes a POA&M item.

## 9. Out of scope

- Blocking or dropping traffic (IPS mode), and any automatic response.
- A switch mirror port or a dedicated sensor (option C; later).
- Extended rule sets beyond ET Open; rule downloads on the appliance.
- Full traffic logging (flows, DNS, HTTP, files) and packet capture.
- Metrics (part 4).
