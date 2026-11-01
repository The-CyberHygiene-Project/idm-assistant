# Design: the CHP security bundle, part 1 (Wazuh)

**Status:** sections 1–5 approved by the owner (2026-10-27); this written spec awaits the owner's review.
**Releases:** `0.2.0-update4` (a package update for existing 0.2.0 sites) and ISO `0.3.0` (new installs).

## 1. Purpose and scope

The ISO is built step by step. This step adds the **security bundle**: an optional add-on that approximates the
reference stack of the RS#2 system, with log monitoring and intrusion detection, malware scanning, network intrusion
detection and health metrics. One spec covers the whole bundle's frame (how it is enabled, packaged, signed, updated
and alerted on). One plan and release follows for each tool, in this order:

1. **Wazuh** (this spec's detail): manager on the server, agents on the clients. It is the hub the others report into.
2. **YARA** malware scanning, triggered by Wazuh file events plus a weekly full scan (RS#2's proven design; ClamAV
   does not work under FIPS).
3. **Suricata** network intrusion detection, feeding Wazuh.
4. **Prometheus + node-exporter** health metrics.

Parts 2–4 get their own specs. The owner notes that dc1 had many anti-malware dead ends; RS#2 is the model, not dc1.

### Decisions settled during design (owner, 2026-10-27)

| Topic | Decision |
|---|---|
| Order | Wazuh first, then YARA, Suricata, metrics; one release per tool |
| Packaging | **Approach A:** Wazuh's own signed RPMs in the CHP signed repo with Wazuh's key pinned, plus a CHP package `chp-security` that configures them. Not rebuilt from source (B); no containers (C) |
| Alerts | **Manager only + `ALERT_HOOK`**, plus `chp-site alerts`. No indexer or dashboard in this release |
| FIPS | Wazuh's bundled crypto is outside the validated module; it is recorded as a **POA&M item**, like Kanidm's |
| Data location | A dedicated directory, bind-mounted at `/var/ossec`: `/data/wazuh` where `/data` exists, otherwise `/srv/wazuh` on the root volume. `/var` is not resized |
| Recommended server | x86-64, 32 GB RAM minimum (64 GB preferred), 2 TB+ SSD; 1 TB or smaller is not recommended |

## 2. Evidence: the FIPS lab test (2026-10-27)

Wazuh 4.14.9 (RPMs signed RSA/SHA-256 by key `0DCFCA5547B19D2A6099506096B3EE5F29111145`, which **expires
05/15/2027**) was tested on the iso5 golden hosts: FIPS mode, SELinux enforcing, fapolicyd and USBGuard active.

- The manager and the agent install and run. The agent enrolled (1515) and connected (1514). There were no fapolicyd
  denials and no Wazuh SELinux denials. Every Wazuh daemon runs as `unconfined_service_t`.
- **Crypto:** OpenSSL 3.5.1 is statically linked into `/var/ossec/lib/libwazuhext.so`, and the API's embedded Python
  carries its own 3.5.1. Rocky's validated FIPS provider (3.5.5) is not used. The transport algorithms are approved
  (TLS 1.3, AES-256-GCM).
- **Unsafe defaults:** enrolment without a password; agents registered with IP "any"; the API on `0.0.0.0:55000`.
- **Vulnerability detection** unpacks an offline feed of about 19 GB on first start. On the appliance that is inside
  the fixed 20 GB `/var`, which it fills. With room (a bind-mounted directory), the database unpacked and the client's
  full package inventory (1,225 packages) reached the server. Even so, **no vulnerability alerts were produced in
  15 minutes**; the scanner only reported "Failed to sync agent: No available server". In 4.14 it needs the indexer.
- Resources: the manager uses about 580 MB RSS (plus its data), each agent about 70 MB.

## 3. Enabling and installing

- **Packages** (signed repo): `wazuh-manager` and `wazuh-agent` (Wazuh-signed, key pinned in `trusted-keys.txt`), and
  `chp-security` (CHP-signed: the configuration, the alert forwarder, the monitor checks, local rules).
- **Site setting:** a new optional `site.conf` key, `SECURITY_ADDONS=yes|no` (default `no`). It is additive: existing
  sticks and Automated_Compliance are unaffected. A second optional key, `SECURITY_ALERT_LEVEL` (default 10), is
  described in §5.
- **New installs (ISO 0.3.0):** with the setting on, first boot installs `wazuh-manager` + `chp-security` on the
  server and `wazuh-agent` + `chp-security` on each client. With it off, the package set is identical to 0.2.0.
- **Existing 0.2.0 sites:** `0.2.0-update4`, then `chp-site security enable` on each host (server first). No reinstall.
- **Data directory:** before Wazuh is installed, `chp-security` creates the data directory and a bind mount at
  `/var/ossec` (an `fstab` entry). It uses `/data/wazuh` if a `/data` volume exists, otherwise `/srv/wazuh`.

## 4. Enrolment and the server's settings

- **Pre-made agent keys; no enrolment service.** At first boot (or `security enable`), the server creates one agent key
  per client from its hosts table, tied to the client's name and fixed IP. Each key travels to its client in the
  existing **client token**. Wazuh's enrolment service (1515) is **off**. Adding a client after the server install has
  the same limit as today (requirements row 48).

| Part | Setting |
|---|---|
| Agent traffic, 1514/tcp | on; the server's firewall allows only the site's host IPs; clients only connect out |
| Enrolment, 1515 | **off** |
| API, 55000 | **off** (confirmed workable in Plan W1; if Wazuh needs it, it listens on `127.0.0.1` only) |
| Log collection | on: the systemd journal, `/var/log/audit/audit.log` and `/var/log/secure` on every host |
| Rootcheck | on |
| File integrity (syscheck) | **off**; AIDE does this. It returns narrowly in part 2 (YARA) |
| Policy checks (SCA) | off; the OpenSCAP CUI scan covers this |
| Vulnerability detection | **off** (needs the indexer; see §2) |
| Active response | **off**: alerts only. Repairs stay human-approved |
| Remote agent upgrade (WPK) | **off**: agents update only from the signed repo |
| Shared configuration push (`agent.conf`) | **off**: each host's settings come from `chp-security` on that host |
| Remote commands | off (Wazuh's default) |
| Cluster | off |
| Alert retention | the site's audit-retention decision (default 90 days) |

## 5. How alerts reach the site

- Wazuh writes every alert from every host to `/var/ossec/logs/alerts/alerts.json` on the server.
- **`chp-wazuh-alerts`** (a systemd service in `chp-security`) follows that file:
  - **level ≥ `SECURITY_ALERT_LEVEL`** (default 10): one line to the system log and to `ALERT_HOOK`, in the monitor's
    style (host, rule id, level, description). **Repeats are grouped:** the same rule on the same host within 15
    minutes gives one alert, with a count;
  - **levels 7–9:** kept, with one daily summary line ("23 medium alerts on 3 hosts; run `chp-site alerts`").
- **`chp-site alerts [--since 24h|7d] [--level N]`**: a read-only, root-only summary by host and rule.
- **Monitor checks** (`/usr/lib/chp/monitor.d`) alert if the manager stops, if a client's agent has been disconnected
  for more than 10 minutes, or if the Wazuh data directory passes 80% of its file system.
- **Retention:** alert logs rotate daily, compressed, and are deleted after the retention period.
- **AIDE** watches `/var/ossec/etc`, not Wazuh's queues and logs.
- **Privacy:** alerts contain user names and addresses and stay on the server. The site decides what its hook sends.
- The alerts are JSON already, so the later Local AI engine can read them without a new format.

## 6. Safety and supply chain

- **POA&M item (FIPS):** "Wazuh uses its own bundled OpenSSL 3.5.1, outside the FIPS-validated module; the algorithms
  are approved." Compensating controls: internal network only, the firewall allows only site hosts, and enrolment and
  the API are off. Each new Wazuh version is checked for a FIPS-capable build, which would close the item.
- **SELinux:** Wazuh runs unconfined, recorded like Kanidm's identity client. A confining policy is possible later work.
- **fapolicyd:** no change (RPM-installed files are trusted; the test saw no denials).
- **Signing and keys:** Wazuh's key is pinned in `trusted-keys.txt`, and `verify-repo.sh` accepts Wazuh's packages
  only under it. AIDE's "explained by signed package updates" treats them like any signed package.
- **Key expiry check:** the release scripts refuse a release if any pinned key has expired or expires within 90 days.
  Wazuh's key expires 05/15/2027.
- **Updates:** new Wazuh versions arrive only as a signed CHP update, after a lab proof. Sites never pull from Wazuh.
- **Size:** about 590 MB is added to the ISO.
- **Licence:** Wazuh is GPLv2; it is added to `NOTICE.txt`'s component list.
- **Documents:** after the proof, the chp-templates Rev 2 narratives that Wazuh now evidences change from "this version
  does not…" to partial or appliance status (for example 3.3.1, 3.3.5, 3.14.6, 3.14.7), and the POA&M item is seeded.

## 7. Testing and proof

**Repo tests:**
- The settings generator pins every row of §4 (each "off" is asserted).
- The forwarder: the level threshold, 15-minute grouping, the daily summary.
- `chp-site alerts` and `chp-site security enable` (including the bind mount and the `/data` or `/srv` choice).
- The key-expiry release check.

**Lab proofs (iso5 golden hosts):**
1. **Upgrade:** a 0.2.0 site applies update4 and `security enable`; every agent connects; no Wazuh SELinux denials and
   no fapolicyd denials; only 1514 is open, and only to site hosts; the data directory is bind-mounted.
2. **Catch:** a burst of failed SSH logins (level 10) reaches the hook once, grouped; adding a local user appears in
   the daily summary; stopping a client's agent raises a monitor alert within 10 minutes.
3. **Quiet check:** 24 hours of normal running with the hook on; level-10+ alerts close to zero. Noisy rules are tuned
   in a CHP local-rules file, and each tuning is recorded.
4. **Fresh ISO 0.3.0 installs** with the add-on on (everything in place from first boot) and off (the 0.2.0 package
   set).
5. **CUI scan:** no new failing rules against 0.2.0, with a deviation table that includes the FIPS POA&M item.
6. **Resources:** the manager's memory and disk use are recorded against the recommended hardware.

## 8. Plans

- **Plan W1:** `chp-security`, the `chp-site` commands, the forwarder, the monitor checks, the key-expiry check and the
  tests; proofs 1–3; release `0.2.0-update4`.
- **Plan W2:** ISO `0.3.0` (the first-boot step, the site-stick settings, agent keys in the client token); proofs 4–6;
  release.

## 9. Out of scope

- YARA, Suricata and metrics (parts 2–4 of the bundle).
- The Wazuh indexer and dashboard; with them, vulnerability detection (§2). The recommended RAM makes this realistic
  later.
- Adding a client after the server install (requirements row 48).
- Aligning the installer's disk layout with the documented 2 TB partition scheme (requirements row 50).
