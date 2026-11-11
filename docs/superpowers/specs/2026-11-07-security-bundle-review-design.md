# Security bundle part 4: the ISSO's daily security review (design)

**Status:** design approved in conversation and written spec approved (owner, 2026-11-07). **Frame:**
`docs/superpowers/specs/2026-10-27-security-bundle-wazuh-design.md` (the bundle: optional add-on, signed repo, alerts
through the Wazuh manager and `ALERT_HOOK`). Parts 2 and 3: `2026-11-01-security-bundle-yara-design.md`,
`2026-11-04-security-bundle-suricata-design.md`. This part was planned on 10/27 as "metrics (Prometheus +
node-exporter)"; the conversation reshaped it (§1.1).

## 1. Purpose and scope

Give the **ISSO a daily, signed-off review** of the appliance's security, and the **administrator timely alerts**
when the appliance's own security machinery needs attention (NIST SP 800-171 3.3.1, 3.3.3, 3.3.5, 3.14.6, 3.14.7,
3.12.1, 3.12.3). It is part of the same optional add-on: a host with `SECURITY_ADDONS=yes` gets it; with `no`,
nothing changes.

The owner's priorities, in order:

1. **Possible intrusions and their source:** which addresses probed or attacked which host, how often, and what was
   caught. Built from what Wazuh, Suricata and YARA already detect.
2. **The system's security status:** expiring certificates and keys, agents connected, scans actually running, the
   integrity check current, and the like.
3. **Resource use:** CPU, memory, disk and network, kept as history.

**Success:** each morning the server holds a report of the previous day that a reasonable ISSO can review in a few
minutes; the ISSO records a sign-off that an assessor can later verify, with the report it covered; a status problem
(for example a certificate whose renewal has stopped) reaches `ALERT_HOOK` without anyone reading the report; a dead
feeder makes its section say STALE rather than look clean; FIPS, SELinux, fapolicyd, AIDE and the CUI scan stay as
clean as in 0.5.0.

**Anti-goals (a failure even if it technically works):**

- a report that looks clean while one of its sources has stopped (diwai lesson: its digest went stale for 11 days
  while its monitor showed all green);
- a sign-off record that someone could quietly edit or delete;
- a new always-on network service or listening port on any host;
- figures typed or copied by hand (diwai lesson: a card still said SSP v2.13 when the document was v2.18).

### 1.1 Decisions settled during design (owner, 2026-11-07)

| Topic | Decision |
|---|---|
| Who uses it | **Both:** the ISSO reviews daily; the administrator gets alerts |
| Split | **This part collects, alerts and writes a daily report file.** The ISSO's web page (a LAN portal behind a login, like diwai's) is a **later, separate project** that reads what this part produces |
| Resource history | **sysstat (`sar`)** from Rocky. **No Prometheus or node-exporter** ("a luxury") |
| Sign-off | The ISSO **records a sign-off an assessor can see** |
| Missed sign-off | **Alert the administrator after 2 days** without a sign-off |
| Retention | Sign-off **ledger kept forever**; daily **reports kept one year** |
| Intrusion source | **Address, and inside or outside the site `SUBNET`**, for now. No ownership or country lookups |
| Status coverage | **Every host**, not just the server |
| Ledger protection | **Detect, don't prevent:** the ledger's head is recorded on the site stick at each export, and `review verify` checks it |

## 2. Packages

- **`sysstat`** from the Rocky 9.8 AppStream (Rocky key, already pinned), unmodified. It runs no network listener. It
  is added to `PACKAGES.txt` (source `rocky`) and installed by `chp-site security enable` with the rest.
- **`chp-security`** gains the review's units and monitor checks. **`chp-site`** gains the report builder, the
  `review` commands and the status checks. No new vendor key, no third-party repository.

## 3. Collection

- **Resource history:** sysstat's own collection on every host with the add-on, at its default 10-minute interval,
  kept locally for at least the 28 days sysstat keeps by default (the builder may lengthen it).
- **Getting each host's figures to the server:** **the builder's call, after a spike**, within these limits: no new
  listening port and no new inbound firewall rule on any host; reuse a channel the appliance already has (the Wazuh
  agent, for example a command or log entry the manager already receives, or the existing collector path); nothing
  the server runs on a client may change the client. A host whose figures have not arrived counts as STALE.
- **Intrusions** come from what the Wazuh manager already stores (alerts and their archives), so the clients send
  nothing new for priority 1.
- **Security status covers every host (owner, 2026-11-07).** The clients' own status (scan freshness, AIDE state,
  installed repo version, certificates they rely on) does not reach the server today: Wazuh's inventory modules are
  off on purpose, and the monitor logs only failures. So the same channel that brings each host's sysstat figures also
  carries a short, generated status record from that host. The spike must prove it carries both. A host whose
  figures or status have not arrived is STALE in every section it feeds.

## 4. The daily review report

- **When:** built every night, shortly after midnight local time (a systemd timer on the server, catching up after
  downtime), covering the previous calendar day. A failed or missing build is itself an alert (§6).
- **Frozen once built** *(my call)*: a report is never rebuilt. Data that arrives late (a client offline at midnight)
  does not change yesterday's report; that section stays STALE for the day, and the day can still be signed with a
  note.
- **Where:** `/var/lib/chp/review/<YYYY-MM-DD>/`, root-only (0700 folder, 0600 files): the report in Markdown and
  HTML, plus the machine-readable data it was built from. Reports older than **one year** are removed by the same
  timer; the ledger (§5) is never removed.
- **Sections**, in the owner's priority order. Every figure is generated from the records:
  1. **Intrusions:** every Suricata and YARA alert, and Wazuh alerts at level 7 and above, grouped by **source
     address**, each marked **inside** or **outside** the site `SUBNET` (and named when it is one of the site's own
     hosts), with the target host, the signature or rule, the count, and first and last seen. Highest severity first.
     Wazuh's routine events below level 7 appear only as counts per host. A YARA match has no network origin: its
     source is the host the file was found on. A day with none says so. *(Level floor and YARA source: my call.)*
  2. **Security status:** one line per item, each **OK**, **ATTENTION** or **STALE**, with the figure behind it (§7).
  3. **Resources:** per host, the day's average and peak CPU, memory, disk use and network, with a short trend
     against the previous days.
- **Freshness is part of the report:** every section names its sources and how recent each one is; a source that has
  stopped makes its section **STALE**, never empty-and-clean.
- **Reading it:** `chp-site review` prints the latest report (or a given date) at the server console;
  `chp-site review export` copies a dated set (reports, data, the ledger and its check result) to the site stick for
  reading at a desk, through the pinned-stick path the appliance already uses for `chp-site docs`.
- **Contents are sensitive:** the report names addresses and hosts but holds no secrets (no keys, passwords or tokens).
  It is handled like the site's other security records.

## 5. Sign-off

- **Command:** `chp-site review sign --approver "Name" [--date YYYY-MM-DD] --notes "…"` on the server, as root. It
  shows the report's summary and asks for confirmation, then records the sign-off. Several days may be signed at once
  (after a weekend, for example), each as its own entry.
- **Who may sign:** the ISSO (`ISSO_NAME`) plus anyone listed in a new, optional site key `REVIEW_DELEGATES` (names
  separated by commas; may be empty). It is separate from `BASELINE_DELEGATES` and `UNEXPIRE_DELEGATES`, as those are
  from each other. *(Builder's note: this key is my call; the owner asked only for an assessor-visible sign-off.)*
- **The ledger:** `/var/lib/chp/review/ledger.jsonl`, append-only, **hash-chained** (each entry carries the SHA-256 of
  the previous entry), kept **forever**. Each entry records: the date reviewed, the report's SHA-256, the approver, the
  operator who ran the command, the time, and the notes. The sign-off also goes to the audit record, like
  `aide-accept`.
- **Anchored off the server (owner, 2026-11-07):** the chain alone cannot stop root on the server rewriting the whole
  ledger and the kept reports so they agree, or dropping the latest entries. So the protection is **detection**: each
  `chp-site review export` writes the ledger's current head (the newest entry's hash and count) to the **site stick**,
  which the ISSO keeps, appending to the stick's own record of heads. Nothing extra is needed at sign-off time.
- **Checking it:** `chp-site review verify` re-walks the chain, re-hashes every report still kept, and, when the stick
  is present, checks that every head recorded on the stick is still in the server's chain at the same position. It
  says which entry, report or head no longer matches. An assessor can run it, or read the exported copy and its check
  result.
- **AIDE** must not raise an alert every day for the ledger growing, but must catch an earlier entry being changed; the
  builder chooses how (for example, treating it as a growing log, plus the chain check in a monitor check).

## 6. Alerts to the administrator

Through the existing paths (monitor checks and the Wazuh-to-`ALERT_HOOK` forwarder), never a new channel. *(My call:)*
the **existing monitor checks stay the source of immediate alerts** for what they already watch (for example the
Kanidm certificate's 4-hour warning, AIDE staleness at 26 hours, the weekly YARA scan at 8 days, monitor 74); the
report shows their state but adds **no second alert for the same fault**, and the §7 thresholds apply only where no
check exists today. New items alert **once a day, when the report is built**, except a long-lived certificate or key
within 7 days of expiry, which a new monitor check alerts at once. Alerts are raised for:

- a status item turns **ATTENTION** (§7 says which are immediate);
- **no sign-off for 2 days** (weekends count, so a Friday review alerts on Sunday; the owner may change this);
- a report build failed, or no report exists for yesterday;
- a feeder or host is **STALE**;
- the ledger's chain check fails.

Repeats are grouped as the forwarder already groups them, so a standing problem does not alert every few minutes.

## 7. Status items and thresholds

*(The thresholds are my calls; the owner may change them.)*

- **Certificates.** The appliance mixes very short and very long lifetimes: the Kanidm TLS certificate lasts **24
  hours** and is renewed by `cert-renew-kanidm.timer` every 15 minutes; the step-ca root and intermediate last 10
  years. So the rule depends on the lifetime:
  - lifetime under 90 days (renewed automatically): **ATTENTION** when less than half its lifetime is left (renewal
    has stopped), **immediate alert** when less than a quarter is left; the renewal timer's last result is shown too
    *(changed 2026-11-11, ISO 0.6.0: 30 %, below the Kanidm renewal point, which is 8 h of 24 h; at half, a healthy
    certificate showed ATTENTION about 4 h of every 16 h)*;
  - lifetime of 90 days or more: **ATTENTION** at 30 days left, **immediate alert** at 7 days.
  The builder finds every certificate the appliance relies on (Kanidm, step-ca, the trust anchor, any others) rather
  than a fixed list.
- **Pinned signing keys** (the project key, Wazuh's, EPEL's, Rocky's): **ATTENTION** within 90 days of expiry, the
  same rule as `check-key-expiry.sh`.
- **Wazuh agents:** connected or not, by the existing monitor's rule.
- **Scans:** YARA (5-minute and weekly), Suricata (statistics and drops, as monitor 74), and the AIDE daily check
  (current and accepted): **STALE** when older than twice their schedule.
- **Updates:** the installed signed-repo version on each host, and any host that differs from the server.

## 8. Health and safety

- No network listener, port or firewall change on any host (§3).
- Root-only files; no secrets in reports, data or ledger.
- Hashes use SHA-256 from the system's FIPS-validated library.
- New units run under SELinux enforcing and fapolicyd with no new denials; anything that needs a policy change is
  recorded, as for Wazuh and Suricata.
- AIDE: the review folder's daily new files are expected; the builder lists them in the update notes, as for Suricata.
- Resource cost is measured and recorded (sysstat is small; the report build must stay short).

## 9. Releases and upgrade path

- First a package update, **0.5.0-update1**: unpack the signed repo, `dnf --refresh … upgrade`, then re-run
  `chp-site security enable` (server first), as for parts 2 and 3. Then **ISO 0.6.0** for new installs.
- **Also in 0.5.0-update1** (owner, deferred from part 3): the alert forwarder groups YARA matches per YARA rule (as
  it now does per Suricata signature), so a second, different malware match on a host within 15 minutes is not held
  back.
- **Kit and documents:** the site-stick guide gains a section; `REVIEW_DELEGATES` is added to the kit's template and the
  site.conf↔profile.ini mapping as an additive key (Automated_Compliance reads the kit: flag it in the PR); the SSP
  narratives for the audit-review requirements may follow in chp-templates.

## 10. Testing and proof

- **Spike first:** sysstat under FIPS, SELinux and fapolicyd; the transport choice of §3, carrying both the sysstat
  figures and each host's status record; the report build time.
- **Proofs on the lab** (as for parts 2 and 3: upgrade path, then fresh install):
  - the report shows the Suricata catch test under the client's address, marked inside the subnet, and a YARA test
    file under the host it was found on;
  - every status item reads OK on a healthy lab, and a deliberately stopped renewal timer, a stopped scan, and a host
    whose figures stop arriving each show ATTENTION or STALE and alert the administrator;
  - sign-off: a signed day verifies; editing an earlier ledger entry, or a kept report, makes `review verify` fail and
    the monitor alert; after an export, rewriting the whole ledger, or removing its newest entries, fails `review
    verify` against the stick; an unlisted name cannot sign; no sign-off for 2 days alerts (tested with a shifted clock, as
    the monitor tests do);
  - the one-year report removal keeps the ledger intact;
  - a quiet day: no false ATTENTION; the AIDE changes all explained; resources recorded;
  - the gates: regression, row 36, the CUI scan.

## 11. Out of scope

- **The web portal** and its login (a later project, reading this part's output).
- Ownership or country lookups for outside addresses (no online lookups; an offline database could come later).
- Prometheus, node-exporter, Grafana.
- Changes to what Wazuh, Suricata or YARA detect.
