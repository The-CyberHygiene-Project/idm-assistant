# Spike: sysstat under FIPS, and the host-record transport (Plan R1 Task 1, 2026-11-07)

Lab: iso5-srv and iso5-cli2 at the 0.5.0 golden snapshots (FIPS, SELinux enforcing, fapolicyd, USBGuard, Wazuh,
YARA and Suricata on). Reverted to golden afterwards.

## sysstat

- Rocky 9.8 DVD AppStream: `sysstat-12.5.4-11.el9` (sha256 `87877f4bd7ce4a19e9832305ab7fbf0cd7b88954d25c35040fe132aee3f16256`), Rocky key, `rpm -K` OK.
- **It needs three more Rocky AppStream library packages** that the hosts do not have: `pcp-libs-6.3.7-8.el9_8`,
  `pcp-conf-6.3.7-8.el9_8`, `lm_sensors-libs-3.6.0-10.el9` (Rocky key, libraries only: no daemon, no unit, no listener).
  `avahi-libs`, `libuv` and `cyrus-sasl-lib` are already installed. All four must go in `PACKAGES.txt` (source `rocky`)
  and into aero `/data/lab-inputs/rpms`.
- Installed on both hosts: **no new listener** (`ss -ltnup` identical before and after), 0 AVCs, 0 fapolicyd denials.
  SELinux: `/usr/lib64/sa/sadc` is `sysstat_exec_t` (Rocky's own policy: confined).
- Units: `sysstat.service` (enabled by preset), `sysstat-collect.timer` (`OnCalendar=*:00/10`, disabled by preset: enable
  it), `sysstat-summary.timer` (disabled by preset: enable it). `/etc/sysconfig/sysstat`: `HISTORY=28`,
  `COMPRESSAFTER=31`, `SADC_OPTIONS=" -S DISK"`. Data: `/var/log/sa/saDD` (root 0644).
- `sadf -j` field names: taken from a real day in Task 4 (fixture), after a full day of collection.
- AIDE footprint (`/var/log/sa`, `/var/log/chp-review.json`): checked in the Task 11 quiet day.

## Transport

- **Candidate A as planned (`full_command` localfile) fails:** the agent runs the command (as root, every 60 s in the
  test), but Wazuh delivers its output as `ossec: output: '<alias>':\n<json>`, which matches Wazuh's own rule 530
  (level 0, never stored), not a JSON rule. `wazuh-logtest`: the bare JSON line matches CHP rule 100520; the prefixed
  output matches 530.
- **Chosen: a JSON log file read by the agent** (the pattern already used for `/var/log/chp-yara.json` and Suricata's
  `eve.json`). A timer on each host appends one record line to **`/var/log/chp-review.json`**; the agent (and the
  manager, for its own host) reads it with `<localfile><log_format>json</log_format><location>/var/log/chp-review.json</location></localfile>`;
  manager rule **100520, level 3** (`decoded_as json`, field `chp_review.host`). No new listener, port or firewall
  change.
- Measured: records from cli2 and from the manager itself (agent `000`) are stored within seconds; a 6,000-character
  string field arrives intact; level 3 is not forwarded to `ALERT_HOOK` and not in `chp-site alerts`.
- **The manager stores only level ≥ 3** (`log_alert_level` 3), so 100520 is level 3, not 2.
- **Wazuh rewrites a JSON record's top-level scalars:** numbers become strings (`"time": "1794077454.73"`), `true` →
  `"true"`, `null` → `"null"`, and an empty object (`"sys": {}`) is dropped; values inside lists keep their types. So the
  record carries its payload as **one JSON-encoded string**: `{"chp_review": {"v": 1, "host": "<name>", "body": "<JSON
  text of the full record>"}}`, and the report parses `body`. Size: the full record must stay well under 64 KB (Wazuh's
  line limit); a 6 KB string was proven.
