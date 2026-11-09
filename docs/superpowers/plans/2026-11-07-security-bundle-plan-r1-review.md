# Security bundle Plan R1 (the ISSO's daily security review, 0.5.0-update1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every night the server writes a frozen review of the previous day (intrusions by source, every host's security status, resource use). The ISSO signs it into a hash-chained ledger anchored on the site stick. The administrator is alerted through the existing monitor and `ALERT_HOOK` paths. Released as package update 0.5.0-update1.

**Architecture:**
- **Per host:** every host with the add-on runs sysstat. Every 10 minutes it emits one generated status record (`chp-site review host-record`) that reaches the Wazuh manager over a channel chosen in Task 1.
- **Server, nightly:** a timer runs `chp-site review build`. It reads the manager's alerts and the host records and writes `/var/lib/chp/review/<date>/` (Markdown, HTML, data JSON).
- **Server, sign-off and alerts:** `review sign` appends to `ledger.jsonl`, and `review export` copies a dated set and the ledger head to the stick. Monitor check 75 raises the new alerts.

**Tech Stack:** Python 3.9 standard library (`chp-site`), bash monitor checks, systemd timers, Wazuh 4.14 localfile and rules, sysstat (Rocky AppStream).

**Spec:** `docs/superpowers/specs/2026-11-07-security-bundle-review-design.md` (owner-approved 2026-11-07). Patterns to copy: parts 2/3 (`yara_scan.py`, `suricata_conf.py`, `security.py`, monitor 73/74, `prove-y1.sh`, `prove-s1.sh`); `aide.py` `pin`/`verify_pin` (stick records); `ops.approved_by`; `audit.record`.

## Global Constraints

- **Optional add-on only:** `SECURITY_ADDONS=yes` hosts get it; with `no`, nothing changes.
- **No new network listener, port or firewall change on any host** (spec §3, §8).
- **Packages:** `sysstat` from the Rocky 9.8 AppStream (Rocky key, already pinned), source `rocky` in `PACKAGES.txt`. No Prometheus, node-exporter or Grafana; no new vendor key.
- **Report:**
  - folder `/var/lib/chp/review/<YYYY-MM-DD>/`, 0700, files 0600, root-only;
  - **frozen once built, never rebuilt**;
  - covers the previous **local** calendar day, built shortly after midnight, catching up after downtime;
  - kept **365 days**.
- **Ledger:** `/var/lib/chp/review/ledger.jsonl`, append-only, each entry carries the SHA-256 of the previous entry, kept **forever**. Entry fields: `date`, `report_sha256`, `approver`, `operator`, `time`, `notes`, `prev`.
- **Who signs:** `ISSO_NAME` plus the new optional site key `REVIEW_DELEGATES` (comma-separated; may be empty), via `ops.approved_by(site, approver, "REVIEW_DELEGATES")`.
- **Stick anchor:** each `review export` appends the ledger head (`count`, the newest entry's hash, the time) to `review/heads.txt` on the site stick. `review verify` checks every recorded head is still in the chain at the same position.
- **Intrusions:**
  - every Suricata and YARA alert, plus Wazuh alerts at **level 7 and above**, grouped by source address, each marked inside or outside the site `SUBNET` and named when it's a site host;
  - Wazuh events below level 7 appear as counts per host;
  - a YARA match's source is the host it was found on.
- **Status states:** `OK`, `ATTENTION`, `STALE`. Certificates:
  - lifetime under 90 days: `ATTENTION` below ½ of the lifetime left, immediate alert below ¼;
  - lifetime of 90 days or more: `ATTENTION` at ≤ 30 days left, immediate alert at ≤ 7 days.
- **Other status thresholds:** pinned keys `ATTENTION` within 90 days of expiry; scans and feeders `STALE` when older than **2×** their schedule; a host with no record for the day is `STALE` in every section it feeds.
- **Alerts:**
  - existing monitor checks stay the source of immediate alerts for what they already watch;
  - new items alert **once per day, when the report is built**;
  - a long-lived certificate or key within **7 days** of expiry alerts at once;
  - **no sign-off for 2 days** alerts, and weekends count.
- **Hashes:** SHA-256 (`hashlib`, the system's FIPS-validated library).
- **No secrets** in records, reports, data or ledger.
- **Also in this release:** the forwarder groups YARA alerts per YARA rule (`data.chp_yara.rules`), as it does per Suricata signature.
- **Additive kit change:** `REVIEW_DELEGATES` goes into `site.conf.template` and the site.conf↔profile.ini mapping. Automated_Compliance reads the kit, so flag it in the PR.
- **Lab rule:** before any signing, dry-run the upgrade from an unsigned copy of the stage on a lab host. When adding packages, force a full YARA scan in the proofs.

## Review Focus

1. **The first day after enable, or a day with no data at all:** there are no previous days for a trend and no records. The report builds and says "no data" per section (STALE where a feeder should have reported), never crashes or reads as clean. Owned by Task 5 (`test_first_day_has_no_trend_and_is_stale_not_clean`).
2. **Day boundaries in local time:** alerts carry offsets like `-0700`, and a DST day is 23 or 25 hours long. An alert belongs to the local calendar day of its timestamp, so none is counted twice or lost. Owned by Task 5 (`test_alerts_are_assigned_by_local_day_across_dst`).
3. **A host in the hosts table that never reports** (mixed versions: cli1 left on 0.5.0, or a host that's down): that host is STALE, and the others are unaffected. Owned by Task 5 (`test_silent_host_is_stale_others_ok`).
4. **A damaged ledger** (the last line half-written after a power loss, or a missing file after the first sign): `verify` names the damage; `sign` refuses to append onto a broken chain and says how to recover, rather than silently starting a new chain. Owned by Task 7 (`test_sign_refuses_a_broken_chain`, `test_verify_reports_a_truncated_last_line`).
5. **`review verify` with no stick present, or a stick without `review/heads.txt`:** the chain and reports are still checked, and the output says plainly that the stick anchor was not checked. Never a pass that implies it was. Owned by Task 8 (`test_verify_without_stick_says_anchor_not_checked`).

---

### Task 1: Spike: sysstat under FIPS, and the transport for host records

**Files:** Create `lab/security/SPIKE-REVIEW.md` (facts and the decision). Scratch scripts stay in the repo under `lab/security/spike-review/` (the Mac's /private/tmp is wiped on reboot).

- [ ] **Step 1:** On iso5-srv and iso5-cli2 (lab at golden), install `sysstat` from the DVD AppStream. Record:
  - its timers (`sysstat-collect.timer`, `sysstat-summary.timer`) and the `/var/log/sa` retention default;
  - `sadf -j` output for one day;
  - no listener (`ss -ltnup` before/after);
  - 0 AVCs, 0 fapolicyd denials, its SELinux domain;
  - its AIDE footprint after one daily check.
- [ ] **Step 2: Transport candidate A (try first).** A Wazuh agent `<localfile><log_format>full_command</log_format><command>/usr/bin/chp-site review host-record</command><frequency>600</frequency>` emitting one JSON line, and on the manager a CHP rule (id `100520`, level 2, `decoded_as json`, field `chp_review.host`) so it is stored in `alerts.json`. The manager reads its own the same way. Measure:
  - arrival time on the manager;
  - the line size limit, with a 4–8 KB record;
  - whether the command runs as root;
  - 0 new denials;
  - that the manager's own record arrives.
- [ ] **Step 3: Candidate B (only if A fails a measurement):** the existing `idm-collect` collector path. Record why A failed.
- [ ] **Step 4:** Write `SPIKE-REVIEW.md`: the facts, **the chosen transport**, the record size limit, the `sadf` fields to use. Revert the lab to golden (`bash lab/iso5/reset.sh`).
- [ ] **Step 5: Commit** `lab/security/SPIKE-REVIEW.md lab/security/spike-review/`: "R1 spike: sysstat under FIPS, host-record transport".

**Stop rule:** if no candidate meets the no-new-listener rule, stop and report to the owner.

---

### Task 2: Status thresholds (pure rules)

**Files:** Create `appliance/chp-site/chp_site/review_rules.py`; test `tests/test_chp_site_review_rules.py`.

**Interfaces:**
- Produces:
  - `OK, ATTENTION, STALE = "OK", "ATTENTION", "STALE"`;
  - `cert_state(not_before: float, not_after: float, now: float) -> tuple[str, bool, str]` returns `(state, immediate, detail)`;
  - `key_state(expires: float | None, now: float) -> tuple[str, str]`, where `None` means never expires;
  - `fresh_state(last: float | None, schedule_s: int, now: float) -> tuple[str, str]`;
  - `worst(states: list[str]) -> str`, with order `STALE > ATTENTION > OK`.

- [ ] **Step 1: Write the failing tests**

```python
from chp_site import review_rules as r
H, D = 3600, 86400

def test_short_lived_cert_attention_below_half_and_immediate_below_quarter():
    nb = 0; na = 24 * H                                          # Kanidm: 24 h
    assert r.cert_state(nb, na, 1 * H)[:2] == ("OK", False)
    assert r.cert_state(nb, na, 13 * H)[:2] == ("ATTENTION", False)   # 11 h left < 12 h
    assert r.cert_state(nb, na, 19 * H)[:2] == ("ATTENTION", True)    # 5 h left < 6 h

def test_long_lived_cert_attention_at_30_days_immediate_at_7():
    nb, na = 0, 3650 * D
    assert r.cert_state(nb, na, na - 31 * D)[:2] == ("OK", False)
    assert r.cert_state(nb, na, na - 30 * D)[:2] == ("ATTENTION", False)
    assert r.cert_state(nb, na, na - 7 * D)[:2] == ("ATTENTION", True)

def test_expired_cert_is_attention_and_immediate():
    assert r.cert_state(0, 10 * D, 11 * D)[:2] == ("ATTENTION", True)

def test_key_state_90_days_and_never():
    assert r.key_state(None, 0)[0] == "OK" and r.key_state(91 * D, 0)[0] == "OK" and r.key_state(90 * D, 0)[0] == "ATTENTION"

def test_fresh_state_stale_after_twice_the_schedule_or_never():
    assert r.fresh_state(0, 300, 600)[0] == "OK" and r.fresh_state(0, 300, 601)[0] == "STALE"
    assert r.fresh_state(None, 300, 0)[0] == "STALE"

def test_worst():
    assert r.worst(["OK", "ATTENTION", "STALE"]) == "STALE" and r.worst([]) == "OK"
```

- [ ] **Step 2:** `.venv/bin/python -m pytest -q tests/test_chp_site_review_rules.py` → FAIL (no module).
- [ ] **Step 3:** Implement the five names in `review_rules.py`. Boundary rule: `≤ 30 days` and `≤ 7 days` count as inside, and `< ½` and `< ¼` are strict. `detail` is plain English, e.g. "11 h left of 24 h".
- [ ] **Step 4:** Tests pass. **Step 5: Commit** "review: status thresholds (spec §7)".

---

### Task 3: The host status record

**Files:** Create `appliance/chp-site/chp_site/review_host.py`; modify `cli.py` (`review host-record`); test `tests/test_chp_site_review_host.py`.

**Interfaces:**
- Consumes: Task 2 (`cert_state`, `fresh_state`). Existing state files: `yara_scan.STATE` (`last-recent`, `last-full`), `/var/log/suricata/stats.log`, the AIDE check's last result (as monitor 60/61 read it), `/etc/chp/security.conf`.
- Produces: `host_record(*, host: str, now: float, run, root: Path = Path("/")) -> dict` → `{"chp_review": {"v": 1, "host": str, "time": float, "versions": {"chp-site": str, "chp-security": str, "repo": str}, "certs": [{"path", "not_before", "not_after"}], "keys": [{"file", "fpr", "expires": float|None}], "scans": {"yara_recent": float|None, "yara_full": float|None, "suricata_stats": float|None, "aide_check": float|None, "aide_ok": bool|None}, "sys": {<Task 4 summary>|None}}}`. `find_certs(root: Path) -> list[Path]` covers the PEM certificates under `etc/pki/kanidm/`, `etc/step-ca/certs/`, and `etc/pki/ca-trust/source/anchors/chp-*.crt` (Task 1 may add more). `pinned_keys(root: Path, run) -> list[dict]` reads each `etc/pki/rpm-gpg/RPM-GPG-KEY-*` with `gpg --show-keys --with-colons` in a private temporary GnuPG home (as `security._key_fpr` does), so no `/root/.gnupg` is created. The CLI prints exactly one JSON line under the Task 1 size limit.

- [ ] **Step 1: Failing tests:**
  - `test_record_has_every_field_and_fits_the_limit`;
  - `test_missing_state_files_are_none_not_errors`;
  - `test_find_certs_reads_not_before_and_not_after`, with two test certificates made by `openssl req -x509` in a `tmp_path` root;
  - `test_pinned_key_expiry_uses_a_private_gnupg_home`;
  - `test_record_holds_no_secrets`: no `BEGIN`, no key material, no `client.keys` content;
  - `test_cli_prints_one_line`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. Read certificate dates with `openssl x509 -noout -startdate -enddate` through `run`. The versions come from `rpm -q --qf`; the repo version comes from the installed repo's `repodata` marker that the release writes (Task 1 names the file).
- [ ] **Step 4:** Pass. **Step 5: Commit** "review: per-host status record (spec §3, every host)".

---

### Task 4: The sysstat daily summary

**Files:** Create `appliance/chp-site/chp_site/review_sys.py`; test `tests/test_chp_site_review_sys.py` with a captured `sadf -j` fixture from Task 1 in `tests/fixtures/review/sadf-day.json`.

**Interfaces:**
- Produces: `day_summary(sadf_json: str) -> dict` → `{"cpu": {"avg": float, "peak": float}, "mem": {"avg_pct": float, "peak_pct": float}, "disk": [{"mount", "used_pct"}], "net": {"rx_kbs_avg", "tx_kbs_avg"}}`, or `{}` when there's no data. `host_record` (Task 3) puts the summary for "today so far" under `sys`.

- [ ] **Step 1: Failing tests:** `test_summary_from_a_real_day` (values from the fixture) and `test_empty_or_bad_input_is_empty_dict`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** Pass. **Step 5: Commit** "review: sysstat daily summary".

---

### Task 5: The report builder

**Files:** Create `appliance/chp-site/chp_site/review_report.py`; test `tests/test_chp_site_review_report.py`.

**Interfaces:**
- Consumes:
  - `wazuh_alerts.load_alerts(base, since_epoch)`;
  - Task 2 rules;
  - the records from Task 3, read back from the alerts as `rule.id == "100520"`;
  - the site dict (`SUBNET`) and `hosts.parse_hosts`.
- Produces:
  - `day_bounds(day: date, tz) -> tuple[float, float]`, local midnight to midnight;
  - `build(day: date, *, alerts: list[dict], hosts: list[Host], site: dict, now: float, previous: list[dict]) -> dict`, the report data: `{"day", "built", "intrusions": [...], "routine_counts": {host: n}, "status": [{"host", "item", "state", "immediate", "detail", "source_age"}], "resources": {host: summary|None}, "attention": [...]}`;
  - `render_md(data) -> str` and `render_html(data) -> str`. The HTML is self-contained, with no external links and no scripts.

- [ ] **Step 1: Failing tests:**
  - `test_intrusions_grouped_by_source_inside_outside_and_named`, with source `192.0.2.21` (a site host, inside) and `203.0.113.9` (outside);
  - `test_level_floor_7_and_routine_counts`;
  - `test_yara_source_is_the_host_it_was_found_on`;
  - `test_every_host_every_item_has_a_state`;
  - `test_alerts_are_assigned_by_local_day_across_dst` (Review Focus 2: an alert at 23:30 `-0700` on the DST-change day);
  - `test_first_day_has_no_trend_and_is_stale_not_clean` (Review Focus 1);
  - `test_silent_host_is_stale_others_ok` (Review Focus 3);
  - `test_existing_monitor_items_are_shown_not_alerted`: the Kanidm certificate's state is shown, but it appears in `attention` only if no monitor check owns it;
  - `test_html_has_no_external_references`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. A source address comes from `data.src_ip` for Suricata, from `data.srcip` for Wazuh, and is the agent's own address for YARA. "Inside" means within `SUBNET`. The trend compares against the previous days' data files (`previous`).
- [ ] **Step 4:** Pass. **Step 5: Commit** "review: the daily report (intrusions, status, resources; spec §4)".

---

### Task 6: Build, keep and show

**Files:** Create `appliance/chp-site/chp_site/review_store.py`; modify `cli.py` (`review build [--date]`, `review [--date]` show); test `tests/test_chp_site_review_store.py`.

**Interfaces:**
- Consumes: Task 5.
- Produces:
  - `REVIEW_DIR = Path("/var/lib/chp/review")`;
  - `write_day(day, data, md, html, *, root) -> Path`, which raises `SiteError` if the day already exists (frozen);
  - `report_sha256(day_dir) -> str`, over `report.md`;
  - `prune(*, root, today: date, keep_days=365) -> list[str]`, which never touches `ledger.jsonl` or `stick-heads.json`;
  - `missing_days(*, root, today) -> list[date]`, used for catch-up (at most 31 back).

- [ ] **Step 1: Failing tests:**
  - `test_day_is_written_0700_0600_and_frozen`;
  - `test_catch_up_builds_each_missing_day_once`;
  - `test_prune_keeps_365_days_and_the_ledger`;
  - `test_show_prints_latest_or_given_date`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** Pass. **Step 5: Commit** "review: build, keep (365 days), show".

---

### Task 7: The ledger and sign-off

**Files:** Create `appliance/chp-site/chp_site/review_ledger.py`; modify `cli.py` (`review sign --approver --notes [--date …]`) and `sitefile.py` (`REVIEW_DELEGATES`, parsed like `BASELINE_DELEGATES`); test `tests/test_chp_site_review_ledger.py`.

**Interfaces:**
- Consumes: Task 6 (`report_sha256`); `ops.approved_by`; `audit.record`, `audit.operator`.
- Produces:
  - `LEDGER = REVIEW_DIR / "ledger.jsonl"`;
  - `entry_hash(line: str) -> str`;
  - `read(path) -> list[dict]`, which raises `SiteError` naming the line on a broken chain or a partial last line;
  - `append(path, *, date, report_sha256, approver, operator, notes, now) -> dict`, taking an exclusive `fcntl` lock and refusing a broken chain;
  - `head(path) -> tuple[int, str]`;
  - `verify(path, *, root) -> list[str]`, a list of problems that is empty when fine and covers the chain plus a re-hash of each kept report.

- [ ] **Step 1: Failing tests:**
  - `test_entries_chain_and_verify_clean`;
  - `test_editing_an_earlier_entry_fails_verify`;
  - `test_editing_a_kept_report_fails_verify`;
  - `test_sign_refuses_a_broken_chain` (Review Focus 4);
  - `test_verify_reports_a_truncated_last_line` (Review Focus 4);
  - `test_unlisted_name_cannot_sign`;
  - `test_isso_and_review_delegate_can_sign`;
  - `test_several_days_signed_as_separate_entries`;
  - `test_sign_writes_the_audit_record`;
  - `test_review_delegates_parsed_and_optional` (sitefile).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. The CLI shows each day's summary and asks for `yes` before appending.
- [ ] **Step 4:** Pass. **Step 5: Commit** "review: hash-chained sign-off ledger, REVIEW_DELEGATES (spec §5)".

---

### Task 8: Export and the stick anchor

**Files:** Modify `review_ledger.py` (stick heads) and `cli.py` (`review export [--stick]`, `review verify [--stick]`); test `tests/test_chp_site_review_export.py`.

**Interfaces:**
- Consumes: `usbstick.site_stick`; Task 6 and Task 7.
- Produces:
  - `export(stick: Path, *, root, days: list[date] | None) -> dict`, which copies the dated sets, the ledger and its verify result to `review/` on the stick and appends the head line `"<count> <hash> <iso time>"` to `review/heads.txt`;
  - `verify_heads(path, heads_text) -> list[str]`.

- [ ] **Step 1: Failing tests:**
  - `test_export_appends_the_head_and_copies_sets`;
  - `test_rewritten_ledger_fails_against_the_stick`;
  - `test_dropped_newest_entries_fail_against_the_stick`;
  - `test_verify_without_stick_says_anchor_not_checked` (Review Focus 5).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** Pass. **Step 5: Commit** "review: export to the site stick, head anchor and check".

---

### Task 9: Wazuh plumbing, YARA grouping, monitor check 75

**Files:**
- Modify `wazuh.py`: the `review host-record` command localfile on both roles, per Task 1's choice, and `REVIEW_RULES` (rule `100520`).
- Modify `wazuh_alerts.py`: `_signature` also returns `data.chp_yara.rules`.
- Create `appliance/rpm/chp-security/monitor.d/75-review.sh`.
- Tests: `tests/test_chp_site_wazuh.py`, `tests/test_chp_site_wazuh_alerts.py`, `tests/test_chp_security_monitor.py`.

**Interfaces:**
- Consumes: Task 6 (`REVIEW_DIR`), Task 7 (`verify`), and the report's `attention` list.
- Produces: monitor 75 output lines. The env names follow 73/74 (`CHP_SECURITY_CONF`, `CHP_REVIEW_DIR`, `CHP_NOW`).

- [ ] **Step 1: Failing tests:**
  - `test_both_roles_run_the_host_record_once`;
  - `test_review_rule_stores_records`;
  - `test_yara_matches_grouped_per_rule` (two different rules on one host within 15 minutes both reach the hook);
  - monitor 75:
    - `not enabled → OK`;
    - `client role → OK (server only)`;
    - `yesterday's report missing → ALERT`;
    - `no sign-off for 2 days → ALERT` (the 2-day rule, weekends counted);
    - `each attention item alerted once per day` (a marker file under `REVIEW_DIR`);
    - `ledger verify failure → ALERT`;
    - `immediate long-lived cert ≤ 7 days → ALERT now`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. Monitor 75 calls `chp-site review verify --quiet` and reads the latest `data.json`.
- [ ] **Step 4:** Pass. **Step 5: Commit** "review: host-record transport, YARA per-rule grouping, monitor 75".

---

### Task 10: Enable, packages, AIDE, units

**Files:**
- Modify `security.py`. `_enable` adds `sysstat` to the dnf list and enables `sysstat-collect.timer` on every host, plus `chp-review-build.timer` on the server, and writes the review rules on the server.
- Create `appliance/rpm/chp-security/chp-review-build.{service,timer}`: timer `OnCalendar=*-*-* 00:20:00`, `Persistent=true`; service `ExecStart=/usr/bin/chp-site review build`.
- Modify `chp-security.spec` (0.4.0-1), `build-rpm.sh`, `chp-site.spec` and `__init__.py` (0.12.0-1), `appliance/release/PACKAGES.txt` (`sysstat rocky`).
- Modify the AIDE configuration in `appliance/rpm/chp-integrity` per Task 1's footprint: `/var/lib/chp/review` as a growing log, no daily alerts for new day folders, and `/var/log/sa`.
- Modify `appliance/site-stick-kit/site.conf.template` and the mapping CSV (`REVIEW_DELEGATES`).
- Tests: `tests/test_chp_site_security.py`, `tests/test_chp_security_static.py`, `tests/test_chp_site_cli.py`, and the AIDE config test.

- [ ] **Step 1: Failing tests:**
  - the dnf list ends `…, "chp-suricata-rules", "sysstat"`;
  - `sysstat-collect.timer` is on both roles' enable list;
  - `chp-review-build.timer` is on the server only;
  - the units' exact `OnCalendar`/`Persistent`;
  - spec versions;
  - `REVIEW_DELEGATES` in the template;
  - the AIDE rules for the review folder;
  - a re-run keeps `client.keys`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** Full suite passes. **Step 5: Commit** "chp-security 0.4.0 + chp-site 0.12.0: the daily review; enable installs sysstat".

---

### Task 11: Build, sign repo 0.10.0, prove on the lab

**Files:** Create `lab/security/prove-r1.sh` (stages `repo`, `enable H`, `on`, `build`, `sign`, `stale`, `tamper`, `export`, `full`, `res`, `reboot`, the same `X`/`A`/`check`/`done_` helpers as `prove-s1.sh`) and `lab/security/PROOF-RECORD-R1.md`.

- [ ] **Step 1:** Build `chp-site`, `chp-security`. Copy the DVD `sysstat` RPM into aero `/data/lab-inputs/rpms` (sudo; `rpm -K` OK). Run `push.sh`, then `assemble-repo.sh /data/chp-release/0.10.0/stage …`. **Dry-run the upgrade from an unsigned copy on iso5-srv:** only our packages upgrade.
- [ ] **Step 2: Sign** (owner "go", `gpgconf --kill all` first): `sign-session.sh` with `sign-repo.sh … 0.10.0 …` gives `REPO OK`.
- [ ] **Step 3: Proofs** after `reset.sh`: `repo`, `enable srv`, `enable cli2`, then the stages below. Each must give **ALL PASS**:
  - `on`: sysstat timers, records from both hosts on the manager, 0 denials, no new listener;
  - `build`: a report for a seeded day, from the Suricata catch (SID 2017025) and a YARA EICAR, both appearing under the right source, with every status item OK on the healthy lab;
  - `sign`: by the ISSO, `verify` clean;
  - `stale`: stopping `cert-renew-kanidm.timer`, then stopping a scan, then cutting cli2's record each shows ATTENTION or STALE and alerts the hook;
  - `tamper`: editing an earlier entry, then a kept report, each fails `verify` and alerts;
  - `export`: copies to the stick, then a rewritten ledger fails against the stick;
  - `full`: a forced YARA weekly scan with only the test file matching;
  - `reboot`, `res`.
- [ ] **Step 4: Quiet day:** 24 h without resets, including one real nightly build:
  - no false ATTENTION;
  - the AIDE changes all explained;
  - resources recorded;
  - the missed-sign-off alert, tested with `CHP_NOW` shifted 2 days.
- [ ] **Step 5: Gates** (`golden`, regression 33/33, row 36, CUI scan 108/2). **Commit** "R1: repo 0.10.0 proofs, quiet day, gates".

---

### Task 12: Release 0.5.0-update1

- [ ] **Step 1: Failing tests** (`tests/test_release_iso_static.py`):
  - `UPDATE-0.5.0-update1.md.in` contains `@REPO@`, `chp-site security enable`, `chp-site review sign`, `REVIEW_DELEGATES`, `ledger`, `heads.txt`, `--refresh`, `chp-site aide-accept`, `sysstat`;
  - `release-kit.sh` has the `0.5.0-update1/` and `site-stick-kit-0.5.0-update1/` rows, with every earlier row kept;
  - the kit guide has "### From 0.5.0 update 1 on: the daily security review".
- [ ] **Step 2:** Write the notes (what it adds, apply with `--refresh` server first, how the ISSO signs and exports, the AIDE list from Task 11, known limits), the kit guide section, and the README rows.
- [ ] **Step 3: Final whole-branch review** (fresh reviewer, most capable model), then one fix pass. Each fix is test-first, bumps the Release, and is followed by a re-sign and re-proof.
- [ ] **Step 4: Release** (owner "go"): notes on the Desktop; `release-repo.sh` (V=0.5.0-update1, REPO_V=0.10.0, NOTE=UPDATE-0.5.0-update1.md.in); `release-kit.sh` (V=0.5.0-update1); `RELEASE-RECORD-0.10.0.md`.
- [ ] **Step 5: PR.** Run the pre-publication scan, push, open a PR flagging the additive `REVIEW_DELEGATES` kit key for Automated_Compliance. The owner merges. ISO 0.6.0 follows as its own small release, as 0.5.0 did.
