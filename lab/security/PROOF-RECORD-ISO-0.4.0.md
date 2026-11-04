# Proof record: ISO 0.4.0 (YARA at install) on the iso5 lab

ISO **0.4.0-rc1** = the Rocky 9.8 DVD boot chain + signed repo **0.8.0** (the 0.3.0-update1 packages; `check-iso.sh`: ISO OK;
sha256 `8ca0b90ab9185cf1f37ab4a02d069a3c410e5bc558a11553fc320de64f4bd52d`). No code change from 0.3.0-update1: with
`SECURITY_ADDONS=yes`, first boot's `security enable` installs Wazuh, YARA and its rules and starts both scan timers.
All three hosts were installed from nothing (2026-11-04), replacing the 0.3.0 lab VMs and golden snapshots.

| Gate / proof | Result |
|---|---|
| prep, server, firstboot, export, client1, client2, wazuh-on | ALL PASS (agents Active, keys shredded, AIDE baseline includes Wazuh) |
| `prove-y1.sh fresh`: YARA up at first boot (packages, both timers, log, FIM off, 5-minute scan ran, server rules, no active response) | ALL PASS |
| `hook`, `catch` (EICAR incl. a non-UTF-8 name and a line-break name; server and client; alerts to the hook; files untouched) | ALL PASS |
| `full` (weekly scan on iso5-cli2) | 111,931 files, 67 s, 1 match (the test file), 0 errors |
| **Gate 3:** CUI scan | 108 pass / 2 fail on every host (the two accepted AIDE rules); Gate 3 met |
| adapter, nvram, snapspike, fixtures (FIXTURES OK), golden | ALL PASS |
| **Gate 2:** regression (`lab/iso5/regression-2026-11-04.md`) | **33/33**, with Wazuh and YARA running |
| **Gate 2:** row 36 | 3/3 |

The upgrade path and the 24-hour quiet day for the same packages are in `PROOF-RECORD-Y1.md` (0.3.0-update1).
