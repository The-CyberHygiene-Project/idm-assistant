# fapolicyd denials: design

Date: 2026-10-03. Status: design approved in conversation by the ISSO; this spec awaits review.
Third of the six gap runbooks. Format: `runbooks/README.md`.

## Goal

When fapolicyd silently blocks a program (it fails with "permission denied", exit 126, and nothing points at
fapolicyd), the operator's form says fapolicyd blocked it, names the program, and says which case it is: a stale trust
list (a signed, installed package fapolicyd was never told about: fixable with approval) or an unpackaged program (the
case fapolicyd exists to stop: the ISSO's decision). fapolicyd switched off or permissive is raised as a control that is
off.

## Decision (ISSO, 2026-10-03) — new requirement row 46, "fapolicyd"

With a person's approval, the engine may refresh fapolicyd's trust from the package database
(`fapolicyd-cli --update`) when a denied program belongs to an installed package signed by a pinned key. It never adds a
program that belongs to no package, or to an unsigned or unknown-key package, to the trust list: that is diagnose only,
for the ISSO. fapolicyd permissive or not running is diagnose only.

## Lab facts (read on client2, 2026-10-03)

- fapolicyd 1.4.3, `permissive = 0`, `integrity = none`, `trust = rpmdb,file`; `/etc/fapolicyd/fapolicyd.trust` empty;
  `rpm-plugin-fapolicyd` installed (rpm/dnf notify fapolicyd; `rpm --noplugins` does not).
- Rule `90-deny-execute.rules`: `deny_audit perm=execute all : all` after `allow perm=execute all : trust=1`.
- A denied run exits 126. The audit record (needs `ausearch --input-logs`; without it ausearch reads stdin over
  ssh/sudo and finds nothing): `type=FANOTIFY ... resp=2 ... obj_trust=0`, then in the same event
  `type=SYSCALL ... syscall=59 success=no ... uid=N auid=N` and `type=PATH ... name="/tmp/chp-probe-y" ...`.
- `fapolicyd-cli -D` lines: `rpmdb /usr/bin/true 27936 <sha256>`. `fapolicyd-cli -u, --update` notifies fapolicyd to
  update its database.
- Imported rpm keys on client2: only the project key. So "known signer" is a **pinned list**, not rpm's keyring:
  Rocky 9 `702d426d350d275d` (seen on the fapolicyd package), EPEL 9 `8a3872bf3228467c`, the project
  `521276f43c908f8e`.

## Part 1: evidence and findings

**Collector** (`collector/idm-collect`, read-only), all hosts:

    "fapolicyd": null | {"active": "active"|..., "permissive": true|false|null,
                         "denials": [{"path": str, "when": ISO, "uid": int|null, "count": int, "exists": bool,
                                      "package": str|null, "signer": "<16-hex key id>"|null, "in_trust": bool|null}]}

- `null` when fapolicyd is not installed. `permissive` from `/etc/fapolicyd/fapolicyd.conf` (`permissive = 1` → true).
- `denials`: FANOTIFY events from `ausearch --input-logs -m FANOTIFY -ts recent` (last 10 minutes) whose SYSCALL is
  `syscall=59` (execve), grouped by PATH `name=`; newest 5 paths. Only paths matching `^/[A-Za-z0-9._/+-]+$` are kept.
- Per path: `exists` (`[ -e ]`), `package` (`rpm -qf --qf '%{NAME}'`, null if unowned), `signer` (the Key ID from the
  owning package's RSAHEADER/DSAHEADER/SIGPGP signature, null if unsigned), `in_trust` (the path appears as field 2 of
  a `fapolicyd-cli -D` line; null if the dump fails).

**Findings** (`engine/findings.py`), only for denials whose `exists` is true and `in_trust` is not true:

- `FAPOLICYD_TRUST_STALE` (component `fapolicyd`): `package` set and `signer` in `PINNED_SIGNERS`. Evidence:
  `"fapolicyd blocked <path> (package <pkg>, signed <key>), <count> time(s) in the last 10 minutes"`.
- `FAPOLICYD_DENIED_UNPACKAGED` (component `fapolicyd`): no package, or the package is unsigned or signed by a key not
  in `PINNED_SIGNERS`. Evidence: `"fapolicyd blocked <path> (no package owns it)"` or `"(package <pkg> is unsigned)"` /
  `"(package <pkg> signed by unknown key <key>)"`.
- `FAPOLICYD_PERMISSIVE` (component `fapolicyd`): `permissive` true, or `active` not `active`. Evidence names which.
- `PINNED_SIGNERS = {"702d426d350d275d": "Rocky Linux 9", "8a3872bf3228467c": "EPEL 9", "521276f43c908f8e": "The CyberHygiene Project"}`.

## Part 2: repair and runbooks

**Repair `fapolicyd-trust-refresh`** (`host_role = "client"`, `verify_absent = {"FAPOLICYD_TRUST_STALE"}`):

- `precheck`: the fresh report shows FAPOLICYD_TRUST_STALE; refuse if FAPOLICYD_PERMISSIVE is present (fapolicyd is not
  enforcing: refresh proves nothing).
- `backup`: none (nothing to restore). `apply`: `fapolicyd-cli --update`, then
  `logger -p authpriv.notice -t idm-assistant '<refresh approved by …, case …>'`.
- `verify`: a fresh report no longer shows FAPOLICYD_TRUST_STALE (the denied path is now `in_trust`).
- `undo`: none.

**Allow-list (code, row 46):** `allowed_for_findings` offers nothing for a host whose findings include
FAPOLICYD_DENIED_UNPACKAGED or FAPOLICYD_PERMISSIVE.

**Runbooks** (`decisions: 46`):

`FAPOLICYD_TRUST_STALE.md`: user_sees "A program from an installed package fails to start with \"permission denied\"."
· means "The service or tool that needs it does not work." · evidence "fapolicyd blocked a program that belongs to an
installed, signed package: its trust list was never told about the package." · repair "Refresh fapolicyd's trust list
from the signed package database." · if_wrong "Little risk: only programs from already-installed packages signed by a
pinned key become trusted." · rollback "Cannot be undone, and does not need to be: it only adds what the signed package
database already lists." · say_no_if "Nobody installed this package on purpose."

`FAPOLICYD_DENIED_UNPACKAGED.md`: user_sees "A program fails to start with \"permission denied\"." · means "Something
not installed through a signed package was run on this machine." · evidence "fapolicyd blocked a program that no
signed package owns." · repair "No automatic repair. Tell the ISSO; if the program is needed, install it from a signed
package instead." · if_wrong "Trusting an unknown program lets it run unchecked." · rollback "Nothing is changed by this
tool." · say_no_if "Always the ISSO's decision."

`FAPOLICYD_PERMISSIVE.md`: user_sees "Nothing visible: programs run normally." · means "The control that stops
untrusted programs is off." · evidence "fapolicyd is in permissive mode or not running." · repair "No automatic
repair. Tell the ISSO, then turn enforcement back on (permissive = 0) and restart fapolicyd." · if_wrong "Leaving it off
lets any program run." · rollback "Nothing is changed by this tool." · say_no_if "It was switched off for a documented,
time-limited reason."

`lab/iso-requirements.md` gains row 46.

## Part 3: scenarios and tests

All on client2 (`HOSTS = ["srv1", "client2"]` not needed: client2 only), lab user lab04 for probes.

- **P1 (`scenarios/p1.py`), stale trust:** fetch
  `http://192.168.100.1:8080/chp/0.5.4/google-authenticator-1.09-5.el9.x86_64.rpm` on client2, `rpm -i --noplugins`
  it, run `/usr/bin/google-authenticator --help` (denied). Expect `{"client2": {"FAPOLICYD_TRUST_STALE"}}`;
  `REPAIRS = [("client2", "fapolicyd-trust-refresh")]`; final probe: the program runs (exit ≠ 126).
- **P2 (`scenarios/p2.py`), unpackaged:** `cp /usr/bin/true /usr/local/bin/chp-helper`, run it (denied). Expect
  `{"client2": {"FAPOLICYD_DENIED_UNPACKAGED"}}`; `REPAIRS = []` (model must decline); `restore` removes the file;
  final check clears because a removed path is not reported.
- **P3 (`scenarios/p3.py`), permissive:** `permissive = 1` in fapolicyd.conf, restart fapolicyd. Expect
  `{"client2": {"FAPOLICYD_PERMISSIVE"}}`; `REPAIRS = []`; `restore` sets `permissive = 0` and restarts.
- Regression: P1–P3 3/3; full 11/11; D1, D2, F1, F2 1/1 (collector changed again).

**Unit tests:** collector block with stubbed `ausearch`, `rpm`, `fapolicyd-cli`, `systemctl` and a conf file
(denial grouping, newest 5, non-execve events ignored, path filter, unowned, unsigned, signer parse, in_trust, missing
dump → null, fapolicyd not installed → null); findings (each, removed path silent, in-trust silent, unknown signer →
unpackaged); repair (refuses permissive, refuses nothing-stale, apply runs exactly `fapolicyd-cli --update` + log);
allow-list (row 46); runbooks complete (24); model injection case (planted instruction in evidence → decline).

**Release:** idm-collect 0.1.0-6 (this change plus the two DNS edge fixes already in source) in signed repo 0.5.5.

## Out of scope

Adding programs to `fapolicyd.trust` (row 46: never by the engine); rule edits; integrity modes; servers' own repair
(the repair is client-only for now; the findings run on all hosts).
