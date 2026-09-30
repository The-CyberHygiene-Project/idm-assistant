# ISO Plan 3b: Site Operations (`onboard`, `revoke`, `unexpire`) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An administrator on the identity server can run three commands:
- **`chp-site onboard USER`** brings a person to a ready-to-log-in state and prints a checklist of what is still up to the user.
- **`chp-site revoke USER`** stops a person's access everywhere within seconds, not minutes.
- **`chp-site unexpire USER`** re-enables an expired account, and only with a named ISSO or delegate's approval and a written reason. Each such decision is recorded in the Linux audit log.

**Architecture:** Five new stdlib modules in `chp-site`:
- **`kanidm.py`** runs the Kanidm CLI under the operator's own existing session (it never touches a password) and parses its `attr: value` output.
- **`audit.py`** records every change to the audit log and the journal, both before and after the change.
- **`sshca.py`** manages the SSH CA's registered keys and certificates on disk.
- **`fanout.py`** clears the kanidm-unixd cache on every client over a pinned, forced-command SSH key.
- **`ops.py`** orchestrates the three commands.

The server's first boot gains a `cache-key` step that creates that SSH key. `client.conf` gains `CACHE_PUBKEY`, so the Plan 4 client role can pin it.

**Tech Stack:** Python 3.9 stdlib (`chp-site`), Kanidm 1.11.2 CLI, OpenSSH (`ssh-keygen -s`, `ssh`), `auditctl -m` + `logger`, bash (first boot), RPM, the lab harness in `lab/iso3`.

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md`:
- §4.4 (operations)
- §2 ISSO **#28** (cache: "`chp-site revoke` invalidates the cache on every client") and **#32** (unexpire: ISSO or a `site.conf` delegate, approver + reason, logged, never automated)
- §4.1 (`ISSO_NAME`, `UNEXPIRE_DELEGATES`)

The lab mechanics reproduced here:
- `engine/repairs.py`: `AccountUnexpire`, `UnixdRefresh`, `KanidmCredResetToken`, `SshUserCertReissue`
- `lab/srv1/sign-user-cert.sh`, `lab/srv1/55-ssh-ca-record.sh`
- runbooks `ACCOUNT_EXPIRED`, `UNIXD_CACHE_STALE`, `POSIX_PW_MISSING`

## Decisions for this plan (user / ISSO, 2026-09-30)

1. **Revoke reaches clients through a pinned cache key.** This is the same pattern as the #22 diag key:
   - Each client (Plan 4) gets a locked `chpcache` account.
   - Its `authorized_keys` line is `from="<server IP>",command="sudo -n /usr/bin/kanidm-unix cache-invalidate",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`, with a sudoers rule for exactly that command.
   - The server makes the key (ECDSA P-384) at first boot, and `client.conf` carries its public half.

   **The lab proof of the fan-out to real clients is in Plan 4**, because clients do not exist yet.
2. **Revoke means:**
   - **`revoke USER`**: expire the account **now**, so every login stops. It is reversible only through `unexpire` with approval (#32).
   - It also moves the user's registered SSH key to `/var/lib/ssh-ca/revoked/`, so no new certificate is signed.
   - **`revoke USER --group G`**: remove one direct group membership.
   - Both then clear the client caches. Accounts are never deleted.

**My design choices (recorded; the spec leaves the mechanism open):**
- **The Kanidm session is the operator's.**
  - `chp-site` runs Kanidm commands as `-D <--as>` (default `idm_admin`), with stdin closed. A missing session fails fast with "run `kanidm login -D NAME` first"; `chp-site` never prompts, reads, stores or passes a password.
  - The escrowed `idm_admin` password stays on the stick. The intended day-to-day path is to onboard a **named** admin once (`onboard alice --group idm_admins`), then use `--as alice`.
- **Secrets stay off the screen.**
  - Reset tokens (link, command and QR code) are written to `/root/chp-onboard/<user>.reset-token.txt` (dir 0700, file 0600); only the path is printed.
  - Issued SSH certificates are public; they go to `/root/chp-onboard/<user>-cert.pub` and the CA's record in `/var/lib/ssh-ca/issued/`.
- **Audit record = `auditctl -m`** (a `type=USER` event in `/var/log/audit/audit.log`, found with `ausearch -m USER`) **plus** `logger -p authpriv.notice -t chp-site` (to `/var/log/secure` and the journal).
  - A record is written **before** the change. If that fails, nothing changes.
  - A second record (`<action>.done`) follows the change.
- **Certificate lifetime at onboarding: `+8h`** (a working day; the lab used `+8h` for set-up and `+1h` for repairs). Re-running `onboard` re-signs the certificate.
- **`onboard` is idempotent** and never re-enables an expired account (that would bypass #32). It refuses and points to `unexpire`.
- **Refusals:** `revoke` and `unexpire` refuse the built-in `admin` / `idm_admin`. `revoke` also refuses the operator's own session account, because locking out administration is never what the operator meant.
- **Approver match:** exact after trimming spaces, ignoring case, against `ISSO_NAME` and each `UNEXPIRE_DELEGATES` entry.
- **The cache key's host keys are trust-on-first-use**, kept in a dedicated `known_hosts` (`/var/lib/chp/cache-key/known_hosts`).
  - What that exposes: an impersonated client learns nothing (public-key auth reveals no secret), and the forced command on real clients is fixed.
  - A changed host key (a reinstalled client) is reported by name with the one-line fix.
- **The `cache-key` step reaches fresh installs only.** A server already past its first boot (none are deployed) would need `systemctl restart chp-server-firstboot`, which runs only the new step.

## Global Constraints

- **All Plan 2 and Plan 3a constraints hold:**
  - secrets never go to a log, the console, `/etc/chp`, argv or the repo
  - Python 3.9 stdlib only in `chp-site` (no `match`, no `X | Y` type syntax)
  - the branding header (`appliance/branding/file-header.txt`) on shipped scripts and modules
  - `Vendor`, `.chp` and Apache-2.0 on our RPMs
  - signing through `sign-session.sh`
  - nothing site-specific in any RPM
- **Signing rounds follow the user's accessibility protocol:**
  - announce the round in one line and **wait for "ready"**
  - `say "PIN dialog open. Eyes on the screen."` when pinentry appears, `say "Touch the key now."` every 20 s, `say "Signing finished."` at the end
  - never ask the user to type while a dialog may be open
- **User and group names:** `[a-z][a-z0-9_]{0,31}` (the lab's `valid_user`), checked before any command runs. Every Kanidm command is an argv list, never a shell string.
- **Kanidm CLI facts (captured on lab srv1, 2026-09-30):**
  - `person|group get` prints `---` then `attr: value` lines, one per value.
  - A missing entry prints `No matching entries` with **exit 0**.
  - No session + no TTY gives exit 101 and stderr `No valid authentication tokens found for NAME.`
  - Errors put the useful text on the **last** `ERROR` line of stderr (e.g. `HTTP Error: 409 Conflict`), with ANSI colour codes.
  - `account_expire: 2026-09-30T20:05:08.933703281Z` (RFC 3339 UTC, nanoseconds).
  - `unix_password: unix` and `primary_credential: primary` appear only when set.
  - `validity expire-at NAME now|clear` prints `Success`.
  - The reset-token output holds the link, the command and the expiry (plus a QR code).
- **The carry-forward from Plan 3a:** the next signed repo carries the collector login retry. `chp-identity-server` goes to `0.1.0-5` (retry + `cache-key` step).

## Review Focus

1. **`onboard` on an account that is expired** (deliberately off-boarded). Expected: refused, with a message pointing to `unexpire` and its approval. No Kanidm change is made, and no token or certificate is issued.
2. **`revoke` against the operator's own account or a built-in admin.** Expected: refused before any change, so an operator cannot lock out administration by a typo.
3. **During `revoke`, a client is off, unreachable or reinstalled** (host key changed). Expected:
   - the Kanidm change and the key move still happen, and are recorded
   - every other client is still cleared
   - the command ends non-zero, naming each client that may keep cached access for up to ~2 minutes; a changed host key gets the one-line fix
4. **The Kanidm session expires partway through a command.** Expected: a readable "log in first" error, and no `.done` audit record for a change that did not happen.
5. **An approver name or reason containing quotes, newlines or `key="value"` text.** Expected: it cannot forge or split fields in the audit record, because control characters and quotes are replaced and each field is quoted.

---

## File structure

| File | Responsibility |
|---|---|
| `appliance/chp-site/chp_site/kanidm.py` (new) | run the `kanidm` CLI with the operator's session; parse entries; expiry check |
| `appliance/chp-site/chp_site/audit.py` (new) | `operator()`, `record(action, fields)` → `auditctl -m` + `logger` |
| `appliance/chp-site/chp_site/sshca.py` (new) | registered keys, signing, issued records, revoked keys |
| `appliance/chp-site/chp_site/fanout.py` (new) | clear the unixd cache on this server (if a client) and on every `client` in `hosts` |
| `appliance/chp-site/chp_site/ops.py` (new) | `onboard`, `revoke`, `unexpire` (pure orchestration, everything injected) |
| `appliance/chp-site/chp_site/clientconf.py` | `CACHE_PUBKEY` in `client.conf` |
| `appliance/chp-site/chp_site/cli.py` | `onboard`, `revoke`, `unexpire` sub-commands; `export-client --cache-key` |
| `appliance/rpm/chp-identity-server/server-firstboot.sh` | `cache-key` step |
| `lab/iso3/prove.sh`, `lab/iso3/rootrun.exp` | `ops` stage; an optional second secret line |
| `tests/test_chp_site_{kanidm,audit,sshca,fanout,ops}.py` (new) | unit tests |

---

### Task 1: The Kanidm CLI adapter (`kanidm.py`)

**Files:**
- Create: `appliance/chp-site/chp_site/kanidm.py`
- Test: `tests/test_chp_site_kanidm.py`

**Interfaces:**
- Consumes: `chp_site.sitefile.SiteError`.
- Produces:
  - `NAME_RE: str`, `PROTECTED: frozenset[str]` (`{"admin", "idm_admin"}`)
  - `valid_name(n) -> bool`
  - `parse_entry(text) -> dict[str, list[str]] | None`
  - `expired(entry, now=None) -> bool`
  - `run_cli(argv, timeout=60) -> (rc, stdout, stderr_without_ansi)`
  - `class Kanidm(as_, run=run_cli)`:
    - `.as_`
    - `.whoami() -> str`
    - `.person(name) -> dict | None`
    - `.create_person(name, display)`, `.posix_set(name)`
    - `.add_member(group, name)`, `.remove_member(group, name)`
    - `.reset_token_text(name) -> str`
    - `.expire_now(name)`, `.clear_expiry(name)`

- [ ] **Step 1: Write the failing tests** (the output shapes were captured from lab srv1 on 2026-09-30; session lines are trimmed and the token is fake).

```python
import datetime

import pytest

from chp_site.kanidm import Kanidm, PROTECTED, expired, parse_entry, valid_name
from chp_site.sitefile import SiteError

LAB01 = """---
class: account
class: memberof
class: object
class: person
class: posixaccount
directmemberof: idm_all_persons@idm.kanidm.lab.test
directmemberof: lab_users@idm.kanidm.lab.test
displayname: Lab User 1
gidnumber: 2110612348
name: lab01
primary_credential: primary
spn: lab01@idm.kanidm.lab.test
unix_password: unix
"""
NOSESSION = ("\x1b[2m2026-09-30T20:02:43.467354Z\x1b[0m \x1b[31mERROR\x1b[0m kanidm_cli::common: No valid authentication "
             "tokens found for idm_admin.\nthread 'main' panicked at tools/cli/src/cli/common.rs:312:26:\n"
             "note: run with `RUST_BACKTRACE=1`\n")
CONFLICT = ("\x1b[31mERROR\x1b[0m kanidm_cli: OperationId: \"75ec400a\"\n"
            "\x1b[31mERROR\x1b[0m kanidm_cli: HTTP Error: 409 Conflict\n")
TOKEN = ("The person can use one of the following to allow the credential reset\n\nScan this QR Code:\n\n█▀▀█\n\n"
         "This link: https://idm.x.test/ui/reset?token=AbC-123\n"
         "Or run this command: kanidm person credential use-reset-token AbC-123\n"
         "This token will expire at: 2026-09-30T14:10:11-06:00\n")


class Fake:
    def __init__(self, *replies):
        self.calls, self.replies = [], list(replies)

    def __call__(self, argv, timeout=60):
        self.calls.append(argv)
        return self.replies.pop(0)


def test_parse_entry_multi_valued_and_missing():
    e = parse_entry(LAB01)
    assert e["name"] == ["lab01"] and "posixaccount" in e["class"] and e["unix_password"] == ["unix"]
    assert parse_entry("No matching entries\n") is None


def test_parse_entry_refuses_unrecognised_output():
    with pytest.raises(SiteError, match="unexpected output"):
        parse_entry("something else entirely\n")


def test_names():
    assert valid_name("lab01") and valid_name("a") and not valid_name("Lab01") and not valid_name("-x")
    assert not valid_name("a" * 33) and not valid_name("") and not valid_name(None)
    assert PROTECTED == {"admin", "idm_admin"}


def test_expired():
    now = datetime.datetime(2026, 9, 30, 21, 0, tzinfo=datetime.timezone.utc)
    assert expired({"account_expire": ["2026-09-30T20:05:08.933703281Z"]}, now)
    assert not expired({"account_expire": ["2026-10-30T20:05:08Z"]}, now)
    assert not expired({"name": ["x"]}, now)
    with pytest.raises(SiteError, match="account_expire"):
        expired({"account_expire": ["next tuesday"]}, now)


def test_every_command_uses_the_operator_session():
    f = Fake((0, LAB01, ""))
    assert Kanidm("alice", run=f).person("lab01")["name"] == ["lab01"]
    assert f.calls == [["person", "get", "lab01", "-D", "alice"]]


def test_no_session_is_a_readable_error():
    with pytest.raises(SiteError, match=r"not logged in to Kanidm as idm_admin: run `kanidm login -D idm_admin`"):
        Kanidm("idm_admin", run=Fake((101, "", NOSESSION))).person("lab01")


def test_error_uses_last_error_line_without_colour():
    with pytest.raises(SiteError) as e:
        Kanidm("idm_admin", run=Fake((1, "", CONFLICT))).create_person("lab01", "Lab 1")
    assert str(e.value) == "kanidm person create failed: HTTP Error: 409 Conflict"


def test_mutations_argv():
    f = Fake(*[(0, "Success\n", "")] * 6)
    k = Kanidm("idm_admin", run=f)
    k.create_person("lab09", "Lab User 9"); k.posix_set("lab09"); k.add_member("lab_users", "lab09")
    k.remove_member("lab_users", "lab09"); k.expire_now("lab09"); k.clear_expiry("lab09")
    assert [c[:-2] for c in f.calls] == [
        ["person", "create", "lab09", "Lab User 9"], ["person", "posix", "set", "lab09"],
        ["group", "add-members", "lab_users", "lab09"], ["group", "remove-members", "lab_users", "lab09"],
        ["person", "validity", "expire-at", "lab09", "now"], ["person", "validity", "expire-at", "lab09", "clear"]]


def test_reset_token_text_requires_a_token():
    assert "use-reset-token AbC-123" in Kanidm("idm_admin", run=Fake((0, TOKEN, ""))).reset_token_text("lab09")
    with pytest.raises(SiteError, match="no reset token"):
        Kanidm("idm_admin", run=Fake((0, "odd\n", ""))).reset_token_text("lab09")


def test_bad_names_never_reach_the_cli():
    f = Fake()
    with pytest.raises(SiteError, match="not a valid"):
        Kanidm("idm_admin", run=f).person("x; rm -rf /")
    with pytest.raises(SiteError, match="not a valid"):
        Kanidm("Bad Admin", run=f)
    assert f.calls == []


def test_whoami_returns_name():
    assert Kanidm("alice", run=Fake((0, "---\nname: alice\nspn: alice@x\n", ""))).whoami() == "alice"
```

- [ ] **Step 2: Run to verify it fails.** Run `.venv/bin/python -m pytest tests/test_chp_site_kanidm.py -q`. Expected: FAIL with `ModuleNotFoundError: No module named 'chp_site.kanidm'`.

- [ ] **Step 3: Implement** `appliance/chp-site/chp_site/kanidm.py`:

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The Kanidm CLI as chp-site uses it. Every command runs as the operator's EXISTING session (`-D NAME`, stdin closed so a
missing session fails fast instead of prompting); chp-site never sees a password. Output shapes: Kanidm 1.11.2."""
import datetime
import re
import subprocess

from .sitefile import SiteError

NAME_RE = r"[a-z][a-z0-9_]{0,31}"
PROTECTED = frozenset({"admin", "idm_admin"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def valid_name(n):
    return bool(re.fullmatch(NAME_RE, n or ""))


def _name(n, what="name"):
    if not valid_name(n):
        raise SiteError(f"{n!r} is not a valid {what} (lower-case letters, digits, _; starts with a letter; max 32)")
    return n


def parse_entry(text):
    """`kanidm person|group get` -> {attr: [values]}; None for "No matching entries". Anything else is an error, never
    'absent' (reading garbage as 'no such user' would make onboard try to create an existing account)."""
    if text.strip() == "No matching entries":
        return None
    e = {}
    for line in text.splitlines():
        if line == "---" or ": " not in line:
            continue
        k, v = line.split(": ", 1)
        e.setdefault(k, []).append(v)
    if "name" not in e:
        raise SiteError(f"unexpected output from kanidm: {text.strip()[:120]!r}")
    return e


def expired(entry, now=None):
    """True when account_expire is in the past. An unreadable value is an error, never 'not expired'."""
    v = (entry.get("account_expire") or [None])[0]
    if v is None:
        return False
    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z", v)
    if not m:
        raise SiteError(f"cannot read account_expire {v!r}")
    t = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return t <= (now or datetime.datetime.now(datetime.timezone.utc))


def run_cli(argv, timeout=60):
    try:
        r = subprocess.run(["kanidm", *argv], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise SiteError("the kanidm CLI is not installed here (run this on the identity server)") from None
    except subprocess.TimeoutExpired:
        raise SiteError(f"kanidm {' '.join(argv[:2])} timed out after {timeout} s") from None
    return r.returncode, r.stdout, _ANSI.sub("", r.stderr)


class Kanidm:
    def __init__(self, as_, run=run_cli):
        self.as_ = _name(as_, "Kanidm admin name (--as)")
        self._run = run

    def _k(self, *argv):
        rc, out, err = self._run([*argv, "-D", self.as_])
        if rc != 0:
            if "No valid authentication tokens" in err:
                raise SiteError(f"not logged in to Kanidm as {self.as_}: run `kanidm login -D {self.as_}` first")
            errs = [re.sub(r"^.*?ERROR\s+\S+:\s*", "", ln).strip() for ln in err.splitlines() if "ERROR" in ln]
            raise SiteError(f"kanidm {' '.join(argv[:2])} failed: {(errs[-1] if errs else f'exit {rc}')[:200]}")
        return out

    def whoami(self):
        return parse_entry(self._k("self", "whoami"))["name"][0]

    def person(self, name):
        return parse_entry(self._k("person", "get", _name(name)))

    def create_person(self, name, display):
        self._k("person", "create", _name(name), display)

    def posix_set(self, name):
        self._k("person", "posix", "set", _name(name))

    def add_member(self, group, name):
        self._k("group", "add-members", _name(group, "group name"), _name(name))

    def remove_member(self, group, name):
        self._k("group", "remove-members", _name(group, "group name"), _name(name))

    def reset_token_text(self, name):
        out = self._k("person", "credential", "create-reset-token", _name(name), "--ttl", "3600")
        if not re.search(r"use-reset-token [A-Za-z0-9-]+", out):
            raise SiteError("no reset token in the kanidm output")
        return out

    def expire_now(self, name):
        self._k("person", "validity", "expire-at", _name(name), "now")

    def clear_expiry(self, name):
        self._k("person", "validity", "expire-at", _name(name), "clear")
```

- [ ] **Step 4: Run the tests.** `.venv/bin/python -m pytest tests/test_chp_site_kanidm.py -q`. Expected: `11 passed`.
- [ ] **Step 5: Commit.** `git add appliance/chp-site/chp_site/kanidm.py tests/test_chp_site_kanidm.py && git commit -m "ISO Plan 3b Task 1: chp-site Kanidm CLI adapter (operator session only, parsed output)"`

---

### Task 2: Audit records and the SSH CA helpers (`audit.py`, `sshca.py`)

**Files:**
- Create: `appliance/chp-site/chp_site/audit.py`, `appliance/chp-site/chp_site/sshca.py`
- Test: `tests/test_chp_site_audit.py`, `tests/test_chp_site_sshca.py`

**Interfaces:**
- Consumes: `SiteError`, `sitefile.ssh_pubkey`, `kanidm.valid_name`.
- Produces:
  - `audit.operator() -> str`
  - `audit.record(action, fields, after=False, run=subprocess.run)`
  - `sshca.SshCa(base=Path("/"), run=subprocess.run)` with:
    - `.registered(user) -> str | None`
    - `.register(user, pub_text, replace=False) -> "new" | "same" | "replaced"`
    - `.sign(user, domain) -> (cert_text, valid_to)`
    - `.revoke_key(user, stamp) -> bool`
  - `sshca.VALIDITY = "+8h"`

- [ ] **Step 1: Failing tests** `tests/test_chp_site_audit.py`:

```python
import pytest

from chp_site import audit
from chp_site.sitefile import SiteError


class Run:
    def __init__(self, rc=0, missing=()):
        self.calls, self.rc, self.missing = [], rc, missing

    def __call__(self, argv, **kw):
        if argv[0] in self.missing:
            raise FileNotFoundError(argv[0])
        self.calls.append(argv)
        import types
        return types.SimpleNamespace(returncode=self.rc, stdout="", stderr="denied")


def test_record_goes_to_audit_and_journal():
    r = Run()
    audit.record("unexpire", {"user": "lab04", "approver": "Pat ISSO"}, run=r)
    assert r.calls[0][:2] == ["auditctl", "-m"] and r.calls[1][:5] == ["logger", "-p", "authpriv.notice", "-t", "chp-site"]
    assert r.calls[0][2] == r.calls[1][5] == 'chp-site unexpire user="lab04" approver="Pat ISSO"'


def test_fields_cannot_forge_or_split_the_record():
    r = Run()
    audit.record("unexpire", {"reason": 'ok" approver="ISSO\nuser="root'}, run=r)
    msg = r.calls[0][2]
    assert "\n" not in msg and msg.count('"') == 2 and 'approver="ISSO' not in msg


def test_failed_record_before_a_change_says_nothing_changed():
    with pytest.raises(SiteError, match="nothing was changed"):
        audit.record("revoke", {"user": "x"}, run=Run(rc=1))
    with pytest.raises(SiteError, match="nothing was changed"):
        audit.record("revoke", {"user": "x"}, run=Run(missing=("auditctl",)))


def test_failed_record_after_a_change_says_it_was_made():
    with pytest.raises(SiteError, match="the change WAS made"):
        audit.record("revoke.done", {"user": "x"}, after=True, run=Run(rc=1))


def test_operator_is_a_string():
    assert isinstance(audit.operator(), str) and audit.operator()
```

   And `tests/test_chp_site_sshca.py` (it uses the real `ssh-keygen`, present on macOS and Rocky):

```python
import subprocess

import pytest

from chp_site.sshca import SshCa, VALIDITY
from chp_site.sitefile import SiteError


def keypair(d, name):
    subprocess.run(["ssh-keygen", "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", name, "-f", str(d / name)], check=True)
    return (d / f"{name}.pub").read_text()


@pytest.fixture
def ca(tmp_path):
    (tmp_path / "etc/ssh-ca").mkdir(parents=True)
    keypair(tmp_path / "etc/ssh-ca", "user_ca")
    for d in ("keys", "issued"):
        (tmp_path / "var/lib/ssh-ca" / d).mkdir(parents=True)
    return SshCa(base=tmp_path)


def test_register_new_same_and_refuse_a_different_key(ca, tmp_path):
    k1, k2 = keypair(tmp_path, "k1"), keypair(tmp_path, "k2")
    assert ca.register("lab09", k1) == "new" and ca.register("lab09", k1) == "same"
    with pytest.raises(SiteError, match="different key is already registered"):
        ca.register("lab09", k2)
    assert ca.register("lab09", k2, replace=True) == "replaced" and ca.registered("lab09").split()[1] == k2.split()[1]


def test_register_refuses_ed25519(ca):
    with pytest.raises(SiteError, match="FIPS"):
        ca.register("lab09", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyHV2oRj8Uf8QdTf6eK8f5dDAXHhpxS5X0mGmAcBwUP x")


def test_sign_records_and_returns_the_certificate(ca, tmp_path):
    ca.register("lab09", keypair(tmp_path, "k1"))
    cert, valid_to = ca.sign("lab09", "iso3.lab.test")
    rec = (tmp_path / "var/lib/ssh-ca/issued/lab09-cert.pub").read_text()
    assert rec == cert and cert.startswith("ecdsa-sha2-nistp384-cert-v01@openssh.com ")
    listing = subprocess.run(["ssh-keygen", "-L", "-f", "/dev/stdin"], input=cert, capture_output=True, text=True).stdout
    assert "lab09@idm.iso3.lab.test" in listing and valid_to in listing and VALIDITY == "+8h"


def test_sign_without_a_registered_key_is_refused(ca):
    with pytest.raises(SiteError, match="no registered SSH key"):
        ca.sign("lab09", "iso3.lab.test")


def test_revoke_key_moves_it_aside(ca, tmp_path):
    ca.register("lab09", keypair(tmp_path, "k1"))
    assert ca.revoke_key("lab09", "20260930T200000Z") is True and ca.registered("lab09") is None
    assert (tmp_path / "var/lib/ssh-ca/revoked/lab09.pub.20260930T200000Z").exists()
    assert ca.revoke_key("lab09", "20260930T200001Z") is False
```

- [ ] **Step 2: Run to verify they fail.** `.venv/bin/python -m pytest tests/test_chp_site_audit.py tests/test_chp_site_sshca.py -q`. Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement** `audit.py`:

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Administrative actions to the Linux audit log (`auditctl -m` -> a type=USER event) and to authpriv (/var/log/secure,
journal). A record is written BEFORE a change (the change is refused if that fails) and after it (ISSO #32)."""
import os
import re
import subprocess

from .sitefile import SiteError


def _clean(v):
    return re.sub(r"[\x00-\x1f\x7f\"'\\]", " ", str(v))[:300]


def operator():
    """The person at the keyboard: the audit login uid (kept across su/sudo), else SUDO_USER, else USER."""
    try:
        with open("/proc/self/loginuid") as f:
            uid = int(f.read().strip())
        if uid != 4294967295:
            import pwd
            return pwd.getpwuid(uid).pw_name
    except (OSError, ValueError, KeyError, ImportError):
        pass
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "unknown"


def record(action, fields, after=False, run=subprocess.run):
    msg = f"chp-site {action} " + " ".join(f'{k}="{_clean(v)}"' for k, v in fields.items())
    for argv in (["auditctl", "-m", msg], ["logger", "-p", "authpriv.notice", "-t", "chp-site", msg]):
        try:
            r = run(argv, capture_output=True, text=True)
            why = None if r.returncode == 0 else (r.stderr.strip() or f"exit {r.returncode}")[:120]
        except FileNotFoundError:
            why = f"{argv[0]} is not installed"
        if why:
            tail = ("the change WAS made; the request record exists" if after else "nothing was changed")
            raise SiteError(f"could not write the audit record with {argv[0]} ({why}): {tail}")
```

   Then `sshca.py`:

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The SSH user CA's files (layout from the lab, spec row 34):
  /var/lib/ssh-ca/keys/<user>.pub           the user's REGISTERED public key (the only key the CA will sign for them)
  /var/lib/ssh-ca/issued/<user>-cert.pub    the newest certificate issued (public; read by idm-collect)
  /var/lib/ssh-ca/revoked/<user>.pub.<UTC>  keys taken out of service by `chp-site revoke`"""
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .kanidm import valid_name
from .sitefile import SiteError, ssh_pubkey

VALIDITY = "+8h"


class SshCa:
    def __init__(self, base=Path("/"), run=subprocess.run):
        b = Path(base)
        self.ca = b / "etc/ssh-ca/user_ca"
        self.keys, self.issued, self.revoked = (b / "var/lib/ssh-ca" / d for d in ("keys", "issued", "revoked"))
        self._run = run

    def _user(self, u):
        if not valid_name(u):
            raise SiteError(f"{u!r} is not a valid user name")
        return u

    def registered(self, user):
        p = self.keys / f"{self._user(user)}.pub"
        return p.read_text().strip() if p.exists() else None

    def register(self, user, pub_text, replace=False):
        try:
            key = ssh_pubkey(pub_text.strip())
        except SiteError as e:
            raise SiteError(str(e).replace("ADMIN_SSH_PUBKEY", f"{user}'s SSH key")) from None
        old = self.registered(user)
        if old is not None and old.split()[:2] == key.split()[:2]:
            return "same"
        if old is not None and not replace:
            raise SiteError(f"a different key is already registered for {user}; pass --replace-key to replace it")
        p = self.keys / f"{user}.pub"
        tmp = p.with_suffix(".pub.new")
        tmp.write_text(f"{key} {user}\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)
        return "new" if old is None else "replaced"

    def sign(self, user, domain):
        if self.registered(user) is None:
            raise SiteError(f"{user} has no registered SSH key (onboard with --ssh-key FILE)")
        with tempfile.TemporaryDirectory() as t:
            k = Path(t) / "k.pub"
            k.write_text((self.keys / f"{user}.pub").read_text())
            r = self._run(["ssh-keygen", "-q", "-s", str(self.ca), "-I", f"{user}-cert", "-n", f"{user},{user}@idm.{domain}",
                           "-V", VALIDITY, str(k)], capture_output=True, text=True)
            if r.returncode != 0:
                raise SiteError(f"ssh-keygen could not sign {user}'s key: {r.stderr.strip()[:200]}")
            cert = (Path(t) / "k-cert.pub").read_text()
        out = self.issued / f"{user}-cert.pub"
        out.write_text(cert)
        os.chmod(out, 0o644)
        lst = self._run(["ssh-keygen", "-L", "-f", str(out)], capture_output=True, text=True).stdout
        m = re.search(r"Valid: from \S+ to (\S+)", lst)
        return cert, (m.group(1) if m else "unknown")

    def revoke_key(self, user, stamp):
        p = self.keys / f"{self._user(user)}.pub"
        if not p.exists():
            return False
        self.revoked.mkdir(mode=0o755, exist_ok=True)
        os.replace(p, self.revoked / f"{user}.pub.{stamp}")
        return True
```

- [ ] **Step 4: Run the tests.** Same command. Expected: `10 passed` (`ssh_pubkey` rejects `ssh-ed25519` by its type before decoding, so the fixture line needs no real key).
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 3b Task 2: audit records (before+after, unforgeable fields) and SSH CA key/cert helpers"`

---

### Task 3: The cache key: first-boot step, `client.conf CACHE_PUBKEY`, and the fan-out (`fanout.py`)

**Files:**
- Modify:
  - `appliance/rpm/chp-identity-server/server-firstboot.sh` (new `do_cachekey` + `step cache-key`)
  - `chp-identity-server.spec` (`Release: 5.chp`, changelog)
  - `appliance/chp-site/chp_site/clientconf.py`
  - `appliance/chp-site/chp_site/cli.py` (`export-client --cache-key`)
  - every test/fixture that builds a `client.conf`
- Create: `appliance/chp-site/chp_site/fanout.py`; `tests/fixtures/chp-site/cache_key.pub` (a fresh `ssh-keygen -t ecdsa -b 384` public key; the private half is discarded)
- Test: `tests/test_chp_site_fanout.py`, `tests/test_chp_site_clientconf.py`, `tests/test_server_role_static.py`

**Interfaces:**
- Consumes: `hosts.Host` (`mac hostname ip role disk`).
- Produces:
  - `make_client_conf(domain, root_pem, ssh_ca_pub, cache_pub)`; `parse_client_conf` requires `CACHE_PUBKEY` (ECDSA/RSA per `ssh_pubkey`)
  - `fanout.KEY`, `fanout.KNOWN`, `fanout.ACCOUNT = "chpcache"`
  - `fanout.invalidate_all(hosts, run=subprocess.run, key=KEY, known=KNOWN) -> list[(name, ok: bool, detail: str)]`
  - `fanout.report(results) -> (text, failed_names)`

- [ ] **Step 1: Failing tests.**
  - In `tests/test_chp_site_clientconf.py`, add the tests below (import `pytest` and `SiteError` there if needed). Update every existing `make_client_conf(...)` call in the tests to pass `(FX / "cache_key.pub").read_text()` as the 4th argument. That covers `test_chp_site_cli.py`, `test_chp_site_pre.py`, `test_kickstarts.py` and any others; find them with `grep -rn make_client_conf tests`.

```python
def test_client_conf_carries_the_cache_key():
    t = make_client_conf("iso2.lab.test", (FX / "root_ca.crt").read_text(), (FX / "user_ca.pub").read_text(),
                         (FX / "cache_key.pub").read_text())
    c = parse_client_conf(t, {"DOMAIN": "iso2.lab.test"})
    assert c["CACHE_PUBKEY"].startswith("ecdsa-sha2-nistp384 ")


def test_client_conf_without_cache_key_is_refused():
    t = make_client_conf("iso2.lab.test", (FX / "root_ca.crt").read_text(), (FX / "user_ca.pub").read_text(),
                         (FX / "cache_key.pub").read_text())
    t = "\n".join(ln for ln in t.splitlines() if not ln.startswith("CACHE_PUBKEY=")) + "\n"
    with pytest.raises(SiteError, match="CACHE_PUBKEY is required"):
        parse_client_conf(t, {"DOMAIN": "iso2.lab.test"})
```

   `tests/test_chp_site_fanout.py`:

```python
import subprocess
import types

from chp_site.fanout import ACCOUNT, invalidate_all, report
from chp_site.hosts import Host

HOSTS = [Host("52:54:00:00:00:30", "srv", "192.168.100.30", "server", None),
         Host("52:54:00:00:00:31", "cli1", "192.168.100.31", "client", None),
         Host("52:54:00:00:00:32", "cli2", "192.168.100.32", "client", None)]


class Run:
    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        for needle, res in self.table.items():
            if needle in " ".join(argv):
                if res == "timeout":
                    raise subprocess.TimeoutExpired(argv, 20)
                return types.SimpleNamespace(returncode=res[0], stdout="", stderr=res[1])
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")


def test_only_clients_over_the_pinned_key_and_local_unixd_when_active():
    r = Run({"is-active": (0, "")})
    res = invalidate_all(HOSTS, run=r)
    ssh = [c for c in r.calls if c[0] == "ssh"]
    assert [c[-2] for c in ssh] == [f"{ACCOUNT}@192.168.100.31", f"{ACCOUNT}@192.168.100.32"]
    assert all("BatchMode=yes" in c and "IdentitiesOnly=yes" in c and "StrictHostKeyChecking=accept-new" in c for c in ssh)
    assert ["kanidm-unix", "cache-invalidate"] in r.calls and [n for n, ok, _ in res] == ["srv (this server)", "cli1", "cli2"]


def test_server_not_yet_a_client_is_reported_not_hidden():
    res = invalidate_all(HOSTS[:1], run=Run({"is-active": (3, "")}))
    assert res == [("srv (this server)", True, "not a Kanidm client yet: nothing cached")]


def test_unreachable_and_changed_host_key_are_named():
    r = Run({"is-active": (3, ""), "100.31": "timeout",
             "100.32": (255, "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@")})
    text, failed = report(invalidate_all(HOSTS, run=r))
    assert failed == ["cli1", "cli2"] and "timed out" in text
    assert "ssh-keygen -R 192.168.100.32 -f /var/lib/chp/cache-key/known_hosts" in text


def test_no_clients_at_all():
    text, failed = report(invalidate_all(HOSTS[:1], run=Run({"is-active": (3, "")})))
    assert failed == [] and "no clients in the hosts table" in text
```

   In `tests/test_server_role_static.py`:

```python
def test_firstboot_makes_the_cache_key_before_server_done():
    t = (ROOT / "appliance/rpm/chp-identity-server/server-firstboot.sh").read_text()
    assert "ssh-keygen -q -t ecdsa -b 384 -N '' -C \"chpcache@$FQDN\" -f /var/lib/chp/cache-key/id_ecdsa" in t
    assert t.index("step cache-key do_cachekey") < t.index('touch "$M/server.done"')
    assert "install -d -m 0700 /var/lib/chp/cache-key" in t
```

   (Use the module's existing `ROOT` name; if it is named differently, use that name.)

- [ ] **Step 2: Run to verify failure.** `.venv/bin/python -m pytest tests -q -k "cache or fanout or client_conf"`. Expected: FAIL (`ModuleNotFoundError: chp_site.fanout`, a `make_client_conf` arity error, and the static assert).

- [ ] **Step 3: Implement.**
  - **`clientconf.py`:**
    - `make_client_conf(domain, root_pem, ssh_ca_pub, cache_pub)` adds the line `CACHE_PUBKEY={ssh_pubkey(cache_pub)}` after `SSH_CA_FPR`.
    - `parse_client_conf` adds `"CACHE_PUBKEY"` to the required tuple. It validates the key with `ssh_pubkey` (re-labelling the error as `client.conf CACHE_PUBKEY`, as for `SSH_CA_PUBKEY`) and returns it in the dict.
  - **`cli.py` `_export`:** read `Path(a.cache_key).read_text()` and pass it to `make_client_conf`; add `e.add_argument("--cache-key", default="/var/lib/chp/cache-key/id_ecdsa.pub")`. In `tests/test_chp_site_cli.py::test_export_client_writes_and_prints_fingerprints`, pass `"--cache-key", str(FX / "cache_key.pub")`.
  - **`server-firstboot.sh`:** add the step below after `do_sshca`, and add `step cache-key do_cachekey` after `step ssh-ca do_sshca`.

```bash
do_cachekey() {
  # The server's key for `chp-site revoke`: clients (Plan 4) accept it only from this server's IP, only for the forced
  # command `sudo -n /usr/bin/kanidm-unix cache-invalidate` (ISSO #28). Public half goes to client.conf (CACHE_PUBKEY).
  install -d -m 0700 /var/lib/chp/cache-key
  if [ ! -f /var/lib/chp/cache-key/id_ecdsa ]; then
    ssh-keygen -q -t ecdsa -b 384 -N '' -C "chpcache@$FQDN" -f /var/lib/chp/cache-key/id_ecdsa
  fi
  restorecon -R /var/lib/chp/cache-key
}
```

  - **`chp-identity-server.spec`:** `Release: 5.chp%{?dist}` with a changelog entry: `- cache-key first-boot step (chp-site revoke fan-out, ISSO #28); carries the 0.1.0-4 collector login retry`.
  - **`fanout.py`:**

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Clear the kanidm-unixd cache everywhere after a revoke (ISSO #28: the ~2 min cache window becomes seconds).
Clients accept the server's cache key only from the server's IP and only for the forced command
`sudo -n /usr/bin/kanidm-unix cache-invalidate` (client role, Plan 4). Host keys: trust on first use, in a dedicated file."""
import subprocess
from pathlib import Path

KEY = Path("/var/lib/chp/cache-key/id_ecdsa")
KNOWN = Path("/var/lib/chp/cache-key/known_hosts")
ACCOUNT = "chpcache"


def _local(run):
    name = "(this server)"
    if run(["systemctl", "is-active", "-q", "kanidm-unixd"], capture_output=True, text=True).returncode != 0:
        return (name, True, "not a Kanidm client yet: nothing cached")
    r = run(["kanidm-unix", "cache-invalidate"], capture_output=True, text=True)
    return (name, r.returncode == 0, "ok" if r.returncode == 0 else (r.stderr.strip() or "failed")[:120])


def invalidate_all(hosts, run=subprocess.run, key=KEY, known=KNOWN):
    server = next((h.hostname for h in hosts if h.role == "server"), "server")
    n, ok, d = _local(run)
    out = [(f"{server} {n}", ok, d)]
    for h in hosts:
        if h.role != "client":
            continue
        argv = ["ssh", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", f"UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=accept-new",
                f"{ACCOUNT}@{h.ip}", "cache-invalidate"]
        try:
            r = run(argv, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            out.append((h.hostname, False, "timed out (host off or unreachable?)"))
            continue
        if r.returncode == 0:
            out.append((h.hostname, True, "ok"))
        elif "IDENTIFICATION HAS CHANGED" in r.stderr:
            out.append((h.hostname, False, f"host key changed (reinstalled?); if expected: ssh-keygen -R {h.ip} -f {known}"))
        else:
            last = [ln for ln in r.stderr.splitlines() if ln.strip()]
            out.append((h.hostname, False, (last[-1] if last else f"exit {r.returncode}")[:160]))
    return out


def report(results):
    lines = [f"  {'ok  ' if ok else 'FAIL'} {name}: {detail}" for name, ok, detail in results]
    if not any(True for n, _, _ in results if "(this server)" not in n):
        lines.append("  (no clients in the hosts table)")
    return "caches:\n" + "\n".join(lines), [n for n, ok, _ in results if not ok]
```

- [ ] **Step 4: Run the whole suite.** `.venv/bin/python -m pytest -q`. Expected: all pass (433 + the new ones). Fix every test that built a `client.conf` without the new argument; the suite being green is the gate.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 3b Task 3: cache key (first boot + client.conf CACHE_PUBKEY) and the revoke fan-out"`

---

### Task 4: `chp-site onboard`

**Files:**
- Create: `appliance/chp-site/chp_site/ops.py` (the `onboard` part plus shared helpers)
- Modify: `appliance/chp-site/chp_site/cli.py`
- Test: `tests/test_chp_site_ops.py`

**Interfaces:**
- Consumes: `Kanidm` (Task 1), `SshCa` (Task 2), `audit.record` / `audit.operator` (Task 2).
- Produces:
  - `ops.OUT = Path("/root/chp-onboard")`
  - `ops.write_private(out, name, text) -> Path`
  - `ops.onboard(k, ca, user, domain, display=None, groups=(), ssh_key=None, replace_key=False, out=OUT, rec=audit.record, say=print) -> list[(item, done: bool, note)]`
  - CLI `chp-site onboard USER [--display TEXT] [--group G]... [--ssh-key FILE] [--replace-key] [--as NAME] [--site DIR]`

- [ ] **Step 1: Failing tests** in `tests/test_chp_site_ops.py` (a fake Kanidm with state, the real `SshCa` from Task 2's fixture, and audit captured):

```python
import pytest

from chp_site import ops
from chp_site.sitefile import SiteError
from tests.test_chp_site_sshca import ca, keypair  # noqa: F401  (pytest fixture)


class FakeK:
    """In-memory Kanidm: people = {name: entry dict}; records every mutation."""
    def __init__(self, people=None, as_="idm_admin"):
        self.as_, self.people, self.log = as_, people or {}, []

    def person(self, n):
        return self.people.get(n)

    def create_person(self, n, d):
        self.log.append(("create", n, d)); self.people[n] = {"name": [n], "class": ["person"], "directmemberof": []}

    def posix_set(self, n):
        self.log.append(("posix", n)); self.people[n]["class"].append("posixaccount")

    def add_member(self, g, n):
        self.log.append(("add", g, n)); self.people[n]["directmemberof"].append(f"{g}@idm.x")

    def remove_member(self, g, n):
        self.log.append(("remove", g, n))
        self.people[n]["directmemberof"] = [m for m in self.people[n]["directmemberof"] if not m.startswith(g + "@")]

    def reset_token_text(self, n):
        self.log.append(("token", n)); return "This link: https://idm.x/ui/reset?token=T0K\nuse-reset-token T0K\n"

    def expire_now(self, n):
        self.log.append(("expire", n)); self.people[n]["account_expire"] = ["2000-01-01T00:00:00Z"]

    def clear_expiry(self, n):
        self.log.append(("clear", n)); self.people[n].pop("account_expire", None)


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, action, fields, after=False):
        self.calls.append((action, dict(fields), after))


def test_onboard_new_user_full_path(ca, tmp_path):
    k, rec, out = FakeK(), Rec(), tmp_path / "out"
    items = ops.onboard(k, ca, "lab09", "iso3.lab.test", display="Lab 9", groups=("lab_users",),
                        ssh_key=keypair(tmp_path, "u9"), out=out, rec=rec, say=lambda *_: None)
    assert [e[0] for e in k.log] == ["create", "posix", "add", "token"]
    tok = out / "lab09.reset-token.txt"
    assert tok.read_text().endswith("use-reset-token T0K\n") and oct(tok.stat().st_mode & 0o777) == "0o600"
    assert oct(out.stat().st_mode & 0o777) == "0o700" and (out / "lab09-cert.pub").exists()
    done = {i: d for i, d, _ in items}
    assert done["account"] and done["POSIX enabled"] and done["SSH key registered"] and done["SSH certificate issued"]
    assert not done["primary credential"] and not done["POSIX (unix) password"] and not done["Google Authenticator"]
    assert [c[0] for c in rec.calls] == ["onboard", "onboard.done"] and rec.calls[1][2] is True


def test_onboard_is_idempotent_and_skips_the_token_when_credentials_exist(ca, tmp_path):
    k = FakeK({"lab01": {"name": ["lab01"], "class": ["person", "posixaccount"], "directmemberof": ["lab_users@idm.x"],
                         "primary_credential": ["primary"], "unix_password": ["unix"]}})
    ops.onboard(k, ca, "lab01", "iso3.lab.test", groups=("lab_users",), out=tmp_path / "o", rec=Rec(), say=lambda *_: None)
    assert k.log == [] and not (tmp_path / "o" / "lab01.reset-token.txt").exists()


def test_onboard_refuses_an_expired_account(ca, tmp_path):     # Review Focus 1: no bypass of ISSO #32
    k, rec = FakeK({"lab04": {"name": ["lab04"], "class": ["person"], "account_expire": ["2000-01-01T00:00:00Z"]}}), Rec()
    with pytest.raises(SiteError, match="chp-site unexpire lab04 --approver"):
        ops.onboard(k, ca, "lab04", "iso3.lab.test", ssh_key=keypair(tmp_path, "u4"), out=tmp_path / "o", rec=rec)
    assert k.log == [] and rec.calls == [] and ca.registered("lab04") is None


def test_onboard_refuses_builtin_admins(ca, tmp_path):
    with pytest.raises(SiteError, match="built-in"):
        ops.onboard(FakeK(), ca, "idm_admin", "x.test", out=tmp_path / "o", rec=Rec())


def test_onboard_audit_failure_changes_nothing(ca, tmp_path):
    def bad(action, fields, after=False):
        raise SiteError("could not write the audit record")
    k = FakeK()
    with pytest.raises(SiteError, match="audit"):
        ops.onboard(k, ca, "lab09", "x.test", out=tmp_path / "o", rec=bad)
    assert k.log == []
```

   Add a CLI test in `tests/test_chp_site_cli.py`:

```python
def test_onboard_help_lists_the_options():
    r = cli("onboard", "--help")
    assert r.returncode == 0 and all(o in r.stdout for o in ("--group", "--ssh-key", "--replace-key", "--as", "--display"))
```

- [ ] **Step 2: Run to verify failure.** `.venv/bin/python -m pytest tests/test_chp_site_ops.py tests/test_chp_site_cli.py -q`. Expected: FAIL (`No module named 'chp_site.ops'`; argparse `invalid choice: 'onboard'`).

- [ ] **Step 3: Implement** `ops.py`:

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site onboard | revoke | unexpire (spec 4.4; ISSO #28, #32). Kanidm runs as the operator's own session; every change
is audited before and after; secrets (reset tokens) go to root-only files and are never printed."""
import os
import time
from pathlib import Path

from . import audit
from .kanidm import PROTECTED, expired, valid_name
from .sitefile import SiteError

OUT = Path("/root/chp-onboard")


def _stamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _user(u):
    if not valid_name(u):
        raise SiteError(f"{u!r} is not a valid user name")
    if u in PROTECTED:
        raise SiteError(f"refusing: {u} is a built-in Kanidm admin account; chp-site does not manage it")
    return u


def write_private(out, name, text):
    out = Path(out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    p = out / name
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(p, 0o600)
    return p


def onboard(k, ca, user, domain, display=None, groups=(), ssh_key=None, replace_key=False, out=OUT,
            rec=audit.record, say=print):
    _user(user)
    for g in groups:
        if not valid_name(g):
            raise SiteError(f"{g!r} is not a valid group name")
    e = k.person(user)
    if e is not None and expired(e):
        raise SiteError(f"{user} is expired; re-enabling needs the ISSO's approval: "
                        f"chp-site unexpire {user} --approver NAME --reason TEXT")
    fields = {"user": user, "groups": ",".join(groups), "operator": audit.operator(), "as": k.as_}
    rec("onboard", fields)
    if e is None:
        k.create_person(user, display or user)
        say(f"created Kanidm person {user}")
        e = k.person(user)
    if "posixaccount" not in e.get("class", []):
        k.posix_set(user)
        e = k.person(user)
    member = {m.split("@")[0] for m in e.get("directmemberof", [])}
    for g in groups:
        if g not in member:
            k.add_member(g, user)
            say(f"added {user} to {g}")
    e = k.person(user)
    has_primary, has_unix = "primary_credential" in e, "unix_password" in e
    token = None
    if not (has_primary and has_unix):
        token = write_private(out, f"{user}.reset-token.txt", k.reset_token_text(user))
    if ssh_key is not None:
        say(f"SSH key for {user}: {ca.register(user, ssh_key, replace=replace_key)}")
    cert_note = None
    if ca.registered(user) is not None:
        cert, valid_to = ca.sign(user, domain)
        p = write_private(out, f"{user}-cert.pub", cert)
        os.chmod(p, 0o644)
        cert_note = f"valid to {valid_to}: {p} (public; give it to the user)"
    rec("onboard.done", fields, after=True)
    tok_note = f"reset token (valid 1 h, re-run onboard for a new one): {token}" if token else ""
    return [("account", True, user),
            ("POSIX enabled", True, ""),
            ("primary credential", has_primary, tok_note),
            ("POSIX (unix) password", has_unix, "same reset token" if token else ""),
            ("SSH key registered", ca.registered(user) is not None, "" if ca.registered(user) else "pass --ssh-key FILE"),
            ("SSH certificate issued", cert_note is not None, cert_note or ""),
            ("Google Authenticator", False, "the user enrols on each client at first login (client role)")]
```

   And in `cli.py`: add `_ops_env`, `_onboard`, the sub-parser and the dispatch entry:

```python
def _ops_env(a):
    from .kanidm import Kanidm
    from .sshca import SshCa
    site, hosts = _load(a.site)
    return site, hosts, Kanidm(a.as_), SshCa()


def _onboard(a):
    from .ops import onboard
    site, _hosts, k, ca = _ops_env(a)
    key = Path(a.ssh_key).read_text() if a.ssh_key else None
    items = onboard(k, ca, a.user, site["DOMAIN"], display=a.display, groups=tuple(a.group), ssh_key=key,
                    replace_key=a.replace_key)
    print(f"onboarding checklist for {a.user}:")
    for item, done, note in items:
        print(f"  [{'x' if done else ' '}] {item}" + (f"  ({note})" if note else ""))
```

```python
    o = sub.add_parser("onboard", help="create/complete a person: POSIX, groups, reset token, SSH key + certificate")
    o.add_argument("user"); o.add_argument("--display"); o.add_argument("--group", action="append", default=[])
    o.add_argument("--ssh-key", help="the user's OpenSSH public key file (ECDSA or RSA >= 3072)")
    o.add_argument("--replace-key", action="store_true")
    o.add_argument("--as", dest="as_", default="idm_admin", help="your Kanidm admin session (kanidm login -D NAME)")
    o.add_argument("--site", default="/etc/chp")
```

   Add `"onboard": _onboard` to the dispatch dict. The display name travels as one argv element; `Kanidm.create_person` passes it unchanged (no shell).

- [ ] **Step 4: Run.** `.venv/bin/python -m pytest tests/test_chp_site_ops.py tests/test_chp_site_cli.py -q`, then the whole suite. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 3b Task 4: chp-site onboard (idempotent checklist; never re-enables an expired account)"`

---

### Task 5: `chp-site revoke`

**Files:**
- Modify: `appliance/chp-site/chp_site/ops.py`, `appliance/chp-site/chp_site/cli.py`
- Test: `tests/test_chp_site_ops.py`

**Interfaces:**
- Consumes: `fanout.invalidate_all`, `fanout.report` (Task 3); `FakeK`, `Rec` (Task 4 tests).
- Produces:
  - `ops.revoke(k, ca, hosts, user, group=None, rec=audit.record, fan=fanout.invalidate_all, say=print)`. It raises `SiteError` when any cache clear failed, **after** the change is made and recorded.
  - CLI `chp-site revoke USER [--group G] [--as NAME] [--site DIR]`

- [ ] **Step 1: Failing tests** (append to `tests/test_chp_site_ops.py`):

```python
def people():
    return {"lab09": {"name": ["lab09"], "class": ["person", "posixaccount"], "directmemberof": ["lab_users@idm.x"]}}


def fan_ok(hosts):
    return [("srv (this server)", True, "not a Kanidm client yet: nothing cached")]


def test_revoke_user_expires_moves_key_audits_and_clears(ca, tmp_path):
    ca.register("lab09", keypair(tmp_path, "u9"))
    k, rec, fanned = FakeK(people()), Rec(), []
    ops.revoke(k, ca, [], "lab09", rec=rec, fan=lambda h: fanned.append(1) or fan_ok(h), say=lambda *_: None)
    assert k.log == [("expire", "lab09")] and ca.registered("lab09") is None and fanned == [1]
    assert [c[0] for c in rec.calls] == ["revoke", "revoke.done"] and rec.calls[0][1]["scope"] == "account"


def test_revoke_group_membership_only(ca):
    k = FakeK(people())
    ops.revoke(k, ca, [], "lab09", group="lab_users", rec=Rec(), fan=fan_ok, say=lambda *_: None)
    assert k.log == [("remove", "lab_users", "lab09")]


def test_revoke_group_not_a_direct_member_is_refused(ca):
    k = FakeK(people())
    with pytest.raises(SiteError, match="not a direct member of admins_x"):
        ops.revoke(k, ca, [], "lab09", group="admins_x", rec=Rec(), fan=fan_ok)
    assert k.log == []


@pytest.mark.parametrize("who", ["admin", "idm_admin", "alice"])
def test_revoke_refuses_builtins_and_yourself(ca, who):          # Review Focus 2
    k = FakeK({"alice": {"name": ["alice"], "class": ["person"], "directmemberof": []}}, as_="alice")
    with pytest.raises(SiteError, match="refusing"):
        ops.revoke(k, ca, [], who, rec=Rec(), fan=fan_ok)
    assert k.log == []


def test_revoke_unknown_person(ca):
    with pytest.raises(SiteError, match="no Kanidm person lab77"):
        ops.revoke(FakeK(people()), ca, [], "lab77", rec=Rec(), fan=fan_ok)


def test_revoke_with_an_unreachable_client_still_applies_and_says_so(ca):   # Review Focus 3
    k, rec = FakeK(people()), Rec()
    bad = lambda h: [("srv (this server)", True, "ok"), ("cli1", False, "timed out (host off or unreachable?)")]
    with pytest.raises(SiteError, match=r"the Kanidm change IS in effect.*cli1.*~2 min"):
        ops.revoke(k, ca, [], "lab09", rec=rec, fan=bad, say=lambda *_: None)
    assert k.log == [("expire", "lab09")] and [c[0] for c in rec.calls] == ["revoke", "revoke.done"]


def test_revoke_session_lost_midway_writes_no_done_record(ca):      # Review Focus 4
    class Dies(FakeK):
        def expire_now(self, n):
            raise SiteError("not logged in to Kanidm as idm_admin: run `kanidm login -D idm_admin` first")
    rec = Rec()
    with pytest.raises(SiteError, match="not logged in"):
        ops.revoke(Dies(people()), ca, [], "lab09", rec=rec, fan=fan_ok)
    assert [c[0] for c in rec.calls] == ["revoke"]
```

- [ ] **Step 2: Run to verify failure.** `.venv/bin/python -m pytest tests/test_chp_site_ops.py -q`. Expected: FAIL (`module 'chp_site.ops' has no attribute 'revoke'`).

- [ ] **Step 3: Implement** in `ops.py` (add `from . import fanout` to the imports):

```python
def revoke(k, ca, hosts, user, group=None, rec=audit.record, fan=fanout.invalidate_all, say=print):
    _user(user)
    if user == k.as_:
        raise SiteError(f"refusing: {user} is the Kanidm session you are using; revoking it locks out administration")
    if group is not None and not valid_name(group):
        raise SiteError(f"{group!r} is not a valid group name")
    e = k.person(user)
    if e is None:
        raise SiteError(f"no Kanidm person {user}")
    if group is not None and group not in {m.split("@")[0] for m in e.get("directmemberof", [])}:
        raise SiteError(f"{user} is not a direct member of {group} (membership through another group: revoke that one)")
    fields = {"user": user, "scope": f"group:{group}" if group else "account", "operator": audit.operator(), "as": k.as_}
    rec("revoke", fields)
    if group is not None:
        k.remove_member(group, user)
        say(f"removed {user} from {group}")
    else:
        k.expire_now(user)
        moved = ca.revoke_key(user, _stamp())
        say(f"{user}: account expired now" + ("; registered SSH key moved to /var/lib/ssh-ca/revoked/" if moved else ""))
    rec("revoke.done", fields, after=True)
    text, failed = fanout.report(fan(hosts))
    say(text)
    if failed:
        raise SiteError(f"the Kanidm change IS in effect, but {', '.join(failed)} may keep cached access for up to "
                        "~2 min (fix and re-run, or wait)")
```

   `cli.py`:

```python
def _revoke(a):
    from .ops import revoke
    _site, hosts, k, ca = _ops_env(a)
    revoke(k, ca, hosts, a.user, group=a.group)
```

```python
    v = sub.add_parser("revoke", help="expire a person now (or remove one group membership) and clear every client's cache")
    v.add_argument("user"); v.add_argument("--group")
    v.add_argument("--as", dest="as_", default="idm_admin"); v.add_argument("--site", default="/etc/chp")
```

   Add `"revoke": _revoke` to the dispatch.

- [ ] **Step 4: Run** the ops tests, then the whole suite. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 3b Task 5: chp-site revoke (expire + key out of service, or one group; cache fan-out; ISSO #28)"`

---

### Task 6: `chp-site unexpire`

**Files:**
- Modify: `appliance/chp-site/chp_site/ops.py`, `appliance/chp-site/chp_site/cli.py`
- Test: `tests/test_chp_site_ops.py`

**Interfaces:**
- Consumes: the site dict (`ISSO_NAME`, `UNEXPIRE_DELEGATES`), `FakeK`, `Rec`, `fan_ok`.
- Produces:
  - `ops.unexpire(k, ca, site, hosts, user, approver, reason, rec=audit.record, fan=fanout.invalidate_all, say=print)`
  - CLI `chp-site unexpire USER --approver NAME --reason TEXT [--as NAME] [--site DIR]`

- [ ] **Step 1: Failing tests:**

```python
SITE = {"ISSO_NAME": "Pat Isso", "UNEXPIRE_DELEGATES": ["Sam Deputy"]}


def expired_people():
    return {"lab04": {"name": ["lab04"], "class": ["person", "posixaccount"], "directmemberof": [],
                      "account_expire": ["2000-01-01T00:00:00Z"]}}


@pytest.mark.parametrize("approver", ["Pat Isso", "  pat isso ", "Sam Deputy"])
def test_unexpire_by_isso_or_delegate(ca, approver):
    k, rec = FakeK(expired_people()), Rec()
    ops.unexpire(k, ca, SITE, [], "lab04", approver, "expired by mistake on the wrong ticket", rec=rec, fan=fan_ok,
                 say=lambda *_: None)
    assert k.log == [("clear", "lab04")] and [c[0] for c in rec.calls] == ["unexpire", "unexpire.done"]
    assert rec.calls[0][1]["approver"] == approver.strip() and "wrong ticket" in rec.calls[0][1]["reason"]


def test_unexpire_refuses_anyone_else(ca):
    k, rec = FakeK(expired_people()), Rec()
    with pytest.raises(SiteError, match=r"not the ISSO \(Pat Isso\) or a delegate"):
        ops.unexpire(k, ca, SITE, [], "lab04", "Chris Admin", "please let me back in now", rec=rec, fan=fan_ok)
    assert k.log == [] and rec.calls == []


@pytest.mark.parametrize("reason", ["", "short", "x" * 301, "line one\nline two is here"])
def test_unexpire_needs_a_real_reason(ca, reason):
    with pytest.raises(SiteError, match="--reason"):
        ops.unexpire(FakeK(expired_people()), ca, SITE, [], "lab04", "Pat Isso", reason, rec=Rec(), fan=fan_ok)


def test_unexpire_not_expired_is_refused(ca):
    k = FakeK(people())
    with pytest.raises(SiteError, match="lab09 is not expired"):
        ops.unexpire(k, ca, SITE, [], "lab09", "Pat Isso", "expired by mistake on the wrong ticket", rec=Rec(), fan=fan_ok)
    assert k.log == []


def test_unexpire_reminds_that_the_ssh_key_was_revoked(ca):
    said = []
    ops.unexpire(FakeK(expired_people()), ca, SITE, [], "lab04", "Pat Isso", "expired by mistake on the wrong ticket",
                 rec=Rec(), fan=fan_ok, say=said.append)
    assert any("chp-site onboard lab04 --ssh-key" in s for s in said)


def test_unexpire_builtin_refused(ca):
    with pytest.raises(SiteError, match="built-in"):
        ops.unexpire(FakeK(), ca, SITE, [], "admin", "Pat Isso", "expired by mistake on the wrong ticket", rec=Rec())
```

- [ ] **Step 2: Run to verify failure.** Expected: FAIL (`no attribute 'unexpire'`).

- [ ] **Step 3: Implement** in `ops.py`:

```python
def unexpire(k, ca, site, hosts, user, approver, reason, rec=audit.record, fan=fanout.invalidate_all, say=print):
    """ISSO #32: only the ISSO or a delegate named in site.conf approves; approver + reason are audited; never automatic."""
    _user(user)
    names = [site["ISSO_NAME"], *site.get("UNEXPIRE_DELEGATES", [])]
    approver = (approver or "").strip()
    if approver.casefold() not in {n.strip().casefold() for n in names}:
        raise SiteError(f"refusing: {approver!r} is not the ISSO ({site['ISSO_NAME']}) or a delegate in UNEXPIRE_DELEGATES")
    reason = (reason or "").strip()
    if not 10 <= len(reason) <= 300 or any(ord(c) < 32 for c in reason):
        raise SiteError("--reason: 10 to 300 characters on one line, saying why the expiry was a mistake")
    e = k.person(user)
    if e is None:
        raise SiteError(f"no Kanidm person {user}")
    if not expired(e):
        raise SiteError(f"{user} is not expired; nothing to do")
    fields = {"user": user, "approver": approver, "reason": reason, "operator": audit.operator(), "as": k.as_}
    rec("unexpire", fields)
    k.clear_expiry(user)
    rec("unexpire.done", fields, after=True)
    say(f"{user}: expiry cleared (approved by {approver}; recorded in the audit log)")
    text, failed = fanout.report(fan(hosts))
    say(text)
    if failed:
        say(f"note: {', '.join(failed)} may refuse {user} for up to ~2 min (cached expiry)")
    if ca.registered(user) is None:
        say(f"{user} has no registered SSH key (revoke takes it out of service): "
            f"chp-site onboard {user} --ssh-key FILE")
```

   `cli.py`:

```python
def _unexpire(a):
    from .ops import unexpire
    site, hosts, k, ca = _ops_env(a)
    unexpire(k, ca, site, hosts, a.user, a.approver, a.reason)
```

```python
    u = sub.add_parser("unexpire", help="re-enable an expired person (ISSO or delegate approval, audited; ISSO #32)")
    u.add_argument("user"); u.add_argument("--approver", required=True); u.add_argument("--reason", required=True)
    u.add_argument("--as", dest="as_", default="idm_admin"); u.add_argument("--site", default="/etc/chp")
```

   Add `"unexpire": _unexpire` to the dispatch.

- [ ] **Step 4: Version and docs.**
  - Set `VERSION = "0.3.0"` in `chp_site/__init__.py`. In `chp-site.spec`, set `Version: 0.3.0`, `Release: 1.chp`, with a changelog entry.
  - Update the module docstring of `cli.py` to list every sub-command.
  - Add rows **39** (the revoke fan-out cache key: decision 1, Plan 4 installs the client half) and **40** (unexpire approval + audit record; onboard never re-enables) to `lab/iso-requirements.md`, in the table's existing style, with evidence "ISO Plan 3b".
- [ ] **Step 5: Run** the whole suite (expected: all pass) and commit: `git commit -m "ISO Plan 3b Task 6: chp-site unexpire (ISSO/delegate approval + reason, audited; ISSO #32); chp-site 0.3.0"`

---

### Task 7: Build the RPMs and sign repo 0.3.3 (the user's signing round)

- [ ] **Step 1: Build.** Run `appliance/chp-site/build-rpm.sh` (chp-site 0.3.0-1.chp) and `appliance/rpm/chp-identity-server/build-rpm.sh` (0.1.0-5.chp). `chp-base` is unchanged; reuse `0.1.0-3.chp`.
  Assemble `/data/chp-release/0.3.3/stage` from `PACKAGES.txt` (10 packages) with `assemble-repo.sh`.
  Check with `rpm -qp --queryformat '%{NAME}-%{VERSION}-%{RELEASE}\n'`. **The collector login retry from Plan 3a must be in 0.1.0-5**: `rpm2cpio … | cpio -i --to-stdout ./usr/libexec/chp/server-firstboot | grep -c 'retry the login'` must return ≥ 1.
- [ ] **Step 2: Signing round (protocol).**
  1. Tell the user in one line, and **wait for "ready"**.
  2. Start `sign-session.sh … sign-repo.sh … 0.3.3`.
  3. The moment it starts, `say "PIN dialog open. Eyes on the screen."`. While it runs, `say "Touch the key now."` every 20 seconds. At the end, `say "Signing finished."`.

  Expected: `REPO OK: 10 packages`, and `verify-repo.sh` passes against `trusted-keys.txt`. Serve the repo at `http://192.168.100.1:8080/chp/0.3.3/`.
- [ ] **Step 3: Commit** the release record `appliance/release/RELEASE-RECORD-0.3.3.md` (package list with NEVRA and SHA-256; no serials) with the message `ISO Plan 3b Task 7: signed repo 0.3.3 (chp-site 0.3.0, chp-identity-server 0.1.0-5)`.

---

### Task 8: Install proof on aero (the `ops` stage)

**Files:** modify `lab/iso3/prove.sh`, `lab/iso3/rootrun.exp`, `lab/iso3/PROOF-RECORD.md`, `lab/iso-requirements.md` (rows 39, 40 evidence).

- [ ] **Step 1: Harness changes.**
  - **`rootrun.exp` gets an optional second secret line.** After the root prompt, add:

```tcl
if {[gets stdin sec] > 0} {
  send "IFS= read -rs CHP_SECRET; export CHP_SECRET\r"
  after 300
  send -- "$sec\r"
  expect {
    -re {\]# } {}
    timeout { puts "RC=255 (no prompt after secret)"; exit 1 }
  }
}
```

    The secret never reaches argv or the log (`log_user 0` stays). `export` matters: the command runs in a child `bash`.
  - **New `lab/iso3/rs.sh`** (runs on aero as root; pushed to `/tmp/iso2/` in `prep`):

```bash
#!/bin/bash
# rs.sh STICK VM IP FIELD CMD_B64 (RUNS ON AERO, root): like Rt, plus a second secret, FIELD of the stick's
# KANIDM_ADMINS_JSON (escrow/<VM>-server.txt), available as "$CHP_SECRET" inside CMD. Secrets move over pipes only.
set -euo pipefail
STICK=$1 VM=$2 IP=$3 FIELD=$4 B=$5
root=$(bash /tmp/iso2/stick.sh escrow "$STICK" "$VM.txt" | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p')
sec=$(bash /tmp/iso2/stick.sh escrow "$STICK" "$VM-server.txt" | sed -n 's/^KANIDM_ADMINS_JSON=//p' \
      | python3 -c 'import base64,json,sys; print(json.loads(base64.b64decode(sys.stdin.read()))[sys.argv[1]])' "$FIELD")
printf '%s\n%s\n' "$root" "$sec" | expect /tmp/iso2/rootrun.exp "$IP" /tmp/iso2/iso2_chpadmin "$B"
```

    In `prove.sh`: `Rs() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n'); A "sudo bash /tmp/iso2/rs.sh $STICK $VM $IP $2 $b" | tr -d '\r' | sed '/^RC=/d'; }` (usage `Rs CMD FIELD`).
  - **Settings:** `CHP_REPO=0.3.3`. The `firstboot` marker check now expects `cache-key.done` too.
  - **`export` also checks:** `client.conf` on the stick has a `CACHE_PUBKEY=ecdsa-sha2-nistp384` line equal to `/var/lib/chp/cache-key/id_ecdsa.pub`; the key is `0600 root`, in a `0700` directory.
  - **Lab stand-in for the user:** copy `lab/srv1/enrol-user.exp` and `lab/srv1/totp.py` to `/root/chp-lab/` on the VM through `Rv`, with `/tmp/srv1/` rewritten to `/root/chp-lab/` (the CUI profile polyinstantiates `/tmp`).
- [ ] **Step 2: The `ops` stage** (after `export`; run as root through `Rs`/`Rv`; a lab public key made on the Mac at `~/idm-lab-secrets/iso3_lab09_ecdsa{,.pub}`, ECDSA P-384, never committed):
  1. `chp-site onboard lab09` **without a Kanidm session** fails with `run \`kanidm login -D idm_admin\` first`, and exits 2.
  2. Log in with `Rs 'printf "%s\n" "$CHP_SECRET" | expect /usr/libexec/chp/kanidm-login.exp idm_admin' idm_admin`.
  3. Run `chp-site onboard lab09 --display "Lab User 9" --ssh-key /root/chp-lab/lab09.pub`. Then check:
     - the checklist shows the account, POSIX, SSH key and certificate `[x]`, and the primary credential, unix password and GA `[ ]`
     - `/root/chp-onboard` is `0700`, the token file is `0600`, and **the token value is not in the stage output**
  4. **Lab stand-in for the user:** feed the token file's `use-reset-token` value + a generated password + a generated unix password + `totp` to `enrol-user.exp`. Everything goes over stdin; keep them in `~/idm-lab-secrets/iso3_lab09.json` on the Mac.
  5. Re-run `onboard lab09`. Every item is `[x]` except GA, and **no new token file** is written (compare its mtime).
  6. `ssh-keygen -L` on `/var/lib/ssh-ca/issued/lab09-cert.pub` shows principals `lab09` and `lab09@idm.iso3.lab.test`, valid about 8 h.
  7. `chp-site revoke idm_admin` is refused.
  8. `chp-site revoke lab09 --group nosuch` is refused.
  9. Run `chp-site revoke lab09`. Then check:
     - `kanidm person get lab09` shows `account_expire`
     - `/var/lib/ssh-ca/keys/lab09.pub` is gone and `revoked/lab09.pub.*` exists
     - the output contains `no clients in the hosts table`
  10. `chp-site onboard lab09` is refused (points to `unexpire`).
  11. `chp-site unexpire lab09 --approver "Chris Admin" --reason "…"` is refused.
  12. Run `chp-site unexpire lab09 --approver "<ISSO_NAME from site.conf.in>" --reason "expired by mistake in the Plan 3b proof"`. The expiry is cleared.
  13. `ausearch --input-logs -m USER </dev/null | grep -c 'chp-site unexpire'` returns **2**: the request and the `.done` record, each with the approver and reason.
      If `auditctl -m` is refused on the CUI profile (immutable rules, `-e 2`), stop. That is a finding for systematic-debugging: the design needs the audit record, and silently dropping it is not allowed.
  14. `journalctl -t chp-site` shows the same records.
  15. `kanidm logout -D idm_admin`.
  16. `ausearch -m AVC -ts boot` is 0, and fapolicyd FANOTIFY is 0.
- [ ] **Step 3: Run** the stages: `prep`, `server`, `firstboot`, `reboot`, `export`, `ops`, `cleanup` (skip `renew`; it is unchanged since 0.3.2). Poll the logs yourself every ≤ 10 min, and never wait silently. Every line must be PASS; for any FAIL, stop and use superpowers:systematic-debugging.
- [ ] **Step 4: `PROOF-RECORD.md`:** add a "Plan 3b" section with the results and findings, and fill the evidence for rows 39 and 40. State plainly that the **client fan-out is not proven here** (no clients until Plan 4).
- [ ] **Step 5: Tests, scans, commit.** The whole suite passes, and the pre-publication secrets scan of the branch diff is clean. Commit with the message `ISO Plan 3b Task 8: onboard / revoke / unexpire proven on a fresh server from repo 0.3.3`.

---

## Self-review (done while writing)

- **Spec coverage:**
  - §4.4 onboard (primary credential, POSIX password, GA per host, SSH key registered with the CA) → Task 4. GA is a checklist item the user completes on each client; the client role (Plan 4) enforces it.
  - §4.4 revoke + #28 → Tasks 3 and 5, with the client half in Plan 4.
  - §4.4 unexpire + #32 → Task 6.
  - §4.1 `ISSO_NAME` / `UNEXPIRE_DELEGATES` are already parsed (Plan 2) and are consumed in Task 6.
  - The carry-forward (collector login retry) → Task 7.
- **Plan 4 inputs this plan creates:**
  - the `chpcache` account, its `authorized_keys` line and sudoers rule (decision 1)
  - `client.conf CACHE_PUBKEY`
  - proving the fan-out on real clients, including a changed host key after a client reinstall
- **Type consistency:**
  - `Kanidm.as_` is used by `ops.revoke` (self-check) and the audit fields.
  - `fanout.report` returns `(text, failed)` and is used by revoke and unexpire.
  - `SshCa.registered/register/sign/revoke_key` are used by onboard, revoke and unexpire with the same signatures.
  - `make_client_conf` has 4 arguments everywhere after Task 3.
- **Known assumption to verify in Task 8 (not assumed):** `auditctl -m` works for root under the CUI profile's audit rules. If it does not, the design needs a different audit path; that is a user/ISSO decision, not a silent fallback.
