# ISO Plan 4b: The Second Factor (Google Authenticator) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On every installed host, a **Kanidm user** logs in with a second factor: a host-local Google Authenticator TOTP code. This covers SSH (certificate + code + Kanidm password), the console, `sudo` and the GDM login screen.
- Admins enrol users per host with an audited `chp-site ga-enrol`, which also issues 5 one-time scratch codes.
- Local break-glass accounts are exempt.
- A scripted PAM test of the `gdm-password` stack (row 36) proves the GUI path without a screen.

**Architecture:**
- **No new RPM.**
  - `chp-site` 0.5.0 gains: a GA PAM patch applied by the existing `authselect-patch` step; `ga-enrol USER [--reset]` (root, audited); and `pam-test SERVICE USER` (a stdlib `ctypes` PAM conversation, secrets on stdin).
  - `chp-identity-client` 0.2.0 requires `google-authenticator`, owns the token directory, and adds a GA monitor.
- **Token location:** `/var/lib/google-authenticator/<user>`, `root:root 0600`, read with `secret=… user=root`. **Rocky's policy already labels it `var_auth_t`.**
- Task 4 **measures on a real install** whether the stacks need any SELinux rule. A `chp_ga` module ships only if the evidence shows denials, and only for what was denied.

**Tech Stack:** Python 3.9 stdlib (`ctypes` against `libpam.so.0`), Linux-PAM, `pam_google_authenticator` (EPEL 1.09), authselect, OpenSSH 9.9, GDM (`gdm-password`), the lab harness `lab/iso4`.

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md`:
- §5.3 (GUI and login: `pam_kanidm` + `pam_google_authenticator`, no `nullok`, on `gdm-password`, `login`, `sshd`, `sudo`; tokens host-local; row 36)
- §2 #12 (`chp_ga`)

The ISSO decisions of 2026-09-28 (`lab/chp-findings.md` §8: one TOTP secret per user per host; host-local tokens in `/var/lib/google-authenticator/`).

Requirements: rows **11, 19, 36**.

## Decisions for this plan (user / ISSO, 2026-10-01)

1. **Enrolment: admin-assisted, at the host.**
   - A `chp_admins` member runs `sudo chp-site ga-enrol USER` on the host. The QR code and scratch codes appear on that terminal for the user, present in person. The action is audited (as `unexpire`).
   - **This is a testing expediency.** The production path, to be built once the server has mail, sends the user a **one-time, short-lived enrolment link** (not the QR image: the QR *is* the secret). Recorded as a POA&M / requirements note.
2. **GA applies to Kanidm users only.** Local accounts (root at the console, `chpadmin`, `diag`, `chpcache`) skip it via `pam_localuser`. Break-glass works without a phone, consistent with dc1 and the other CHP systems; recorded as an SSP deviation.
3. **Lost phone: 5 emergency scratch codes** per user per host, shown once at enrolment (the user keeps them safe). `ga-enrol --reset` remains the admin backup.

**My design choices (recorded; the spec leaves the mechanism open):**
- **PAM placement.** Two lines go into the `custom/kanidm` `system-auth` and `password-auth`, immediately before `pam_kanidm` (after `pam_faillock preauth`):
  ```
  auth        [success=1 default=ignore]                   pam_localuser.so
  auth        required                                     pam_google_authenticator.so secret=/var/lib/google-authenticator/${USER} user=root
  ```
  The prompt order is "Verification code" then "Password". A wrong code fails the stack after the password is asked (no oracle). `faillock authfail` counts it.
  - `system-auth` covers `login`, `sudo`, `su`; `password-auth` covers `sshd` and `gdm-password`.
  - The patch **refuses** if any earlier `auth` line has a numeric jump (none in the CUI stack), so no jump can be redirected by the insertion.
- **Token options** (the lab's, with scratch codes): `google-authenticator -t -d -f -r 3 -R 30 -w 3 -e 5`:
  - TOTP; a code can't be reused; at most 3 attempts per 30 s; ±1 window; 5 scratch codes
  - label `<user>@<host fqdn>`, issuer `CHP <domain>`
- **Bootstrap of the first admin on a host:** the first `chp_admins` user on a fresh host has no token there, so cannot SSH in or `sudo`. **root** enrols them (the console with the escrowed password, or `chpadmin` + `su -`). Every later enrolment is done by an enrolled admin with `sudo`. Documented and proven.
- **Row 36's GDM test** is `chp-site pam-test gdm-password USER`. It drives the real `gdm-password` stack through a PAM conversation (password + code on stdin), then checks the token file's label (the dc1 failure was a label flip on write).
- **Spec deviation (flagged):** the spec says the tokens are labelled `auth_home_t` and that `chp_ga` ships. The installed policy says `var_auth_t` for this path. We keep the policy's label, and `chp_ga` ships only if Task 4 shows denials.

## Global Constraints

- **All earlier constraints hold:**
  - secrets never go to logs, argv or the repo; the QR/scratch codes go **only** to the enrolling terminal (decision 1), never to a log or file other than the token itself
  - Python 3.9 stdlib only in `chp-site`
  - the branding header on shipped files
  - signing with the accessibility protocol (announce in one line, wait for "ready", `say` prompts)
  - nothing site-specific in RPMs
- **Paths and modes:**
  - token directory `/var/lib/google-authenticator` (0700 root)
  - token `/var/lib/google-authenticator/<user>` (0600 root:root, label `var_auth_t` from policy)
- **Users** `[a-z][a-z0-9_]{0,31}` (Kanidm short names); PAM services `[a-z0-9-]{1,32}`.
- **No `nullok` anywhere** (row 8: `without-nullok` stays). A Kanidm user without a token on a host cannot log in there.
- **Lab:** client installs stay **sequential** (one stick, one writer). The GA rate limit (3 per 30 s) and no-reuse rule mean the harness waits for a fresh 30-s window between logins of the same user on the same host.

## Review Focus

1. **A Kanidm user with no token on this host.** Expected: refused (no `nullok`), on every stack, with a journal line naming the missing file. Local accounts are unaffected.
2. **A wrong code, a replayed code, or a scratch code used twice.** Expected: refused; the password is still asked (no early "wrong code" signal); `faillock` counts the failure.
3. **`ga-enrol` for a local account, an unknown user, or a user who already has a token (without `--reset`).** Expected: refused before anything changes; no file is created or replaced; no `.done` audit record.
4. **After a GDM/sshd/sudo login the token file is rewritten** (rate-limit / replay state). Expected: still `root:root 0600` and `var_auth_t` (the dc1 label-flip lockout must not recur).
5. **The first admin on a fresh host.** Expected: enrolment works through root (console or `chpadmin` + `su -`) and is audited the same way. After it, that admin enrols others with `sudo`, and their own `sudo` asks for code + password.

---

## File structure

| File | Responsibility |
|---|---|
| `appliance/chp-site/chp_site/pamtest.py` (new) | `answer()` + `authenticate()` (ctypes PAM conversation) |
| `appliance/chp-site/chp_site/authselect_ga.py` (new) | `patch_ga(text)`, `main(dir)` |
| `appliance/chp-site/chp_site/ga.py` (new) | `enrol(...)`: token creation/reset, audit |
| `appliance/chp-site/chp_site/cli.py` | `pam-test`, `ga-enrol`; `authselect-patch` also applies the GA patch |
| `appliance/rpm/chp-identity-client/{chp-identity-client.spec,monitor.d/53-ga.sh}` | Requires GA, the token dir, the GA monitor |
| `lab/iso4/{prove.sh,ssh-ki.exp,PROOF-RECORD.md}` | the GA stages |

---

### Task 1: `chp-site pam-test` (the row-36 tool)

**Files:**
- Create: `appliance/chp-site/chp_site/pamtest.py`
- Modify: `cli.py`
- Test: `tests/test_chp_site_pamtest.py`

**Interfaces:**
- Produces:
  - `pamtest.answer(prompt: str, style: int, password: str, code: str|None) -> str|None`
  - `pamtest.authenticate(service, user, password, code, lib=None) -> (ok: bool, why: str, prompts: list[str])`
  - CLI `chp-site pam-test SERVICE USER` reads the password from stdin line 1 and the code from line 2 (optional). It prints `PAM_OK prompts=<p1>|<p2>` or `PAM_FAIL <why> prompts=…` and exits 0/1. It never prints a secret.

- [ ] **Step 1: Failing tests**

```python
import subprocess
import sys
from pathlib import Path

import pytest

from chp_site.pamtest import ECHO_OFF, ECHO_ON, ERROR_MSG, TEXT_INFO, answer

PKG = Path(__file__).resolve().parents[1] / "appliance" / "chp-site"


@pytest.mark.parametrize("prompt,style,want", [
    ("Verification code: ", ECHO_OFF, "123456"),
    ("Password: ", ECHO_OFF, "pw"),
    ("One-time code: ", ECHO_ON, "123456"),
    ("Login incorrect", ERROR_MSG, None),
    ("Welcome", TEXT_INFO, None),
])
def test_answer_picks_the_right_secret(prompt, style, want):
    assert answer(prompt, style, "pw", "123456") == want


def test_answer_without_a_code_never_sends_the_password_as_a_code():
    assert answer("Verification code: ", ECHO_OFF, "pw", None) == ""


def cli(*a, stdin=""):
    return subprocess.run([sys.executable, "-m", "chp_site.cli", "pam-test", *a], cwd=PKG, input=stdin,
                          capture_output=True, text=True)


@pytest.mark.parametrize("args", [("gdm password", "alice"), ("gdm-password", "Alice"), ("../etc", "alice")])
def test_bad_service_or_user_refused(args):
    r = cli(*args, stdin="pw\n")
    assert r.returncode == 2 and "not a valid" in r.stderr


def test_secrets_never_echoed(monkeypatch):
    from chp_site import cli as c, pamtest
    monkeypatch.setattr(pamtest, "authenticate", lambda *a, **k: (False, "Authentication failure", ["Verification code: ", "Password: "]))
    import io
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO("s3cretPW\n654321\n")); monkeypatch.setattr(sys, "stdout", out)
    assert c.main(["pam-test", "gdm-password", "alice"]) == 1
    o = out.getvalue()
    assert "PAM_FAIL Authentication failure" in o and "s3cretPW" not in o and "654321" not in o
    assert "prompts=Verification code:|Password:" in o
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_chp_site_pamtest.py -q`. Expected: FAIL (`No module named 'chp_site.pamtest'`).

- [ ] **Step 3: Implement** `pamtest.py`:

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Authenticate a user through a real PAM stack (row 36: the gdm-password stack, without a screen). A ctypes conversation
answers the module prompts: the TOTP code for a verification-code prompt, the password otherwise. Linux-PAM semantics
(an array of message pointers). Run as root (pam_google_authenticator user=root, pam_kanidm via unixd)."""
import ctypes
import ctypes.util
import re

ECHO_OFF, ECHO_ON, ERROR_MSG, TEXT_INFO = 1, 2, 3, 4
_CODE = re.compile(r"verification code|one-time|token|otp", re.I)


def answer(prompt, style, password, code):
    if style not in (ECHO_OFF, ECHO_ON):
        return None
    if _CODE.search(prompt or ""):
        return code if code is not None else ""
    return password


class _Msg(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _Resp(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_Msg)),
                         ctypes.POINTER(ctypes.POINTER(_Resp)), ctypes.c_void_p)


class _Conv(ctypes.Structure):
    _fields_ = [("conv", _CONV), ("appdata_ptr", ctypes.c_void_p)]


def authenticate(service, user, password, code, lib=None):
    pam = lib or ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.calloc.restype, libc.calloc.argtypes = ctypes.c_void_p, [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype, libc.strdup.argtypes = ctypes.c_void_p, [ctypes.c_char_p]
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_Conv), ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_authenticate.argtypes = pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_strerror.restype, pam.pam_strerror.argtypes = ctypes.c_char_p, [ctypes.c_void_p, ctypes.c_int]
    prompts = []

    def conv(n, msgs, resp, _data):
        arr = libc.calloc(n, ctypes.sizeof(_Resp))
        if not arr:
            return 5                                   # PAM_BUF_ERR
        r = ctypes.cast(arr, ctypes.POINTER(_Resp))
        for i in range(n):
            m = msgs[i].contents
            p = (m.msg or b"").decode(errors="replace")
            prompts.append(p.strip())
            a = answer(p, m.msg_style, password, code)
            if a is not None:
                r[i].resp = libc.strdup(a.encode())     # PAM frees these with free()
        resp[0] = r
        return 0

    cb = _CONV(conv)
    conv_struct = _Conv(cb, None)
    h = ctypes.c_void_p()
    rc = pam.pam_start(service.encode(), user.encode(), ctypes.byref(conv_struct), ctypes.byref(h))
    if rc != 0:
        return False, f"pam_start failed ({rc})", prompts
    try:
        rc = pam.pam_authenticate(h, 0)
        if rc == 0:
            rc = pam.pam_acct_mgmt(h, 0)
        return rc == 0, ("ok" if rc == 0 else pam.pam_strerror(h, rc).decode(errors="replace")), prompts
    finally:
        pam.pam_end(h, rc)
```

   In `cli.py`:

```python
def _pam_test(a):
    import re as _re
    from . import pamtest
    from .kanidm import valid_name
    if not _re.fullmatch(r"[a-z0-9-]{1,32}", a.service):
        raise SiteError(f"{a.service!r} is not a valid PAM service name")
    if not valid_name(a.user):
        raise SiteError(f"{a.user!r} is not a valid user name")
    lines = sys.stdin.read().splitlines()
    pw, code = (lines + ["", ""])[0], (lines[1] if len(lines) > 1 and lines[1] else None)
    ok, why, prompts = pamtest.authenticate(a.service, a.user, pw, code)
    print(("PAM_OK" if ok else f"PAM_FAIL {why}") + " prompts=" + "|".join(prompts))
    return 0 if ok else 1
```

   Sub-parser: `pt = sub.add_parser("pam-test", help="authenticate USER through PAM service SERVICE (secrets on stdin; root)"); pt.add_argument("service"); pt.add_argument("user")`. Dispatch: `"pam-test": _pam_test`. In `main`, use a handler's integer return value as the exit code: `rc = {...}[a.cmd](a); return rc if isinstance(rc, int) else 0`.
- [ ] **Step 4: Run** the file (expected: all pass), then the whole suite.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4b Task 1: chp-site pam-test (ctypes PAM conversation; row 36 tool)"`

---

### Task 2: The GA PAM patch (`authselect_ga.py`), applied by `authselect-patch`

**Files:**
- Create: `appliance/chp-site/chp_site/authselect_ga.py`
- Modify: `cli.py` (`_authselect_patch`)
- Test: `tests/test_chp_site_authselect_ga.py`

**Interfaces:**
- Produces:
  - `authselect_ga.GA_LINES` (the two lines)
  - `authselect_ga.patch_ga(text) -> str` (raises `SiteError` with no `pam_kanidm` auth line, or when an earlier auth line has a numeric jump)
  - `authselect_ga.main(dir)` (patches `system-auth` and `password-auth`)
  - `chp-site authselect-patch DIR` applies the Kanidm patch, then the GA patch

- [ ] **Step 1: Failing tests** (the CUI stack is the one captured on lab client2, 2026-10-01):

```python
import pytest

from chp_site.authselect_ga import GA_LINES, patch_ga
from chp_site.sitefile import SiteError

CUI = """auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        required                                     pam_faillock.so preauth silent                         {include if "with-faillock"}
auth        sufficient                                   pam_kanidm.so ignore_unknown_user
auth        sufficient                                   pam_unix.so {if not "without-nullok":nullok}
auth        required                                     pam_faillock.so authfail                               {include if "with-faillock"}
auth        required                                     pam_deny.so
account     sufficient                                   pam_kanidm.so ignore_unknown_user
"""


def test_ga_goes_right_before_pam_kanidm_after_faillock_preauth():
    out = patch_ga(CUI).splitlines()
    i = next(n for n, l in enumerate(out) if "pam_kanidm.so" in l and l.startswith("auth"))
    assert out[i - 2] == GA_LINES[0] and out[i - 1] == GA_LINES[1]
    assert "preauth" in out[i - 3]


def test_local_users_skip_exactly_the_ga_line():
    out = patch_ga(CUI).splitlines()
    j = out.index(GA_LINES[0])
    assert "[success=1 default=ignore]" in out[j] and "pam_localuser.so" in out[j]
    assert "pam_google_authenticator.so" in out[j + 1] and "pam_kanidm.so" in out[j + 2]


def test_no_nullok_and_tokens_read_as_root_from_var_lib():
    ga = GA_LINES[1]
    assert "nullok" not in ga and "secret=/var/lib/google-authenticator/${USER}" in ga and "user=root" in ga
    assert "no_strict_owner" not in ga and "allowed_perm" not in ga


def test_idempotent():
    once = patch_ga(CUI)
    assert patch_ga(once) == once


def test_refuses_without_pam_kanidm():
    with pytest.raises(SiteError, match="pam_kanidm"):
        patch_ga("auth required pam_unix.so\n")


def test_refuses_when_an_earlier_line_jumps():
    text = "auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n" + CUI
    with pytest.raises(SiteError, match="jump"):
        patch_ga(text)
```

   Add to `tests/test_chp_site_cli.py`: after `authselect-patch`, the `system-auth` of the test profile contains `GA_LINES[1]` exactly once, **before** the `pam_kanidm` auth line. Use the existing `test_authselect_patch_subcommand` fixture, and add `pam_faillock preauth` to its input.
- [ ] **Step 2: Run.** Expected: FAIL (no module).
- [ ] **Step 3: Implement** `authselect_ga.py`:

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The second factor in the custom/kanidm profile (spec 5.3; ISSO 2026-09-28 #1/#3; 2026-10-01 #2): Kanidm users must
give a host-local Google Authenticator code; LOCAL accounts (root, chpadmin, diag, chpcache) skip it (break-glass).
The two lines go immediately before pam_kanidm. Refused if an earlier auth line has a numeric jump (none in the CUI
stack): inserting lines under a jump would change what it skips."""
import re
from pathlib import Path

from .sitefile import SiteError

GA_LINES = (
    "auth        [success=1 default=ignore]                   pam_localuser.so",
    "auth        required                                     pam_google_authenticator.so "
    "secret=/var/lib/google-authenticator/${USER} user=root",
)


def _auth(line):
    return line.split(None, 1)[:1] == ["auth"]


def patch_ga(text):
    if "pam_google_authenticator" in text:
        return text
    lines = text.splitlines()
    i = next((n for n, l in enumerate(lines) if _auth(l) and "pam_kanidm.so" in l), None)
    if i is None:
        raise SiteError("no pam_kanidm auth line: apply the Kanidm patch first")
    for l in lines[:i]:
        if _auth(l) and re.search(r"\[[^\]]*=\d+", l):
            raise SiteError(f"an earlier auth line has a numeric jump ({l.split()[1]}): not inserting the GA lines")
    out = lines[:i] + list(GA_LINES) + lines[i:]
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def main(profile_dir):
    d = Path(profile_dir)
    for name in ("system-auth", "password-auth"):
        p = d / name
        p.write_text(patch_ga(p.read_text()))
```

   In `cli._authselect_patch`, after the Kanidm `patch(a.dir)`: `from .authselect_ga import main as ga; ga(a.dir)`. Then update the printed message to mention the GA step.
- [ ] **Step 4: Run** the files and the whole suite (the `pam_kanidm` jump-safety property test in `test_pam_patch.py` still passes: no jump reaches across the inserted lines).
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4b Task 2: GA PAM lines before pam_kanidm (local users skip; no nullok; tokens in /var/lib as root)"`

---

### Task 3: `chp-site ga-enrol USER [--reset]`

**Files:**
- Create: `appliance/chp-site/chp_site/ga.py`
- Modify: `cli.py`
- Test: `tests/test_chp_site_ga.py`

**Interfaces:**
- Consumes: `audit.record`, `audit.operator`, `kanidm.valid_name`, `escrow._shred`.
- Produces:
  - `ga.TOKDIR = Path("/var/lib/google-authenticator")`
  - `ga.enrol(user, fqdn, domain, reset=False, tokdir=TOKDIR, passwd=Path("/etc/passwd"), resolves=<getent>, run=subprocess.run, chown=os.chown, rec=audit.record) -> Path`
  - CLI `chp-site ga-enrol USER [--reset]`: root only; the QR and scratch codes go to the terminal only

- [ ] **Step 1: Failing tests**

```python
import types

import pytest

from chp_site import ga
from chp_site.sitefile import SiteError


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, action, fields, after=False):
        self.calls.append((action, dict(fields), after))


def fake_ga(cmds):
    def run(argv, **kw):
        cmds.append(argv)
        if argv[0] == "google-authenticator":
            p = argv[argv.index("-s") + 1]
            open(p, "w").write("SECRETBASE32\n\" TOTP_AUTH\n12345678\n")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def env(tmp_path, local=("root", "chpadmin")):
    pw = tmp_path / "passwd"; pw.write_text("".join(f"{u}:x:0:0::/:/bin/bash\n" for u in local))
    return dict(tokdir=tmp_path / "ga", passwd=pw, resolves=lambda u: u in ("alice", "chpadmin", "root"),
                chown=lambda *a: None)


def test_enrol_creates_a_root_0600_token_with_the_chosen_options(tmp_path):
    cmds, rec = [], Rec()
    p = ga.enrol("alice", "cli1.x.test", "x.test", run=fake_ga(cmds), rec=rec, **env(tmp_path))
    assert p == tmp_path / "ga" / "alice" and oct(p.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "ga").stat().st_mode & 0o777) == "0o700"
    g = cmds[0]
    for opt in (["-t"], ["-d"], ["-f"], ["-r", "3"], ["-R", "30"], ["-w", "3"], ["-e", "5"], ["-l", "alice@cli1.x.test"],
                ["-i", "CHP x.test"], ["-Q", "UTF8"]):
        assert any(g[i:i + len(opt)] == opt for i in range(len(g))), opt
    assert ["restorecon", str(p)] in cmds
    assert [c[0] for c in rec.calls] == ["ga-enrol", "ga-enrol.done"] and rec.calls[0][1]["reset"] == "no"


@pytest.mark.parametrize("user,why", [("chpadmin", "local account"), ("root", "local account"),
                                      ("bob", "does not resolve"), ("Bad", "not a valid")])
def test_refusals_change_nothing(tmp_path, user, why):                      # Review Focus 3
    cmds, rec = [], Rec()
    with pytest.raises(SiteError, match=why):
        ga.enrol(user, "h.x.test", "x.test", run=fake_ga(cmds), rec=rec, **env(tmp_path))
    assert cmds == [] and rec.calls == [] and not (tmp_path / "ga").exists()


def test_existing_token_needs_reset(tmp_path):
    e = env(tmp_path); cmds, rec = [], Rec()
    ga.enrol("alice", "h.x.test", "x.test", run=fake_ga(cmds), rec=Rec(), **e)
    before = (tmp_path / "ga" / "alice").read_text()
    with pytest.raises(SiteError, match="--reset"):
        ga.enrol("alice", "h.x.test", "x.test", run=fake_ga(cmds), rec=rec, **e)
    assert (tmp_path / "ga" / "alice").read_text() == before and rec.calls == []
    ga.enrol("alice", "h.x.test", "x.test", reset=True, run=fake_ga(cmds), rec=rec, **e)
    assert [c[1]["reset"] for c in rec.calls] == ["yes", "yes"]
    assert not list((tmp_path / "ga").glob(".alice*"))                     # no temp file left


def test_failed_generator_keeps_the_old_token(tmp_path):
    e = env(tmp_path)
    ga.enrol("alice", "h.x.test", "x.test", run=fake_ga([]), rec=Rec(), **e)
    before = (tmp_path / "ga" / "alice").read_text()
    bad = lambda argv, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="boom")
    rec = Rec()
    with pytest.raises(SiteError, match="google-authenticator failed"):
        ga.enrol("alice", "h.x.test", "x.test", reset=True, run=bad, rec=rec, **e)
    assert (tmp_path / "ga" / "alice").read_text() == before and [c[0] for c in rec.calls] == ["ga-enrol"]
```

- [ ] **Step 2: Run.** Expected: FAIL (no module).
- [ ] **Step 3: Implement** `ga.py`:

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site ga-enrol: a host-local Google Authenticator token for a KANIDM user (ISSO 2026-09-28 #1/#3; 2026-10-01 #1-#3).
Run as root on the host (sudo by an enrolled chp_admins member; root itself for the host's first admin). The QR code
and the 5 scratch codes are printed to THIS terminal only, for the user present (decision 1: a testing expediency;
production = a one-time enrolment link by mail). Local accounts never get a token (decision 2)."""
import os
import subprocess
from pathlib import Path

from . import audit
from .escrow import _shred
from .kanidm import valid_name
from .sitefile import SiteError

TOKDIR = Path("/var/lib/google-authenticator")


def _resolves(user):
    return subprocess.run(["getent", "passwd", user], capture_output=True).returncode == 0


def _local(user, passwd):
    try:
        return any(l.split(":", 1)[0] == user for l in Path(passwd).read_text().splitlines())
    except OSError:
        return False


def enrol(user, fqdn, domain, reset=False, tokdir=TOKDIR, passwd=Path("/etc/passwd"), resolves=_resolves,
          run=subprocess.run, chown=os.chown, rec=audit.record):
    if not valid_name(user):
        raise SiteError(f"{user!r} is not a valid user name")
    if _local(user, passwd):
        raise SiteError(f"{user} is a local account: local accounts do not use Google Authenticator (break-glass)")
    if not resolves(user):
        raise SiteError(f"{user} does not resolve on this host (not a Kanidm user, or kanidm-unixd is offline)")
    tokdir = Path(tokdir); p = tokdir / user
    if p.exists() and not reset:
        raise SiteError(f"{user} already has a token on this host; pass --reset to replace it (the old one stops working)")
    fields = {"user": user, "host": fqdn, "reset": "yes" if reset else "no", "operator": audit.operator()}
    rec("ga-enrol", fields)
    tokdir.mkdir(mode=0o700, parents=True, exist_ok=True); os.chmod(tokdir, 0o700)
    tmp = tokdir / f".{user}.new"
    if tmp.exists():
        tmp.unlink()
    r = run(["google-authenticator", "-t", "-d", "-f", "-r", "3", "-R", "30", "-w", "3", "-e", "5",
             "-l", f"{user}@{fqdn}", "-i", f"CHP {domain}", "-Q", "UTF8", "-s", str(tmp)])
    if r.returncode != 0 or not tmp.exists():
        if tmp.exists():
            _shred(tmp)
        raise SiteError(f"google-authenticator failed (exit {r.returncode}); the existing token, if any, is unchanged")
    os.chmod(tmp, 0o600); chown(str(tmp), 0, 0)
    if p.exists():
        _shred(p)
    os.replace(tmp, p)
    run(["restorecon", str(p)])
    rec("ga-enrol.done", fields, after=True)
    return p
```

   `cli.py`:

```python
def _ga_enrol(a):
    import socket
    from .ga import enrol
    if os.geteuid() != 0:
        raise SiteError("run as root: sudo chp-site ga-enrol USER")
    site = parse_site(read_file(Path(a.site) / "site.conf", "site.conf"))
    p = enrol(a.user, socket.getfqdn(), site["DOMAIN"], reset=a.reset)
    print(f"\nGoogle Authenticator token for {a.user} on {socket.getfqdn()} saved ({p}). The user scans the QR code above "
          "and keeps the 5 emergency scratch codes somewhere safe; each works once.")
```

   Sub-parser: `ge = sub.add_parser("ga-enrol", help="host-local Google Authenticator token for a Kanidm user (root; audited)"); ge.add_argument("user"); ge.add_argument("--reset", action="store_true"); ge.add_argument("--site", default="/etc/chp")`. Dispatch: `"ga-enrol": _ga_enrol`. `google-authenticator` inherits the terminal (no `capture_output`), so the QR goes only to the operator's screen.
- [ ] **Step 4: Run** the file and the whole suite.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4b Task 3: chp-site ga-enrol (host-local token, 5 scratch codes, --reset, audited; local accounts refused)"`

---

### Task 4: Measure on a real install: do the GA stacks need any SELinux rule? (a lab spike, decides `chp_ga`)

**Files:**
- Create: `lab/iso4/ga-measure.sh`
- Write: the "Plan 4b Task 4" section of `lab/iso4/PROOF-RECORD.md`

**Decision rule (stated before measuring):**
- **0 AVCs** for every stack → no `chp_ga` module. The policy's `var_auth_t` suffices, and the spec's `auth_home_t`/`chp_ga` is superseded (a ruling).
- **Any AVC** naming `/var/lib/google-authenticator` → `chp_ga.te` allows **exactly** the denied permissions for **exactly** the denied source domains on `var_auth_t`. It is re-measured to 0 before Task 5.

- [ ] **Step 1: Hosts.** Fresh `iso4-srv` + `iso4-cli1` from the **signed 0.4.1** repo (`prove.sh prep server firstboot reboot export client1`; sequential).
- [ ] **Step 2: Hand-apply the 4b changes** (lab only), on `iso4-cli1` as root, with the dev-built `chp-site.pyz` (a plain zip, so fapolicyd allows `python3 chp-site.pyz`):
  1. `dnf -y install google-authenticator` (from the chp repo)
  2. `install -d -m 0700 /var/lib/google-authenticator && restorecon -R /var/lib/google-authenticator`
  3. re-run the authselect step: `python3 /root/chp-site.pyz authselect-patch /etc/authselect/custom/kanidm` after restoring the original files, i.e. `client-enrol --step authselect` with `chp-site` pointing at the dev pyz through a temporary `/usr/local/bin/chp-site` wrapper (removed afterwards)
  4. onboard a test user on the server (as in Plan 4a ops)
  5. `python3 /root/chp-site.pyz ga-enrol <user> > /dev/null`. **In the lab the QR and scratch codes are discarded:** the stand-in for the user's phone reads the secret (line 1) and the scratch codes (the 8-digit lines) from the token file as root, so no secret reaches the harness output
- [ ] **Step 3: Exercise every stack, AVC baseline first:**
  - **sshd:** `ssh-ki.exp` with key + certificate + code + password → `LOGIN_OK`
  - **gdm-password:** `python3 chp-site.pyz pam-test gdm-password <user>` (password + code on stdin) → `PAM_OK`, prompts include a verification-code prompt
  - **login:** `pam-test login <user>` → `PAM_OK`
  - **sudo** for a `chp_admins` user: `ssh-ki.exp` MODE sudo → `LOGIN_OK SUDO_OK`
  - **a local account:** `pam-test login root` with the escrowed root password and **no code** → `PAM_OK`, and prompts contain no verification-code prompt
  - after each: `ausearch -m AVC -ts <baseline>`, and the token file is still `root:root 0600 var_auth_t`
- [ ] **Step 4: Apply the decision rule.** Record the AVC lines (or "0") per stack in `PROOF-RECORD.md`. If any appear, write `appliance/rpm/chp-identity-client/selinux/chp_ga.te`/`.fc` from them (the build's CIL check applies), load it on the VM, and repeat Step 3 to 0.
- [ ] **Step 5: Clean up** the VMs (`prove.sh cleanup`). Commit the script and the record: `git commit -m "ISO Plan 4b Task 4: GA stacks measured on an installed client (SELinux: <result>)"`.

---

### Task 5: `chp-identity-client` 0.2.0: Requires GA, owns the token dir, GA monitor (+ `chp_ga` only if Task 4 found denials)

**Files:**
- Modify: `appliance/rpm/chp-identity-client/chp-identity-client.spec`, `build-rpm.sh`
- Create: `monitor.d/53-ga.sh`
- Test: `tests/test_client_role_static.py`

- [ ] **Step 1: Failing tests:**

```python
def test_client_rpm_carries_the_second_factor():
    s = text("chp-identity-client.spec")
    assert re.search(r"^Requires:\s+.*\bgoogle-authenticator\b", s, re.M)
    assert re.search(r"^Requires:\s+.*\bchp-site >= 0\.5\.0", s, re.M)
    assert "%dir %attr(0700,root,root) %{_sharedstatedir}/google-authenticator" in s
    assert "53-ga.sh" in s and "Version:        0.2.0" in s


def test_ga_monitor():
    m = text("monitor.d/53-ga.sh")
    assert m.startswith("#!/bin/bash\n# CyberHygiene") and "ALERT " in m and "OK " in m
    assert "pam_google_authenticator.so" in m and "/etc/pam.d/system-auth" in m and "/etc/pam.d/password-auth" in m
    assert "stat -c" in m and "600 root root" in m and "700 root root" in m
    assert "restorecon -nRv /var/lib/google-authenticator" in m
    assert subprocess.run(["bash", "-n", str(C / "monitor.d/53-ga.sh")]).returncode == 0
```

- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - **The spec** goes to `Version: 0.2.0`, `Release: 1.chp`, with:
    - `Requires: google-authenticator, chp-site >= 0.5.0`
    - `%dir %attr(0700,root,root) %{_sharedstatedir}/google-authenticator` (plus the matching `install -d` in `%install`)
    - `Source15: 53-ga.sh` installed to `monitor.d`
    - a changelog entry
    - if Task 4 produced `chp_ga`: a second `.pp` Source, `semodule -i` in `%post` and `-r` in `%postun`, compiled and CIL-checked in `build-rpm.sh` like `chp_kanidm`
  - **`53-ga.sh`:**
    - if `client.done` is absent → `OK GA (not enrolled yet)`
    - the GA line is in both `/etc/pam.d/system-auth` and `/etc/pam.d/password-auth`
    - the directory is `700 root root`
    - every token is `600 root root`
    - `restorecon -nRv /var/lib/google-authenticator` prints nothing
    - otherwise `ALERT GA: …`, naming the first problem
- [ ] **Step 4: Run** the suite, build on aero (`bash appliance/rpm/chp-identity-client/build-rpm.sh`: the file list contains the dir and `53-ga.sh`).
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4b Task 5: chp-identity-client 0.2.0 (google-authenticator, token dir, GA monitor)"`

---

### Task 6: Build and sign repo 0.5.0 (the user's signing round)

- [ ] **Step 1: Build and assemble.**
  - Bump `chp-site` to 0.5.0 (`__init__.VERSION`, spec + changelog, CLI version test).
  - Build `chp-site` and `chp-identity-client`.
  - Assemble `/data/chp-release/0.5.0/stage` (11 packages; third-party dir `/data/chp-release/0.4.1/stage`).
- [ ] **Step 2: Signing round** (the protocol: one-line announce, **wait for "ready"**, `say` prompts). Expected: `REPO OK: 11 packages`.
- [ ] **Step 3: Publish** to `/data/lab-inputs/chp/0.5.0`, and write `appliance/release/RELEASE-RECORD-0.5.0.md`.
- [ ] **Step 4: Commit.** `git commit -m "ISO Plan 4b Task 6: signed repo 0.5.0 (chp-site 0.5.0, chp-identity-client 0.2.0)"`

---

### Task 7: Install proof on aero: a server and two clients with the second factor

**Files:** modify `lab/iso4/prove.sh` (`CHP_REPO=0.5.0`; new stage `ga`), `lab/iso4/ssh-ki.exp` (answers a verification-code prompt), `lab/iso4/PROOF-RECORD.md`, `lab/iso-requirements.md`.

- [ ] **Step 1: Harness.**
  - **`ssh-ki.exp`** takes an optional 6th argument, `SECRET_FILE` (root-only on aero). On a `[Vv]erification code` prompt it sends `exec python3 /tmp/iso2/totp.py - sha1 < SECRET_FILE`.
  - **`prove.sh`:**
    - a helper `fresh_window` sleeps until the next 30-s TOTP window, so no code is reused (`-d`) and the rate limit is respected
    - a helper `gasecret HOST VM USER` copies the first line of `/var/lib/google-authenticator/USER` (the base32 secret; **lab stand-in for the user's phone**) through the root channel into `/tmp/iso2/<host>-<user>.ga` (0600 root on aero)
    - `prep` also copies `lab/srv1/totp.py` to `/tmp/iso2/`
- [ ] **Step 2: Stages** `prep server firstboot reboot export client1 client2` (as Plan 4a, all PASS on 0.5.0; client installs sequential), then **`ga`**:
  1. **Bootstrap (Review Focus 5):** onboard admin `A` (`--group chp_admins`) and users `U`, `V`. On the server, **root** (the `Rv` channel) runs `chp-site ga-enrol A`. `A` logs in to the server with certificate + code + password → `LOGIN_OK`; `sudo` → `LOGIN_OK SUDO_OK`.
  2. **Admin enrols a user over SSH with sudo:** root bootstraps `A` on `iso4-cli1` (as on the server). Then `A` logs in there and runs `sudo -S -p SUDOPW: chp-site ga-enrol U > /dev/null && echo RESULT=ENROLLED`. This is `ssh-ki.exp` MODE `enrol`: sudo's own GA prompt is answered with `A`'s code and `SUDOPW:` with `A`'s password; the QR goes to `/dev/null` in the lab. **The audit log on `iso4-cli1` shows `ga-enrol user="U" … operator="A"`.**
  3. **Logins:**
     - `U` on `iso4-cli1` with certificate + code + password → `LOGIN_OK`
     - the same code again in the same window → `LOGIN_REFUSED` (no reuse)
     - a wrong code → `LOGIN_REFUSED`, and the password was still asked (the prompt sequence is recorded)
  4. **No token on that host:** `U` on `iso4-cli2` (no token there) → `LOGIN_REFUSED`; root enrols `U` on `iso4-cli2` → `LOGIN_OK` (host-local tokens).
  5. **Scratch code:** `U` logs in with scratch code #1 → `LOGIN_OK`; the same scratch code again → `LOGIN_REFUSED`.
  6. **gdm-password (row 36):** `chp-site pam-test gdm-password U` on `iso4-cli1` → `PAM_OK` with a verification-code prompt, then the token is `600 root root var_auth_t`. The same for `pam-test login U` and `pam-test sudo A`.
  7. **Local accounts exempt:**
     - `pam-test login root` (escrowed password, no code) → `PAM_OK` with no code prompt
     - `chpadmin` key-only SSH on all hosts → ok
     - diag report from a client → ok
     - the revoke fan-out (`chpcache`) → `ok` for both clients
  8. **ga-enrol refusals:** `chp-site ga-enrol chpadmin` → refused (local); an unknown user → refused; `ga-enrol U` again without `--reset` → refused; with `--reset` → new token, and the old secret no longer works.
  9. **Monitors quiet**, 0 AVC and 0 fapolicyd on all three hosts.
- [ ] **Step 3: `cleanup`.** Update `PROOF-RECORD.md`. In `lab/iso-requirements.md`:
  - update row 11 (the location `var_auth_t`, read as root)
  - add row 36 evidence
  - add rows **42** (GA enrolment workflow: admin-assisted now; one-time enrolment link by mail = POA&M) and **43** (5 scratch codes + admin `--reset`; local accounts exempt = SSP deviation)
- [ ] **Step 4:** Run the suite and the pre-publication scan. Commit with the message `ISO Plan 4b Task 7: second factor proven — server + 2 clients from repo 0.5.0 (sshd/login/sudo/gdm-password, scratch codes, local break-glass exempt)`.

---

## Self-review (done while writing)

- **Spec §5.3 coverage:**
  - GA on `gdm-password`, `login`, `sshd`, `sudo` (no `nullok`) → Tasks 2, 7
  - tokens host-local in `/var/lib/google-authenticator` → Tasks 3, 5
  - the label question (spec `auth_home_t`) → decided by evidence in Task 4 (policy `var_auth_t`)
  - row 36 (the scripted `gdm-password` test + the label afterwards) → Tasks 1, 7
  - #12 `chp_ga` → Task 4 decides; Task 5 ships it only if needed
- **The ISSO decisions** (2026-09-28 #1, #3; 2026-10-01 #1–#3) → Tasks 2, 3, 7 and the requirements rows 42, 43.
- **Type consistency:**
  - `GA_LINES` (Task 2) is used by the tests and checked by the monitor (Task 5) through the module name
  - `ga.enrol` keywords match the CLI and the tests
  - `pam-test` output (`PAM_OK` / `PAM_FAIL … prompts=…`) is consumed by Tasks 4 and 7
- **Assumptions verified on hardware, not assumed:**
  - `user=root` + `secret=` works for `sshd`/`gdm`/`login`/`sudo` under the CUI profile
  - the ctypes PAM conversation drives `pam_kanidm` + GA correctly
  - the `var_auth_t` label survives the module's state rewrites (Tasks 4, 7)
