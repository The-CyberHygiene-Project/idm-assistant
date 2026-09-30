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
SA_RE = r"[a-z][a-z0-9_-]{0,63}"          # service accounts, e.g. unixd-<hostname>
PROTECTED = frozenset({"admin", "idm_admin"})
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def valid_name(n):
    return bool(re.fullmatch(NAME_RE, n or ""))


def _name(n, what="name"):
    if not valid_name(n):
        raise SiteError(f"{n!r} is not a valid {what} (lower-case letters, digits, _; starts with a letter; max 32)")
    return n


def _sa(n):
    if not re.fullmatch(SA_RE, n or ""):
        raise SiteError(f"{n!r} is not a valid service account name")
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
        err = _ANSI.sub("", err)
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
        self._k("group", "add-members", _name(group, "group name"), _sa(name))

    def remove_member(self, group, name):
        self._k("group", "remove-members", _name(group, "group name"), _name(name))

    def reset_token_text(self, name):
        out = self._k("person", "credential", "create-reset-token", _name(name), "--ttl", "3600")
        if not re.search(r"use-reset-token [A-Za-z0-9-]+", out):
            raise SiteError("no reset token in the kanidm output")
        return out

    def service_account_exists(self, name):
        return parse_entry(self._k("service-account", "get", _sa(name))) is not None

    def service_account_create(self, name, display):
        self._k("service-account", "create", _sa(name), display, "idm_admins")

    def api_token(self, name, label):
        """A READ-ONLY API token (no --readwrite). The token is returned, never logged."""
        out = self._k("service-account", "api-token", "generate", _sa(name), _sa(label))
        m = re.findall(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", out)
        if not m:
            raise SiteError("no API token in the kanidm output")
        return m[-1]

    def expire_now(self, name):
        self._k("person", "validity", "expire-at", _name(name), "now")

    def clear_expiry(self, name):
        self._k("person", "validity", "expire-at", _name(name), "clear")
