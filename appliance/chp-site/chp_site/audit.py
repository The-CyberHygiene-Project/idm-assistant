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
