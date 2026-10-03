# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site ga-enrol: a host-local Google Authenticator token for a KANIDM user (ISSO 2026-09-28 #1/#3; 2026-10-01 #1-#3).
Run as root on the host (sudo by an enrolled chp_admins member; root itself for the host's first admin). The QR code
and the 5 scratch codes are printed to THIS terminal only, for the user present (decision 1: a testing expediency;
production = a one-time enrolment link by mail). Local accounts never get a token (decision 2)."""
import os
import subprocess
import sys
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
          run=subprocess.run, chown=os.chown, rec=audit.record, no_confirm=False, tty=lambda: sys.stdin.isatty()):
    """By default google-authenticator asks the user to type a code from the app after scanning (proof the phone is
    set up). That needs a terminal; scripted use passes no_confirm (-C)."""
    if not valid_name(user):
        raise SiteError(f"{user!r} is not a valid user name")
    if _local(user, passwd):
        raise SiteError(f"{user} is a local account: local accounts do not use Google Authenticator (break-glass)")
    if not resolves(user):
        raise SiteError(f"{user} does not resolve on this host (not a Kanidm user, or kanidm-unixd is offline)")
    tokdir = Path(tokdir); p = tokdir / user
    if p.exists() and not reset:
        raise SiteError(f"{user} already has a token on this host; pass --reset to replace it (the old one stops working)")
    if not no_confirm and not tty():
        raise SiteError("ga-enrol needs a terminal (the user confirms a code from the app); use --no-confirm only for "
                        "scripted enrolment")
    fields = {"user": user, "host": fqdn, "reset": "yes" if reset else "no", "operator": audit.operator()}
    rec("ga-enrol", fields)
    tokdir.mkdir(mode=0o700, parents=True, exist_ok=True); os.chmod(tokdir, 0o700)
    tmp = tokdir / f".{user}.new"
    if tmp.exists():
        tmp.unlink()
    r = run(["google-authenticator", "-t", "-d", "-f", "-r", "3", "-R", "30", "-w", "3", "-e", "5",
             "-l", f"{user}@{fqdn}", "-i", f"CHP {domain}", "-Q", "UTF8", "-s", str(tmp)] + (["-C"] if no_confirm else []))
    if r.returncode != 0 or not tmp.exists():
        if tmp.exists():
            _shred(tmp)
        raise SiteError(f"google-authenticator failed (exit {r.returncode}); the existing token, if any, is unchanged")
    os.chmod(tmp, 0o400); chown(str(tmp), 0, 0)      # 0400: the mode the PAM module itself writes back
    if p.exists():
        os.chmod(p, 0o600)       # the old token is 0400 (as the module writes it): writable for the shred
        _shred(p)
    os.replace(tmp, p)
    run(["restorecon", str(p)])
    rec("ga-enrol.done", fields, after=True)
    return p
