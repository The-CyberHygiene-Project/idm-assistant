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
