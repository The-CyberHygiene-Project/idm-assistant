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
