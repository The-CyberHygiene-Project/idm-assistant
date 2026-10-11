# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Row 37: verify the install repository BEFORE anything is installed. Anaconda installs with gpgcheck=0 and
repo_gpgcheck=0; every package's checksum is listed in metadata that repomd.xml pins, so a valid signature on
repomd.xml by a pinned PRIMARY key covers the whole repository. gpgv only: no keyring, no agent, no trust database."""
import base64
import os
import pkgutil
import subprocess
import tempfile
import urllib.error
import urllib.request

from .sitefile import SiteError

TRUSTED_PRIMARY = ("2DE0D71BF37D8F5E4201A590521276F43C908F8E",)   # == appliance/release/trusted-keys.txt (tested)


def bundled_key():
    return pkgutil.get_data("chp_site", "keys/RPM-GPG-KEY-cyberhygiene").decode()


def dearmor(text):
    """ASCII armour -> binary OpenPGP packets (gpgv wants a binary keyring)."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.startswith("-----BEGIN PGP PUBLIC KEY BLOCK"))
        end = next(i for i, ln in enumerate(lines) if i > start and ln.startswith("-----END PGP"))
    except StopIteration:
        raise SiteError("the bundled signing key is not an armoured OpenPGP public key") from None
    body = lines[start + 1:end]
    if "" in body:                                   # armour headers ("Version: …") end at the first blank line
        body = body[body.index("") + 1:]
    return base64.b64decode("".join(ln.strip() for ln in body if not ln.startswith("=")))


def primary_from_status(status):
    """The primary-key fingerprint from gpgv's status output: the LAST field of the one VALIDSIG line."""
    v = [ln.split() for ln in status.splitlines() if ln.startswith("[GNUPG:] VALIDSIG ")]
    if len(v) != 1:
        raise SiteError(f"expected exactly one valid signature on repomd.xml, found {len(v)}")
    return v[0][-1].upper()


def _fetch(url, what):
    try:
        with urllib.request.urlopen(url, timeout=60) as r:      # file:// (the ISO) and http:// (lab) alike
            return r.read()
    except (urllib.error.URLError, OSError) as e:
        raise SiteError(f"cannot read {what} ({url}): {getattr(e, 'reason', e)}") from None


def verify(url, armored_key, trusted=None, gpgv="gpgv"):
    trusted = TRUSTED_PRIMARY if trusted is None else trusted     # read at call time, not at import
    base = url.rstrip("/")
    data = _fetch(f"{base}/repodata/repomd.xml", "the repository metadata")
    sig = _fetch(f"{base}/repodata/repomd.xml.asc", "the repository signature")
    with tempfile.TemporaryDirectory() as d:
        paths = {n: os.path.join(d, n) for n in ("keyring.gpg", "repomd.xml", "repomd.xml.asc")}
        for name, blob in (("keyring.gpg", dearmor(armored_key)), ("repomd.xml", data), ("repomd.xml.asc", sig)):
            with open(paths[name], "wb") as f:
                f.write(blob)
        try:
            r = subprocess.run([gpgv, "--status-fd", "1", "--keyring", paths["keyring.gpg"], paths["repomd.xml.asc"],
                                paths["repomd.xml"]], capture_output=True, text=True, env=dict(os.environ, GNUPGHOME=d))
        except OSError as e:
            raise SiteError(f"cannot run gpgv ({e.strerror}): the repository cannot be verified") from None
    if r.returncode != 0:
        raise SiteError(f"the install repository's signature is NOT valid ({base}): it was changed, or not signed "
                        "by the project key")
    fpr = primary_from_status(r.stdout)
    if fpr not in tuple(t.upper() for t in trusted):
        raise SiteError(f"repomd.xml is signed by {fpr}, which is not a pinned project key")
    return fpr
