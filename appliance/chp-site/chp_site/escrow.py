# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Move the server's pending recovery secrets onto the site stick: write, sync, read back, THEN shred on the server."""
import base64
import os
from pathlib import Path

from .sitefile import SiteError

KEYS = {"kanidm-admins.json": "KANIDM_ADMINS_JSON", "step-ca-password": "STEP_CA_PASSWORD", "root_ca_key": "ROOT_CA_KEY_PEM"}


def _shred(p):
    n = p.stat().st_size
    with open(p, "r+b") as f:
        f.write(os.urandom(max(n, 1))); f.flush(); os.fsync(f.fileno())
    p.unlink()


def move_pending(pending, stick, server_hostname, now):
    pending, stick = Path(pending), Path(stick)
    files = sorted(f for f in pending.iterdir() if f.is_file()) if pending.is_dir() else []
    if not files:
        return []
    body = [f"# {server_hostname} server recovery secrets, moved off the server {now}. KEEP THIS STICK OFFLINE."]
    for f in files:
        body.append(f"{KEYS.get(f.name, f.name.upper().replace('-', '_').replace('.', '_'))}="
                    f"{base64.b64encode(f.read_bytes()).decode()}")
    text = "\n".join(body) + "\n"
    d, out = stick / "escrow", stick / "escrow" / f"{server_hostname}-server.txt"
    try:
        d.mkdir(exist_ok=True)
        if out.exists():
            out.rename(d / f"{out.name}.{now}.old")
        out.write_text(text)
        os.sync()
        if out.read_text() != text:
            raise OSError(0, "read-back mismatch")
    except OSError as e:
        raise SiteError(f"could not write the server secrets to the stick ({e.strerror}); they are kept on the server "
                        "and the monitor keeps warning") from None
    for f in files:
        _shred(f)
    return [f.name for f in files]
