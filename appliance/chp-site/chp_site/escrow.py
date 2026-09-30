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
    """Best effort: overwrite, fsync, unlink. XFS reflink and SSD wear levelling can keep old blocks; LUKS protects the rest."""
    n = p.stat().st_size
    with open(p, "r+b") as f:
        f.write(os.urandom(max(n, 1))); f.flush(); os.fsync(f.fileno())
    p.unlink()


def _read_back(path):
    """Read the file back FROM THE DEVICE: its pages were fsync'd, now drop them from the page cache so the read is
    served by the stick, not by memory (Linux; elsewhere this is a plain read)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        if hasattr(os, "posix_fadvise"):
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        chunks = []
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks).decode()
    finally:
        os.close(fd)


def _write_synced(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode())
        os.fsync(fd)                       # raises on a device write error (EIO): nothing is shredded then
    finally:
        os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)                      # the directory entry too
    finally:
        os.close(dfd)


def move_pending(pending, stick, server_hostname, now):
    """Write the pending secrets to the stick, fsync file + directory, read them back from the DEVICE and compare every
    decoded value with its source; only then shred them on the server. Any doubt keeps them on the server."""
    pending, stick = Path(pending), Path(stick)
    files = sorted(f for f in pending.iterdir() if f.is_file()) if pending.is_dir() else []
    if not files:
        return []
    src = {KEYS.get(f.name, f.name.upper().replace("-", "_").replace(".", "_")): f.read_bytes() for f in files}
    body = [f"# {server_hostname} server recovery secrets, moved off the server {now}. KEEP THIS STICK OFFLINE."]
    body += [f"{k}={base64.b64encode(v).decode()}" for k, v in src.items()]
    text = "\n".join(body) + "\n"
    d, out = stick / "escrow", stick / "escrow" / f"{server_hostname}-server.txt"
    try:
        d.mkdir(exist_ok=True)
        if out.exists():
            out.rename(d / f"{out.name}.{now}.old")
        _write_synced(out, text)
        got = dict(line.split("=", 1) for line in _read_back(out).splitlines() if "=" in line and not line.startswith("#"))
        for k, v in src.items():
            if base64.b64decode(got.get(k, "")) != v:
                raise OSError(0, f"read-back of {k} from the stick does not match")
    except (OSError, ValueError) as e:
        raise SiteError(f"could not write the server secrets to the stick ({getattr(e, 'strerror', None) or e}); they are "
                        "kept on the server and the monitor keeps warning") from None
    for f in files:
        _shred(f)
    return [f.name for f in files]


def move_tokens(pending_tokens, stick, now):
    """Per-client unixd tokens -> stick/tokens/<host>.token with the same guarantee as the escrow: written, fsync'd,
    read back from the DEVICE and compared, only then shredded on the server."""
    pending_tokens, d = Path(pending_tokens), Path(stick) / "tokens"
    files = sorted(f for f in pending_tokens.iterdir() if f.is_file() and f.name.endswith(".token")) \
        if pending_tokens.is_dir() else []
    if not files:
        return []
    try:
        d.mkdir(exist_ok=True)
        for f in files:
            v = f.read_text()
            out = d / f.name
            if out.exists():
                out.rename(d / f"{f.name}.{now}.old")
            _write_synced(out, v)
            if _read_back(out) != v:
                raise OSError(0, f"read-back of {f.name} from the stick does not match")
    except OSError as e:
        raise SiteError(f"could not write the client tokens to the stick ({getattr(e, 'strerror', None) or e}); they are "
                        "kept on the server and the monitor keeps warning") from None
    for f in files:
        _shred(f)
    try:
        pending_tokens.rmdir()
    except OSError:
        pass
    return [f.name[:-len(".token")] for f in files]
