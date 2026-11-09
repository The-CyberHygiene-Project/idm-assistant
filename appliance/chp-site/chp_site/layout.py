# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The disk layout by disk size and role (ISO 0.6.0 spec section 2). Pure arithmetic; stdlib only, Python 3.9."""
from collections import namedtuple

Vol = namedtuple("Vol", "mount name mib fsoptions")

GIB = 1024
OVERHEAD_MIB = 3072 + 64          # /boot/efi + /boot, LUKS2 header + LVM metadata slack
SERVER_TODAY_BELOW = 900 * 10**9  # below this the lab layout is kept
CLIENT_TODAY_BELOW = 240 * 10**9
RECOMMENDED_BYTES = 1_900_000_000_000

# (mount, name, MiB) in kickstart order; root is last in today's layout because it grows.
_TODAY = (("swap", "swap", 8192), ("/home", "home", 10240), ("/tmp", "tmp", 4096), ("/var", "var", 20480),
          ("/var/tmp", "var_tmp", 4096), ("/var/log", "var_log", 8192), ("/var/log/audit", "var_log_audit", 8192),
          ("/", "root", 20480))


def _usable(size_bytes):
    return size_bytes // 2**20 - OVERHEAD_MIB


def _share(r, pct):
    return int(r * pct) // 1024 * 1024


def _fixed(role):
    if role == "server":
        g = {"swap": 29, "/tmp": 15, "/var": 100, "/var/tmp": 15, "/var/log": 50, "/var/log/audit": 30, "/": 90}
    else:
        g = {"swap": 8, "/tmp": 4, "/var": 20, "/var/tmp": 4, "/var/log": 20, "/var/log/audit": 8, "/": 40}
    return [Vol(m, n, g[m] * GIB, "") for m, n, _ in _TODAY if m in g]


def _is_today(role, size_bytes):
    return size_bytes < (SERVER_TODAY_BELOW if role == "server" else CLIENT_TODAY_BELOW)


def plan(role, size_bytes):
    """(volumes, grow_root). grow_root is True only for today's layout (root takes the rest)."""
    if _is_today(role, size_bytes):
        return [Vol(m, n, mib, "") for m, n, mib in _TODAY], True
    vols = _fixed(role)
    r = _usable(size_bytes) - sum(v.mib for v in vols)
    if role == "server":
        vols += [Vol("/home", "home", _share(r, 0.156), ""),
                 Vol("/data", "data", _share(r, 0.229), "nodev,nosuid"),
                 Vol("/backup", "backup", _share(r, 0.392), "nodev,nosuid,noexec")]
    else:
        vols.append(Vol("/home", "home", max(_share(r, 0.25), 10 * GIB), ""))
    order = [m for m, _, _ in _TODAY] + ["/data", "/backup"]
    vols.sort(key=lambda v: order.index(v.mount))
    return vols, False


def unallocated_gib(role, size_bytes):
    vols, grow = plan(role, size_bytes)
    if grow:
        return 0
    return (_usable(size_bytes) - sum(v.mib for v in vols)) // GIB


def note(role, size_bytes):
    if role != "server" or size_bytes >= RECOMMENDED_BYTES:
        return ""
    return f"disk is {size_bytes // 10**9} GB, smaller than the recommended 2 TB for the server"
