# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Pick the install disk. A wrong answer destroys data, so: exactly one candidate, or the hosts table names it."""
import json
from collections import namedtuple

from .sitefile import SiteError

Disk = namedtuple("Disk", "name size tran rm by_id")


def disks_from_lsblk(json_text, by_id):
    """`lsblk -J -b -d -o NAME,SIZE,TRAN,RM,TYPE` output; by_id maps kernel name -> [/dev/disk/by-id/... paths]."""
    out = []
    for d in json.loads(json_text).get("blockdevices", []):
        if d.get("type") != "disk" or str(d.get("name", "")).startswith(("loop", "zram", "sr")):
            continue
        rm = d.get("rm") in (True, 1, "1", "true")
        out.append(Disk(d["name"], int(d.get("size") or 0), d.get("tran") or "", rm, by_id.get(d["name"], [])))
    return out


def choose_disk(disks, wanted, min_bytes=100_000_000_000):
    cands = [d for d in disks if d.tran != "usb" and not d.rm]
    if wanted:
        hit = [d for d in disks if wanted in (d.name, f"/dev/{d.name}") or wanted in d.by_id]
        if not hit:
            raise SiteError(f"install disk {wanted!r} (hosts table) not found on this machine; disks: "
                            + ", ".join(d.name for d in disks))
        d = hit[0]
        if d not in cands:
            raise SiteError(f"install disk {wanted!r} is a USB or removable device; refusing to install on it")
    else:
        if not cands:
            raise SiteError("no install disk: only USB/removable devices found")
        if len(cands) > 1:
            raise SiteError(f"{len(cands)} disks could be the install disk (" + ", ".join(d.name for d in cands)
                            + "): name one in the hosts table (5th column) so the right one is wiped")
        d = cands[0]
    if d.size < min_bytes:
        raise SiteError(f"install disk {d.name} is {d.size // 10**9} GB; at least 100 GB are required")
    return d.name
