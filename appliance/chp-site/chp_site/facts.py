# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The only code that reads this machine's hardware: NIC MACs and block devices."""
import os
import subprocess
import time
from collections import namedtuple
from pathlib import Path

from .disks import disks_from_lsblk

Facts = namedtuple("Facts", "macs disks now")


def live():
    macs = []
    for nic in sorted(Path("/sys/class/net").iterdir()):
        if nic.name == "lo":
            continue
        m = (nic / "address").read_text().strip()
        if m and m != "00:00:00:00:00:00":
            macs.append(m)
    js = subprocess.run(["lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,TRAN,RM,TYPE"], check=True,
                        capture_output=True, text=True).stdout
    by_id = {}
    bid = Path("/dev/disk/by-id")
    if bid.is_dir():
        for p in bid.iterdir():
            by_id.setdefault(os.path.basename(os.path.realpath(p)), []).append(str(p))
    return Facts(macs, disks_from_lsblk(js, by_id), time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))


def stick_identity(label="/dev/disk/by-label/OEMDRV"):
    """USB identity of the device holding the OEMDRV volume ({ID, SERIAL, NAME}), or None if it is not USB."""
    try:
        name = os.path.basename(os.path.realpath(label))
        node = Path(os.path.realpath(f"/sys/class/block/{name}"))
        while node != node.parent:
            if (node / "idVendor").exists():
                rd = lambda f: (node / f).read_text().strip() if (node / f).exists() else ""
                return {"ID": f"{rd('idVendor')}:{rd('idProduct')}", "SERIAL": rd("serial"), "NAME": rd("product")}
            node = node.parent
    except OSError:
        return None
    return None

