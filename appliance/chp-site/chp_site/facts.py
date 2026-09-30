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
