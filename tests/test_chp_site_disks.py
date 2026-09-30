import json

import pytest

from chp_site.disks import choose_disk, disks_from_lsblk
from chp_site.sitefile import SiteError

G = 1_000_000_000


def _ls(*devs):
    return json.dumps({"blockdevices": [dict(zip(("name", "size", "tran", "rm", "type"), d)) for d in devs]})


def test_one_candidate_is_chosen_usb_and_cdrom_ignored():
    ds = disks_from_lsblk(_ls(("vda", 120 * G, "virtio", False, "disk"), ("sda", 8 * G, "usb", True, "disk"),
                              ("sr0", 11 * G, "sata", True, "rom")), {})
    assert choose_disk(ds, "") == "vda"


def test_two_candidates_need_a_name():
    ds = disks_from_lsblk(_ls(("vda", 120 * G, "virtio", False, "disk"), ("vdb", 120 * G, "virtio", False, "disk")), {})
    with pytest.raises(SiteError, match="2 disks could be the install disk.*vda.*vdb.*5th column"):
        choose_disk(ds, "")
    assert choose_disk(ds, "vdb") == "vdb"


def test_named_by_id_and_bad_names():
    ds = disks_from_lsblk(_ls(("nvme0n1", 512 * G, "nvme", False, "disk")),
                          {"nvme0n1": ["/dev/disk/by-id/nvme-Samsung_X"]})
    assert choose_disk(ds, "/dev/disk/by-id/nvme-Samsung_X") == "nvme0n1"
    with pytest.raises(SiteError, match="not found"):
        choose_disk(ds, "sdz")
    usb = disks_from_lsblk(_ls(("sda", 500 * G, "usb", False, "disk")), {})
    with pytest.raises(SiteError, match="USB"):
        choose_disk(usb, "sda")


def test_no_disk_and_too_small():
    with pytest.raises(SiteError, match="no install disk"):
        choose_disk(disks_from_lsblk(_ls(("sda", 8 * G, "usb", True, "disk")), {}), "")
    with pytest.raises(SiteError, match="at least 100 GB"):
        choose_disk(disks_from_lsblk(_ls(("vda", 40 * G, "virtio", False, "disk")), {}), "")
