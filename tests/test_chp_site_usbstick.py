"""usbstick: find the ONE blocked USB mass-storage device (USBGuard) so export-client can allow it temporarily."""
import pytest

from chp_site.sitefile import SiteError
from chp_site.usbstick import blocked_mass_storage

KBD = '3: allow id 0627:0001 serial "42" name "QEMU USB Keyboard" hash "a=" parent-hash "b=" via-port "1-1" with-interface 03:01:01 with-connect-type ""'
STICK = '12: block id 46f4:0001 serial "1-0000:00:1d.7-1" name "QEMU USB HARDDRIVE" hash "c=" parent-hash "d=" via-port "2-1" with-interface 08:06:50 with-connect-type ""'
STICK2 = '13: block id 0781:5581 serial "4C53" name "Ultra" hash "e=" parent-hash "f=" via-port "2-2" with-interface { 08:06:50 08:06:62 } with-connect-type "hotplug"'
BLOCKED_MOUSE = '14: block id 046d:c077 serial "" name "USB Optical Mouse" hash "g=" parent-hash "h=" via-port "1-2" with-interface 03:01:02 with-connect-type "hotplug"'


def test_one_blocked_stick_among_other_devices():
    assert blocked_mass_storage("\n".join([KBD, STICK, BLOCKED_MOUSE])) == "12"


def test_interface_sets_are_understood():
    assert blocked_mass_storage("\n".join([KBD, STICK2])) == "13"


def test_an_allowed_stick_is_not_picked():
    assert blocked_mass_storage(STICK.replace(": block ", ": allow ")) is None


def test_two_blocked_sticks_is_ambiguous():
    with pytest.raises(SiteError, match="2 blocked USB storage devices"):
        blocked_mass_storage("\n".join([STICK, STICK2]))


def test_none_found_returns_none():
    assert blocked_mass_storage("\n".join([KBD, BLOCKED_MOUSE])) is None


from chp_site.usbstick import pick_pinned


PIN = {"ID": "46f4:0001", "SERIAL": "1-0000:00:1d.7-1"}


def test_pinned_stick_is_picked_by_id_and_serial():
    dev, h = pick_pinned("\n".join([KBD, STICK, STICK2]), PIN, None)
    assert dev == "12" and h == "c="


def test_a_different_stick_is_refused_even_if_it_is_the_only_one():
    with pytest.raises(SiteError, match="not the site stick"):
        pick_pinned(STICK2, PIN, None)


def test_once_the_hash_is_pinned_it_must_match():
    assert pick_pinned(STICK, PIN, "c=") == ("12", "c=")
    spoof = STICK.replace('hash "c="', 'hash "zz="')                      # same id + serial, different descriptors
    with pytest.raises(SiteError, match="hash"):
        pick_pinned(spoof, PIN, "c=")


def test_no_pin_is_refused():
    with pytest.raises(SiteError, match="no site-stick pin"):
        pick_pinned(STICK, None, None)
