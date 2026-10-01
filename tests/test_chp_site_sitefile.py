import ast
import base64
import ipaddress
import struct
from pathlib import Path

import pytest

from chp_site.sitefile import SiteError, parse_site, read_kv, ssh_pubkey

PKG = Path(__file__).resolve().parents[1] / "appliance" / "chp-site" / "chp_site"


def _blob(*parts):
    return base64.b64encode(b"".join(struct.pack(">I", len(p)) + p for p in parts)).decode()


ECDSA = "ecdsa-sha2-nistp384 " + _blob(b"ecdsa-sha2-nistp384", b"nistp384", b"\x04" + b"\x01" * 96)
RSA3072 = "ssh-rsa " + _blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + b"\xff" * 384)
RSA2048 = "ssh-rsa " + _blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + b"\xff" * 256)
ED25519 = "ssh-ed25519 " + _blob(b"ssh-ed25519", b"\x02" * 32)

GOOD = f"""# lab site
DOMAIN=iso2.lab.test
SUBNET=192.168.100.0/24
GATEWAY=192.168.100.1
DNS_FORWARDERS=
NTP_UPSTREAM=192.168.100.1
TIMEZONE=America/Denver
ISSO_NAME=D. Shannon
UNEXPIRE_DELEGATES=J. Shannon, Deputy ISSO
COLLECTOR_IP=192.168.100.1
ACCESSIBILITY=off
ALERT_HOOK=
ADMIN_SSH_PUBKEY={ECDSA} chpadmin@mac
"""


def test_every_module_is_python_39_syntax():
    for f in PKG.glob("*.py"):
        ast.parse(f.read_text(), filename=str(f), feature_version=(3, 9))


def test_good_site_parses_and_normalises():
    s = parse_site(GOOD)
    assert s["DOMAIN"] == "iso2.lab.test"
    assert s["SUBNET"] == ipaddress.IPv4Network("192.168.100.0/24")
    assert s["GATEWAY"] == ipaddress.IPv4Address("192.168.100.1")
    assert s["DNS_FORWARDERS"] == [] and s["NTP_UPSTREAM"] == ["192.168.100.1"]
    assert s["UNEXPIRE_DELEGATES"] == ["J. Shannon", "Deputy ISSO"]
    assert s["ADMIN_SSH_PUBKEY"] == ECDSA          # comment dropped
    assert s["ACCESSIBILITY"] == "off" and s["ALERT_HOOK"] == ""


def test_optional_keys_default():
    text = "\n".join(l for l in GOOD.splitlines() if not l.startswith(("DNS_", "UNEXPIRE", "COLLECTOR", "ACCESS", "ALERT")))
    s = parse_site(text)
    assert s["DNS_FORWARDERS"] == [] and s["ACCESSIBILITY"] == "off" and s["COLLECTOR_IP"] == ""


def test_crlf_bom_and_trailing_spaces_are_tolerated():          # Review Focus 1
    s = parse_site("﻿" + GOOD.replace("\n", "  \r\n"))
    assert s["DOMAIN"] == "iso2.lab.test"


@pytest.mark.parametrize("line,why", [
    ("DOMAIN=“iso2.lab.test”", "DOMAIN"),                      # smart quotes (Review Focus 1)
    ('DOMAIN="iso2.lab.test"', "DOMAIN"),
    ("DOMAIN=ISO2.lab.test", "DOMAIN"),                        # upper case
    ("DOMAIN=localhost", "DOMAIN"),                            # one label
    ("SUBNET=192.168.100.5/24", "SUBNET"),                     # host bits set
    ("GATEWAY=10.0.0.1", "GATEWAY"),                           # outside SUBNET
    ("TIMEZONE=Mountain", "TIMEZONE"),
    ("ACCESSIBILITY=yes", "ACCESSIBILITY"),
    ("ALERT_HOOK=relative/path", "ALERT_HOOK"),
    ("COLLECTOR_IP=10.0.0.9", "COLLECTOR_IP"),
    ("ISSO_NAME=", "ISSO_NAME"),
])
def test_bad_values_name_the_key(line, why):
    key = line.split("=", 1)[0]
    text = "\n".join(line if l.startswith(key + "=") else l for l in GOOD.splitlines())
    with pytest.raises(SiteError, match=why):
        parse_site(text)


def test_unknown_key_missing_key_duplicate_key_and_no_equals():
    with pytest.raises(SiteError, match="unknown key NTP_SERVER"):
        parse_site(GOOD + "NTP_SERVER=1.2.3.4\n")
    with pytest.raises(SiteError, match="DOMAIN is required"):
        parse_site("\n".join(l for l in GOOD.splitlines() if not l.startswith("DOMAIN=")))
    with pytest.raises(SiteError, match="line 14: DOMAIN is set twice"):
        parse_site(GOOD + "DOMAIN=other.lab.test\n")
    with pytest.raises(SiteError, match="line 2: expected KEY=value"):
        read_kv("A=1\njust words\n", "site.conf")


def test_admin_key_types():                                      # Review Focus 5
    assert ssh_pubkey(ECDSA + " c") == ECDSA
    assert ssh_pubkey(RSA3072) == RSA3072
    with pytest.raises(SiteError, match="ed25519.*FIPS"):
        ssh_pubkey(ED25519)
    with pytest.raises(SiteError, match="3072"):
        ssh_pubkey(RSA2048)
    with pytest.raises(SiteError, match="does not match"):     # declared type vs the type inside the blob
        ssh_pubkey("ecdsa-sha2-nistp256 " + ECDSA.split()[1])
    with pytest.raises(SiteError):
        ssh_pubkey('from="10.0.0.1" ' + ECDSA)                # options are not a key


def test_quote_error_names_the_line():                                    # final review Minor 1
    text = GOOD.replace("DOMAIN=iso2.lab.test", 'DOMAIN="iso2.lab.test"')
    with pytest.raises(SiteError, match=r"line 2: DOMAIN"):
        parse_site(text)


def test_inline_comment_is_refused_not_kept_in_the_value():             # final review Minor 3
    with pytest.raises(SiteError, match=r"line 8: ISSO_NAME.*comment"):
        parse_site(GOOD.replace("ISSO_NAME=D. Shannon", "ISSO_NAME=D. Shannon   # the ISSO"))


def test_timezone_must_exist_when_the_tz_database_is_present():          # final review Minor 4
    import zoneinfo
    if not zoneinfo.available_timezones():
        pytest.skip("no tz database here")
    with pytest.raises(SiteError, match="TIMEZONE.*America/Denvr"):
        parse_site(GOOD.replace("America/Denver", "America/Denvr"))


COLL = (Path(__file__).parent / "fixtures" / "chp-site" / "cache_key.pub").read_text().strip()


def test_collector_key_optional_and_validated():
    assert parse_site(GOOD)["COLLECTOR_SSH_PUBKEY"] == ""
    s = parse_site(GOOD + f"COLLECTOR_SSH_PUBKEY={COLL}\n")
    assert s["COLLECTOR_SSH_PUBKEY"] == " ".join(COLL.split()[:2])


def test_collector_key_ed25519_refused_with_its_own_name():
    with pytest.raises(SiteError, match="COLLECTOR_SSH_PUBKEY.*FIPS"):
        parse_site(GOOD + "COLLECTOR_SSH_PUBKEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyH x\n")


def test_collector_key_needs_collector_ip():
    text = "\n".join(l for l in GOOD.splitlines() if not l.startswith("COLLECTOR_IP=")) + "\n"
    with pytest.raises(SiteError, match="COLLECTOR_SSH_PUBKEY needs COLLECTOR_IP"):
        parse_site(text + f"COLLECTOR_SSH_PUBKEY={COLL}\n")
