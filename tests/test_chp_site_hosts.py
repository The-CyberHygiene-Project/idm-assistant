import pytest

from chp_site.hosts import lookup, norm_mac, parse_hosts, server_of
from chp_site.sitefile import SiteError, parse_site
from tests.test_chp_site_sitefile import GOOD

SITE = parse_site(GOOD)
HOSTS = """# MAC               hostname  IP              role    [disk]
52:54:00:c4:02:30  iso2-srv  192.168.100.30  server
52:54:00:c4:02:31  iso2-cli  192.168.100.31  client  vda
"""


def test_parse_and_lookup():
    hs = parse_hosts(HOSTS, SITE)
    assert [h.hostname for h in hs] == ["iso2-srv", "iso2-cli"]
    assert lookup(hs, ["aa:bb:cc:dd:ee:ff", "52:54:00:c4:02:31"]).hostname == "iso2-cli"
    assert server_of(hs).ip == "192.168.100.30"
    assert hs[1].disk == "vda" and hs[0].disk == ""


@pytest.mark.parametrize("raw", ["52-54-00-C4-02-30", "52:54:00:C4:02:30", " 52:54:00:c4:02:30 "])
def test_mac_notations_match(raw):                                 # Review Focus 2
    assert norm_mac(raw) == "52:54:00:c4:02:30"


def test_unknown_machine_stops_with_its_macs():
    with pytest.raises(SiteError, match=r"not in the hosts table.*aa:bb:cc:dd:ee:ff"):
        lookup(parse_hosts(HOSTS, SITE), ["aa:bb:cc:dd:ee:ff"])


def test_crlf_hosts_file_is_fine():
    assert len(parse_hosts(HOSTS.replace("\n", "\r\n"), SITE)) == 2


@pytest.mark.parametrize("bad,why", [
    ("52:54:00:c4:02:30 iso2-srv 192.168.100.30 server\n52:54:00:c4:02:30 b 192.168.100.32 client", "MAC .* twice"),
    ("52:54:00:c4:02:30 iso2-srv 192.168.100.30 server\n52:54:00:c4:02:31 iso2-srv 192.168.100.32 client", "hostname .* twice"),
    ("52:54:00:c4:02:30 a 192.168.100.30 server\n52:54:00:c4:02:31 b 192.168.100.30 client", "IP .* twice"),
    ("52:54:00:c4:02:31 b 192.168.100.31 client", "exactly one server"),
    ("52:54:00:c4:02:30 a 192.168.100.30 server\n52:54:00:c4:02:31 b 192.168.100.31 server", "exactly one server"),
    ("52:54:00:c4:02:30 a 10.0.0.5 server", "outside SUBNET"),
    ("52:54:00:c4:02:30 a 192.168.100.1 server", "is the GATEWAY"),
    ("52:54:00:c4:02:30 a 192.168.100.255 server", "broadcast"),
    ("52:54:00:c4:02:30 Srv_1 192.168.100.30 server", "hostname"),
    ("zz:54:00:c4:02:30 a 192.168.100.30 server", "MAC"),
    ("52:54:00:c4:02:30 a 192.168.100.30 router", "role"),
    ("52:54:00:c4:02:30 a 192.168.100.30 server ../../etc/passwd", "disk"),
    ("52:54:00:c4:02:30 a 192.168.100.30", "4 or 5 fields"),
])
def test_bad_tables_say_why(bad, why):
    with pytest.raises(SiteError, match=why):
        parse_hosts(bad, SITE)


def test_by_id_disk_is_allowed():
    hs = parse_hosts("52:54:00:c4:02:30 a 192.168.100.30 server /dev/disk/by-id/nvme-Samsung_SSD_980_S64DNX0R\n", SITE)
    assert hs[0].disk.startswith("/dev/disk/by-id/")
