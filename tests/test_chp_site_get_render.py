import re
import subprocess
import sys
from pathlib import Path

import pytest

from chp_site.hosts import parse_hosts
from chp_site.render import collect_conf, kanidm_client_config, kanidm_server_toml, named_conf, zone
from chp_site.sitefile import parse_site
from chp_site.sitevars import values
from tests.test_chp_site_hosts import HOSTS
from tests.test_chp_site_sitefile import GOOD

SITE = parse_site(GOOD); HS = parse_hosts(HOSTS, SITE)
PKG = Path(__file__).resolve().parents[1] / "appliance" / "chp-site"


def test_values():
    v = values(SITE, HS)
    assert v["SERVER_IP"] == "192.168.100.30" and v["SERVER_FQDN"] == "iso2-srv.iso2.lab.test"
    assert v["KANIDM_FQDN"] == "idm.iso2.lab.test" and v["CA_FQDN"] == "ca.iso2.lab.test"
    assert v["SUBNET_CIDR"] == "192.168.100.0/24"


def test_zone_has_every_host_and_the_service_names():
    z = zone(SITE, HS, 2026093001)
    assert "@ IN SOA iso2-srv.iso2.lab.test. hostmaster.iso2.lab.test. ( 2026093001" in z
    for name, ip in (("iso2-srv", ".30"), ("iso2-cli", ".31"), ("idm", ".30"), ("ca", ".30")):
        assert re.search(rf"^{name}\s+IN A\s+192\.168\.100{re.escape(ip)}$", z, re.M), name


def test_named_conf_is_authoritative_only_for_the_subnet():
    n = named_conf(SITE, HS)
    assert "listen-on port 53 { 127.0.0.1; 192.168.100.30; };" in n and "allow-query { 127.0.0.1; 192.168.100.0/24; };" in n
    assert "recursion no;" in n and 'zone "iso2.lab.test" IN { type primary; file "iso2.lab.test.zone";' in n


def test_named_conf_forwards_when_forwarders_are_set():
    s = parse_site(GOOD.replace("DNS_FORWARDERS=", "DNS_FORWARDERS=192.168.100.1"))
    n = named_conf(s, HS)
    assert "recursion yes;" in n and "forwarders { 192.168.100.1; };" in n and "forward only;" in n


def test_kanidm_files():
    t = kanidm_server_toml(SITE, HS)
    assert 'bindaddress = "192.168.100.30:443"' in t and 'domain = "idm.iso2.lab.test"' in t
    assert 'origin = "https://idm.iso2.lab.test"' in t and 'tls_key = "/run/kanidmd/tls_key.pem"' in t
    c = kanidm_client_config(SITE)
    assert 'uri = "https://idm.iso2.lab.test"' in c and 'ca_path = "/etc/pki/ca-trust/source/anchors/chp-root.crt"' in c
    assert collect_conf(SITE) == ("KANIDM_URL=https://idm.iso2.lab.test\n"
                                  "CA_ANCHOR=/etc/pki/ca-trust/source/anchors/chp-root.crt\n")


def cli(*a, site=None):
    return subprocess.run([sys.executable, "-m", "chp_site.cli", *a], cwd=PKG, capture_output=True, text=True)


def test_cli_get_and_render(tmp_path):
    (tmp_path / "site.conf").write_text(GOOD); (tmp_path / "hosts").write_text(HOSTS)
    r = cli("get", "SERVER_IP", "--site", str(tmp_path))
    assert r.returncode == 0 and r.stdout == "192.168.100.30\n"
    assert cli("get", "NOPE", "--site", str(tmp_path)).returncode == 2
    r = cli("render", "zone", "--site", str(tmp_path))
    assert r.returncode == 0 and "idm" in r.stdout
