import ipaddress
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_site import suricata_conf as sc
from chp_site.sitefile import SiteError

SPIKE = Path(__file__).resolve().parents[1] / "lab" / "security" / "spike-suricata"
IP_ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
           "2: enp1s0    inet 192.168.100.52/24 brd 192.168.100.255 scope global enp1s0\\       valid_lft forever\n")


def run_ip(out=IP_ADDR):
    return lambda argv, **kw: SimpleNamespace(returncode=0, stdout=out, stderr="")


def test_iface_for_finds_the_site_address():
    assert sc.iface_for("192.168.100.52", run_ip()) == "enp1s0"


def test_iface_for_does_not_match_a_longer_address():
    with pytest.raises(SiteError):
        sc.iface_for("192.168.100.5", run_ip())


def test_no_interface_for_the_site_address_is_a_clear_error():                # Review Focus 1
    with pytest.raises(SiteError, match="192.168.100.99"):
        sc.iface_for("192.168.100.99", run_ip())


def test_home_net_is_the_site_subnet():
    assert sc.home_net({"SUBNET": ipaddress.IPv4Network("192.168.100.0/24")}) == "[192.168.100.0/24]"


def test_missing_subnet_is_a_clear_error():                                    # Review Focus 2
    with pytest.raises(SiteError, match="SUBNET"):
        sc.home_net({})


def test_config_is_ids_only_alert_only_on_one_interface():
    t = sc.config_text("enp1s0", "[192.168.100.0/24]")
    assert "HOME_NET: \"[192.168.100.0/24]\"" in t and "EXTERNAL_NET: \"!$HOME_NET\"" in t
    assert "- interface: enp1s0" in t and "copy-mode" not in t and "nfq" not in t
    assert "filename: eve.json" in t and "- alert" in t
    for off in ("- flow", "- dns", "- http", "- tls", "- fileinfo", "pcap-log", "- drop"):
        assert off not in t, off
    assert f"default-rule-path: {sc.RULES_DIR}" in t and "- chp-suricata.rules" in t
    assert "unix-command:\n  enabled: no" in t


def test_config_is_exactly_the_one_proven_in_the_spike():                     # Task 1: 52,859 loaded, 0 failed
    assert sc.config_text("enp1s0", "[192.168.100.0/24]") == (SPIKE / "chp-suricata.yaml").read_text()


def test_dropin_replaces_execstart_and_sysconfig_empties_options():           # Task 1: no double -c
    d = sc.dropin_text("enp1s0")
    assert d.count("ExecStart=") == 2 and "\nExecStart=\n" in d
    assert f"-c {sc.CONF} " in d and "--af-packet=enp1s0" in d and "--user suricata" in d
    assert sc.SYSCONFIG_TEXT.endswith('OPTIONS=""\n')
    assert d + sc.SYSCONFIG_TEXT == (SPIKE / "dropin-and-sysconfig.txt").read_text()
    assert sc.DROPIN == "/etc/systemd/system/suricata.service.d/chp.conf"


def test_bad_interface_name_is_refused():
    with pytest.raises(SiteError):
        sc.config_text("en p1\n", "[192.168.100.0/24]")
    with pytest.raises(SiteError):
        sc.dropin_text("eth0 --x")
