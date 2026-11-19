import re

import pytest
from pathlib import Path

from chp_site import documents_render as D
from chp_site.hosts import parse_hosts
from chp_site.render import zone
from chp_site.sitefile import SiteError, parse_site
from tests.test_chp_site_hosts import HOSTS
from tests.test_chp_site_sitefile import GOOD

ON = parse_site(GOOD + "SECURITY_ADDONS=yes\nDOCUMENTS=yes\n")
OFF = parse_site(GOOD)
HS = parse_hosts(HOSTS, ON)
KIT = Path(__file__).resolve().parents[1] / "appliance" / "site-stick-kit" / "site.conf.template"


def test_fqdn():
    assert D.fqdn(ON) == "files.iso2.lab.test"


def test_zone_has_files_record_only_when_documents_on():
    assert re.search(r"^files\s+IN A\s+192\.168\.100\.30$", zone(ON, HS, 1), re.M)
    assert not re.search(r"^files\b", zone(OFF, HS, 1), re.M)


def test_hosts_file_is_the_whole_file_with_loopback_first():
    out = D.hosts_file(ON, HS).splitlines()
    assert out[0] == "127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4"
    assert out[1] == "::1 localhost localhost.localdomain localhost6 localhost6.localdomain6"
    lines = [x for x in out[2:] if x.strip() and not x.startswith("#")]
    assert {l.split()[1] for l in lines} == {"idm.iso2.lab.test", "files.iso2.lab.test", "ca.iso2.lab.test",
                                              "iso2-srv.iso2.lab.test"}
    assert all(l.split()[0] == "192.168.100.30" for l in lines)


def test_hosts_file_refuses_when_documents_off():
    with pytest.raises(SiteError):
        D.hosts_file(OFF, HS)


def test_security_addons_no_with_documents_yes_refused():
    with pytest.raises(SiteError, match="DOCUMENTS=yes needs SECURITY_ADDONS=yes"):
        parse_site(GOOD + "SECURITY_ADDONS=no\nDOCUMENTS=yes\n")


def test_sitevars_files_fqdn_single_source():
    from chp_site.sitevars import values
    assert values(ON, HS)["FILES_FQDN"] == D.fqdn(ON)


def test_template_documents_keys_commented_and_additive():
    t = KIT.read_text()
    assert "\nDOCUMENTS=no\n" in t and "\nDOCUMENTS_BACKUP_DAYS=14\n" in t
    assert "\nSECURITY_ADDONS=no\n" in t and "\nREVIEW_DELEGATES=\n" in t
    keys = re.findall(r"^([A-Z_]+)=", t, re.M)
    assert keys[-1] == "DOCUMENTS_BACKUP_DAYS"
    i = t.index("DOCUMENTS=no")
    assert t[:i].rstrip().splitlines()[-1].startswith("#")
    # the template, with only the required keys filled in, parses and the new keys default off
    fill = {"DOMAIN": "x.lab.test", "SUBNET": "10.0.0.0/24", "GATEWAY": "10.0.0.1", "NTP_UPSTREAM": "10.0.0.1",
            "TIMEZONE": "UTC", "ISSO_NAME": "A B", "ADMIN_SSH_PUBKEY": GOOD.split("ADMIN_SSH_PUBKEY=")[1].split("\n")[0]}
    for k, v in fill.items():
        t = re.sub(rf"^{k}=$", f"{k}={v}", t, flags=re.M)
    s = parse_site(t)
    assert s["DOCUMENTS"] == "no" and s["DOCUMENTS_BACKUP_DAYS"] == 14


def test_template_documents_text_says_how_it_is_turned_on():
    # final review M6: the text promised a first-boot set-up that 0.7.0 does not do (enable is a manual step with a
    # Kanidm admin session and the site stick). Other tools read this template: the words matter.
    t = KIT.read_text()
    i = t.index("\nDOCUMENTS=no\n")
    block = " ".join(l.lstrip("# ").strip() for l in t[t.rindex("\n\n", 0, i):i].splitlines())
    assert "installer sets it up" not in block and "not set up at first boot" in block
    assert "chp-site documents enable" in block and "site stick" in block and "SECURITY_ADDONS=yes" in block
