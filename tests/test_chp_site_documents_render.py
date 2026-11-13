import re
from pathlib import Path

from chp_site import documents_render as D
from chp_site.hosts import parse_hosts
from chp_site.render import zone
from chp_site.sitefile import parse_site
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


def test_hosts_file_names_only_site_names():
    lines = [x for x in D.hosts_file(ON, HS).splitlines() if x.strip() and not x.startswith("#")]
    names = {l.split()[1] for l in lines}
    assert names == {"idm.iso2.lab.test", "files.iso2.lab.test", "ca.iso2.lab.test", "iso2-srv.iso2.lab.test"}
    assert all(l.split()[0] == "192.168.100.30" for l in lines)


def test_template_documents_keys_commented_and_additive():
    t = KIT.read_text()
    assert "\nDOCUMENTS=no\n" in t and "\nDOCUMENTS_BACKUP_DAYS=14\n" in t
    assert "\nSECURITY_ADDONS=no\n" in t and "\nREVIEW_DELEGATES=\n" in t
    i = t.index("DOCUMENTS=no")
    assert t[:i].rstrip().splitlines()[-1].startswith("#")
