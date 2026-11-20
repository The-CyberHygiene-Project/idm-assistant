"""Task 12 tailoring (owner decision 2026-11-20): the SERVER's CUI profile, tailored to unselect exactly
chronyd_client_only (the server serves NTP to the site LAN). Workstations keep the stock profile. The rule id is the
one in the lab's Rocky 9 scan (lab/reports/aero-cui-20260927-0029.html, scap-security-guide 0.1.82, ssg-rl9-ds.xml)."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

TOP = Path(__file__).resolve().parents[1]
SRV = TOP / "appliance/rpm/chp-identity-server"
TAILORING = SRV / "scap/chp-server-cui-tailoring.xml"
X = "{http://checklists.nist.gov/xccdf/1.2}"
RULE = "xccdf_org.ssgproject.content_rule_chronyd_client_only"
JUSTIFICATION = ("Owner decision 2026-11-20: the CHP server serves time to the site LAN only (chrony allow <site "
                 "subnet>, bindaddress SERVER_IP, firewalld 123/udp from the site subnet); workstations sync from it and "
                 "never from outside sources.")
NAME = "chp-server-cui-tailoring.xml"


def flat(s):
    return " ".join(s.split())


def test_the_rule_id_is_the_one_the_rocky_scan_reports():
    report = (TOP / "lab/reports/aero-cui-20260927-0029.html").read_text(errors="replace")
    assert RULE in report and "scap-security-guide-0:0.1.82" in report


def test_tailoring_unselects_exactly_that_one_rule():
    root = ET.parse(TAILORING).getroot()
    assert root.tag == X + "Tailoring"
    b = root.find(X + "benchmark")
    assert b.get("href") == "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml"
    (p,) = root.findall(X + "Profile")
    assert p.get("extends") == "xccdf_org.ssgproject.content_profile_cui"
    assert p.get("id").startswith("xccdf_") and "_profile_" in p.get("id")
    sel = p.findall(X + "select")
    assert [(s.get("idref"), s.get("selected")) for s in sel] == [(RULE, "false")]
    assert not p.findall(X + "set-value") and not p.findall(X + "refine-value") and not p.findall(X + "refine-rule")


def test_the_justification_text_is_in_the_tailoring_and_the_guide():
    root = ET.parse(TAILORING).getroot()
    (p,) = root.findall(X + "Profile")
    assert JUSTIFICATION in flat(p.find(X + "description").text)
    sel = p.find(X + "select")
    assert JUSTIFICATION in flat(sel.find(X + "remark").text)
    g = flat((TOP / "appliance/site-stick-kit/SITE-STICK.md").read_text())
    assert JUSTIFICATION in g and NAME in g
    k = flat((TOP / "docs/release/0.7.0-known-issues.md").read_text())
    assert NAME in k and "chronyd_client_only" in k


def test_only_the_server_role_ships_or_names_it():
    spec = (SRV / "chp-identity-server.spec").read_text()
    assert re.search(r"^Source\d+:\s+chp-server-cui-tailoring\.xml$", spec, re.M)
    assert "%{_datadir}/chp/scap/chp-server-cui-tailoring.xml" in spec
    assert "scap/chp-server-cui-tailoring.xml" in (SRV / "build-rpm.sh").read_text()
    others = [p for p in (TOP / "appliance").rglob("*") if p.is_file() and p.suffix not in (".pyc", ".pyz")
              and SRV not in p.parents and "site-stick-kit" not in p.parts and "release" not in p.parts]
    hits = [str(p.relative_to(TOP)) for p in others if NAME in p.read_text(errors="ignore")]
    assert hits == [], hits                         # not the client role, not the kickstarts, not chp-site
