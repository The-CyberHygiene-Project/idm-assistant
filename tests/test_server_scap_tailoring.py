"""Task 12 tailoring (owner decisions 2026-11-20): the SERVER's CUI profile, tailored to unselect exactly two rules,
each with its own justification: chronyd_client_only (the server serves NTP to the site LAN) and
sysctl_user_max_user_namespaces (the deviation every CHP install already carries: the kickstart's %post removes the
profile's sysctl; its reason is the one documented in docs/dc2-planning/dc2-cui-tailoring.xml, the tailoring the ISO
proofs scan with: lab/iso5/DEVIATIONS.md). The rule ids are the ones in the lab's Rocky 9 scan
(lab/reports/aero-cui-20260927-0029.html, scap-security-guide 0.1.82, ssg-rl9-ds.xml)."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

TOP = Path(__file__).resolve().parents[1]
SRV = TOP / "appliance/rpm/chp-identity-server"
TAILORING = SRV / "scap/chp-server-cui-tailoring.xml"
X = "{http://checklists.nist.gov/xccdf/1.2}"
CHRONY = "xccdf_org.ssgproject.content_rule_chronyd_client_only"
USERNS = "xccdf_org.ssgproject.content_rule_sysctl_user_max_user_namespaces"
JUSTIFICATION = ("Owner decision 2026-11-20: the CHP server serves time to the site LAN only (chrony allow <site "
                 "subnet>, bindaddress SERVER_IP, firewalld 123/udp from the site subnet); workstations sync from it and "
                 "never from outside sources.")
DC2 = TOP / "docs/dc2-planning/dc2-cui-tailoring.xml"
# the quoted reason, word for word as it stands in the source (whitespace normalised)
USERNS_QUOTE = ("The base \"cui\" profile sets user.max_user_namespaces = 0. On dc2 this conflicts with systemd's own "
                "unit-level sandboxing (PrivateUsers=true/yes, used by stock RHEL 9 irqbalance.service and "
                "upower.service, plus GNOME session helper units), which requires the ability to create at least one "
                "user namespace per sandboxed service and fails with ENOSPC when the kernel-wide limit is 0.")
NAME = "chp-server-cui-tailoring.xml"


def flat(s):
    return " ".join(s.split())


def profile():
    root = ET.parse(TAILORING).getroot()
    assert root.tag == X + "Tailoring"
    (p,) = root.findall(X + "Profile")
    return root, p


def test_the_rule_ids_are_the_ones_the_rocky_scan_reports():
    report = (TOP / "lab/reports/aero-cui-20260927-0029.html").read_text(errors="replace")
    assert CHRONY in report and USERNS in report and "scap-security-guide-0:0.1.82" in report


def test_tailoring_unselects_exactly_these_two_rules():
    root, p = profile()
    assert root.find(X + "benchmark").get("href") == "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml"
    assert p.get("extends") == "xccdf_org.ssgproject.content_profile_cui"
    assert p.get("id").startswith("xccdf_") and "_profile_" in p.get("id")
    sel = [(s.get("idref"), s.get("selected")) for s in p.findall(X + "select")]
    assert sorted(sel) == sorted([(CHRONY, "false"), (USERNS, "false")])
    assert not p.findall(X + "set-value") and not p.findall(X + "refine-value") and not p.findall(X + "refine-rule")


def test_each_rule_carries_its_own_justification():
    _, p = profile()
    remarks = {s.get("idref"): flat(s.find(X + "remark").text) for s in p.findall(X + "select")}
    assert JUSTIFICATION in remarks[CHRONY]
    assert USERNS_QUOTE in remarks[USERNS] and "docs/dc2-planning/dc2-cui-tailoring.xml" in remarks[USERNS]
    assert JUSTIFICATION not in remarks[USERNS] and USERNS_QUOTE not in remarks[CHRONY]
    d = flat(p.find(X + "description").text)
    assert JUSTIFICATION in d and USERNS_QUOTE in d


def test_the_quote_is_word_for_word_from_its_source():
    assert USERNS_QUOTE in flat(DC2.read_text())


def test_the_justifications_are_in_the_guide_and_known_issues():
    g = flat((TOP / "appliance/site-stick-kit/SITE-STICK.md").read_text())
    assert JUSTIFICATION in g and NAME in g and "sysctl_user_max_user_namespaces" in g and USERNS_QUOTE in g
    k = flat((TOP / "docs/release/0.7.0-known-issues.md").read_text())
    assert NAME in k and "chronyd_client_only" in k and "sysctl_user_max_user_namespaces" in k


def test_only_the_server_role_ships_or_names_it():
    spec = (SRV / "chp-identity-server.spec").read_text()
    assert re.search(r"^Source\d+:\s+chp-server-cui-tailoring\.xml$", spec, re.M)
    assert "%{_datadir}/chp/scap/chp-server-cui-tailoring.xml" in spec
    assert "scap/chp-server-cui-tailoring.xml" in (SRV / "build-rpm.sh").read_text()
    others = [p for p in (TOP / "appliance").rglob("*") if p.is_file() and p.suffix not in (".pyc", ".pyz")
              and SRV not in p.parents and "site-stick-kit" not in p.parts and "release" not in p.parts]
    hits = [str(p.relative_to(TOP)) for p in others if NAME in p.read_text(errors="ignore")]
    assert hits == [], hits                         # not the client role, not the kickstarts, not chp-site
