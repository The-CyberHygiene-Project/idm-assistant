"""ISO 0.7.0 Plan 3 Task 10: the guide's controlled-document chapter, the POA&M seed items and the known issues.

The guide is the kit's SITE-STICK.md. Every command it shows must parse with the real command line, and every POA&M
seed id it names must exist in the seed file (and the other way round for the new seeds)."""
import argparse
import re
import shlex
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "appliance" / "site-stick-kit"
GUIDE = KIT / "SITE-STICK.md"
SEEDS = KIT / "poam-seeds-0.7.0.md"
KNOWN = ROOT / "docs" / "release" / "0.7.0-known-issues.md"
NEW_SEEDS = [f"T-{n:02d}" for n in range(8, 17)]

sys.path.insert(0, str(ROOT / "appliance" / "chp-site"))


def chapter():
    g = GUIDE.read_text()
    start = g.index("### From 0.7.0 on: controlled documents")
    nxt = g.find("\n### ", start + 5)
    return g[start:nxt if nxt != -1 else len(g)]


def seed_ids():
    return re.findall(r"^\| (T-\d\d) \|", SEEDS.read_text(), re.M)


def test_guide_has_the_documents_chapter_and_its_parts():
    c = chapter()
    for h in ("What you need", "The author's day", "Handing the draft to the approver", "The approver's rules",
              "The ISSO override", "Answers and exit codes", "The ISSO's duties", "When the database cannot do MD5",
              "Site rules", "ONLYOFFICE on the workstation", "Alerts you will see", "Accounts outside Kanidm",
              "New installs, and the upgrade notes", "Open items"):
        assert f"#### {h}" in c, h


def test_guide_states_the_requirements_and_rules():
    c = " ".join(chapter().split())
    for s in ("8 GiB", "doc checkout", "doc approve", "doc publish", "-DRAFT", "reader checkout", "sha256",
              "DOC_ISSO_ACCOUNT", "DOC_APPROVER_ACCOUNTS", "never uploaded outside the CUI folders",
              "DEGRADED", "AllFonts", "ALERT_HOOK", "KillUserProcesses", "chp-publisher", "chp-canary",
              "doc-ledger resolve", "doc-ledger pending", "rpmnew", "new installs only", "not with the CUI banner",
              "logger -t", "ncadmin", "100622", "SECURITY_ALERT_LEVEL", "not yet proven in the lab", "Not supported in 0.7.0", "100606", "escrow/",
              "100629", "100628", "check 83", "check 82", "chrony"):
        assert s.lower() in c.lower(), s


def test_every_guide_command_parses_with_the_real_command_line(monkeypatch):
    from chp_site import cli
    for h in ("_doc", "_doc_ledger", "_documents", "_onlyoffice"):
        monkeypatch.setattr(cli, h, lambda a: 0)
    cmds = []
    for line in chapter().splitlines():
        for m in re.finditer(r"chp-site ((?:doc|doc-ledger|documents|onlyoffice)\b[^`]*)", line):
            t = m.group(1).strip().rstrip(".,;:")
            if "..." in t or "|" in t or len(t.split()) == 1:         # prose such as "run chp-site doc as yourself"
                continue
            if t.split()[0] == "doc" and len(t.split()) == 2 and t.split()[1] not in ("login", "logout"):   # a name in prose
                continue
            cmds.append(t)
    assert len(cmds) >= 12
    for t in cmds:
        argv = shlex.split(re.sub(r"<[^>]+>", "x", t))
        try:
            rc = cli.main(argv)
        except SystemExit as e:                                   # argparse refused it
            pytest.fail(f"the guide shows a command the program refuses: chp-site {t} ({e})")
        assert rc == 0, t


def test_every_doc_subcommand_is_in_the_guide():
    from chp_site import doc
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    dp = doc.add_parser(sub)
    names = set(dp._subparsers._group_actions[0].choices)
    c = chapter()
    for n in sorted(names):
        assert f"chp-site doc {n}" in c, n


def test_the_seed_file_follows_the_template_row_format():
    t = SEEDS.read_text()
    assert seed_ids() == NEW_SEEDS
    for ln in t.splitlines():
        if re.match(r"\| T-\d\d \|", ln):
            cells = [x.strip() for x in ln.strip().strip("|").split("|")]
            assert len(cells) == 8, ln
            assert cells[1] == "Rev 2" and cells[-1] == "Open", ln
            assert "Seeded by the template: confirm, adapt or close." in cells[3], ln
            assert re.fullmatch(r"\{\{poam\.due_t\d\d\}\}", cells[5]), ln
            assert cells[6] == "{{roles.security_officer}}" or cells[6] == "{{roles.administrator}}", ln


def test_guide_poam_refs():
    """Every POA&M seed id the guide (or the known issues) names exists in the seed file, and every new seed is
    named in both."""
    have = set(seed_ids())
    for path in (GUIDE, KNOWN):
        named = set(re.findall(r"\bT-\d\d\b", path.read_text()))
        if path == GUIDE:
            named = set(re.findall(r"\bT-\d\d\b", chapter()))
        assert named <= have | {f"T-{n:02d}" for n in range(1, 8)}, (path.name, sorted(named - have))
        assert set(NEW_SEEDS) <= named, (path.name, sorted(set(NEW_SEEDS) - named))


def test_seed_text_is_public_safe():
    for p in (SEEDS, KNOWN, GUIDE):
        t = p.read_text()
        assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", re.sub(r"192\.0\.2\.\d+|0\.0\.0\.0|127\.0\.0\.1", "", t)), p.name
        assert not re.search(r"(?i)claude|anthropic|chatgpt", t), p.name


def test_known_issues_file_covers_the_open_issues():
    k = KNOWN.read_text()
    for s in ("# ISO 0.7.0 known issues", "MD5", "fapolicyd", "recvmesg failed", "FSMARK=0", "BoringSSL", "--no-sandbox",
              "PHP 8.3", "NextCloud 37", "OIDC", "forge", "DNS", "chp-publisher", "ncadmin", "SECURITY_ALERT_LEVEL", "banner", "FCI", "8 GiB",
              "new installs only", "download"):
        assert s.lower() in k.lower(), s


def test_13a_d5_first_enable_raises_100623_five_times_in_the_guide():
    """P3-D5 (logs/139): ncadmin made + added to admin, chp-publisher made + added to chp-users and cui-users."""
    for text in (GUIDE.read_text(), KNOWN.read_text()):
        flat = " ".join(text.split())
        i = flat.index("100623")
        part = flat[i:i + 600]
        assert "five times" in part and "twice" not in part and "chp-publisher" in part and "ncadmin" in part


def test_13a_d7_the_guide_does_not_promise_the_lockdown_line_arrives():
    flat = " ".join(GUIDE.read_text().split())
    assert "It arrives only after the link is back" not in flat
    assert "may never reach the manager" in flat and "EGRESS RECOVERED after LOCKDOWN" in flat and "100635" in flat
    known = " ".join(KNOWN.read_text().split())
    assert "which arrives after recovery" not in known and "100635" in known
