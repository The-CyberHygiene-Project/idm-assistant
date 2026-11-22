"""Plan 3 Task 6: the workstation commands `chp-site doc ...` (chp_site.doc), through chp-site's command line. The stub
of test_doc_auth plays NextCloud (WebDAV + chp_ledger) and Kanidm; x2t is a fake script; templates are the marking
fixtures (made-up values only)."""
import base64
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from chp_site import cli, doc as DOC, doc_auth as A
from chp_site import marking as M
from tests.test_doc_auth import Clock, Stub, login, make_env

FX = Path(__file__).resolve().parent / "fixtures" / "marking"
SITE = {"DOMAIN": "example.test", "CUI_CONTROLLED_BY": "Example Office (made-up)", "CUI_CATEGORY": "PROPIN (made-up)",
        "CUI_POC": "A. Example, 555-0100 (made-up)"}
MARKED = (FX / "CUI_Access-Policy_v1.0.docx").read_bytes()      # banner top and bottom + the block, made-up values
BLOCK = ["Controlled by: Example Office (made-up)", "CUI Category: PROPIN (made-up)",
         "POC: A. Example, 555-0100 (made-up)"]

FAKE_X2T = """#!{py}
import sys, xml.etree.ElementTree as ET
p = ET.parse(sys.argv[1]).getroot()
open({log!r}, "a").write(open(sys.argv[1]).read() + "\\n----\\n")
open(p.findtext("m_sFileTo"), "wb").write(b"%PDF-1.4 fake reader copy of " + open(p.findtext("m_sFileFrom"), "rb").read()[:8])
"""


def setup(tmp_path, user="alice", sign_in=True, clock=None):
    clock = clock or Clock()
    stub = Stub(clock, user=user)
    stub.put("CUI/Compliance/CUI_SSP_v1.2.docx", MARKED)
    stub.put("Internal/Compliance/Access-Policy_v1.0.docx", (FX / "Access-Policy_v1.0.docx").read_bytes())
    tpl = tmp_path / "templates"
    for area, src in (("cui", "CUI_Access-Policy_v1.0.docx"), ("noncui", "Access-Policy_v1.0.docx")):
        (tpl / area).mkdir(parents=True)
        shutil.copyfile(FX / src, tpl / area / "Template.docx")
    shutil.copyfile(FX / "CUI_Notes_v0.1-DRAFT.md", tpl / "cui" / "Template.md")      # unmarked: doc new marks it
    (tpl / "fci").mkdir()
    shutil.copyfile(FX / "FCI_Notice_v1.0.docx", tpl / "fci" / "Template.docx")
    shutil.copyfile(FX / "FCI_Notes_v0.1-DRAFT.md", tpl / "fci" / "Template.md")      # unmarked: doc new marks it
    x2t = tmp_path / "x2t"
    x2t.write_text(FAKE_X2T.format(py=sys.executable, log=str(tmp_path / "x2t.log")))
    x2t.chmod(0o755)
    env = make_env(tmp_path, stub, clock, site=dict(SITE), templates=str(tpl), x2t=str(x2t),
                   editor_running=lambda env: False)
    fonts = env.home / ".local/share/onlyoffice/desktopeditors/data/fonts"
    fonts.mkdir(parents=True)
    (fonts / "AllFonts.js").write_text("// made by the first GUI run\n")
    if sign_in:
        login(env)
    return env


def run(env, monkeypatch, capsys, *argv):
    monkeypatch.setattr(DOC, "system_env", lambda: env)
    rc = cli.main(["doc", *argv])
    out = capsys.readouterr()
    return rc, out.out + out.err


def work(env):
    return env.home / "Documents" / "CHP-Working"


def posts(env):
    return [b for b, _ in env.stub.requests]


def banner_pdf(monkeypatch, ok=True):
    """marking's poppler seam: the reader PDF reads as banner top and bottom + the block (or without a banner)."""
    pages = [["CUI"] + BLOCK + ["text", "CUI"], ["CUI", "more", "CUI"]] if ok else [["text"], ["more"]]

    def run(tool, args):
        if tool == "pdfinfo":
            return f"Pages: {len(pages)}\n"
        return "\n".join(pages[int(args[args.index("-f") + 1]) - 1]) + "\n\f"
    monkeypatch.setattr(M, "_tool", lambda name: "/bin/true")
    monkeypatch.setattr(M, "_poppler", run)


# ---------- checkout ----------

def test_checkout_records_server_sha_and_file_id(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 0, out
    fid = env.stub.ids["CUI/Compliance/CUI_SSP_v1.2.docx"]
    (b,) = posts(env)
    assert b["kind"] == "checkout" and b["file_id"] == fid and "sha256" not in b and "path" not in b
    assert len(b["request_id"]) == 32 and int(b["request_id"], 16) >= 0
    w = work(env)
    assert stat.S_IMODE(w.stat().st_mode) == 0o700
    f = w / "CUI_SSP_v1.3-DRAFT.docx"                       # the next version, as a draft
    assert f.read_bytes() == MARKED and stat.S_IMODE(f.stat().st_mode) == 0o600
    rec = DOC.Records(w).get(f.name)
    assert rec["file_id"] == fid and rec["folder_id"] == env.stub.ids["CUI/Compliance"] and rec["cui"] is True
    assert rec["sha256"] == hashlib.sha256(MARKED).hexdigest()  # the value the SERVER recorded (ledger entry)
    assert rec["name"] == "CUI_SSP_v1.2.docx" and rec["seq"] == 1
    assert "ONLYOFFICE" in out and "CUI_SSP_v1.3-DRAFT.docx" in out

    # the canonical copy changes between the server's record and the download: no working copy is kept
    (tmp_path / "two").mkdir()
    env2 = setup(tmp_path / "two")
    orig = env2.stub._result

    def changed(rid):
        r = orig(rid)
        env2.stub.put("CUI/Compliance/CUI_SSP_v1.2.docx", MARKED + b"admin edit")
        return r
    env2.stub._result = changed
    rc, out = run(env2, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 3 and "changed" in out and "refused" not in out and "WAS recorded" in out          # 13a follow-up
    assert "author of this cycle" in out and "checkout CUI_SSP_v1.2.docx again" in out
    assert not (work(env2) / "CUI_SSP_v1.3-DRAFT.docx").exists()
    assert DOC.Records(work(env2)).get("CUI_SSP_v1.3-DRAFT.docx") is None


def test_checkout_refusals_are_plain(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_Nothing_v1.0.docx")
    assert rc == 2 and "not found" in out and "Traceback" not in out and not posts(env)
    rc, out = run(env, monkeypatch, capsys, "checkout", "SSP with spaces.docx")
    assert rc == 2 and "name rule" in out and not posts(env)
    work(env).mkdir(parents=True, exist_ok=True)
    os.chmod(work(env), 0o755)                              # a working folder others can read: refused
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 2 and "0700" in out and not posts(env)
    os.chmod(work(env), 0o700)
    Path(env.mounts).write_text(Path(env.mounts).read_text().replace("/dev/mapper/rl-home", "/dev/sdb1"))
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 2 and "LUKS2" in out and not posts(env)


def test_checkout_by_path_and_ledger_refusal(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    env.stub.script["*"] = ["refused: CUI_SSP.docx already has a change in progress"]
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI/Compliance/CUI_SSP_v1.2.docx")
    assert rc == 1 and "already has a change in progress" in out
    assert not (work(env) / "CUI_SSP_v1.3-DRAFT.docx").exists()


# ---------- new ----------

def test_new_from_marked_template_is_draft(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    rc, out = run(env, monkeypatch, capsys, "new", "Incident-Plan", "--cui")
    assert rc == 0, out
    f = work(env) / "CUI_Incident-Plan_v0.1-DRAFT.docx"
    assert M.parse_name(f.name).draft
    assert M.check(f, True, M.MarkValues.from_site(SITE)).ok
    (b,) = posts(env)
    assert b == {"kind": "new", "file_id": env.stub.ids["CUI/Compliance"], "path": f.name,
                 "request_id": b["request_id"]}
    assert DOC.Records(work(env)).get(f.name)["folder_id"] == env.stub.ids["CUI/Compliance"]
    assert "ONLYOFFICE" in out
    # an unmarked template (md) is marked from the site keys on the way in
    rc, out = run(env, monkeypatch, capsys, "new", "Notes", "--cui", "--type", "md")
    assert rc == 0, out
    md = work(env) / "CUI_Notes_v0.1-DRAFT.md"
    assert M.check(md, True, M.MarkValues.from_site(SITE)).ok
    assert (tmp_path / "templates/cui/Template.md").read_bytes() == (FX / "CUI_Notes_v0.1-DRAFT.md").read_bytes()
    # non-CUI: no prefix, the Internal area
    rc, out = run(env, monkeypatch, capsys, "new", "Backup-Procedure", "--non-cui")
    assert rc == 0, out
    assert (work(env) / "Backup-Procedure_v0.1-DRAFT.docx").exists()
    assert posts(env)[-1]["file_id"] == env.stub.ids["Internal/Compliance"]


def test_new_refusals_are_plain(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    rc, out = run(env, monkeypatch, capsys, "new", "Plan", "--cui", "--type", "xlsx")   # template not installed
    assert rc == 2 and "chp-templates" in out and not posts(env)
    rc, out = run(env, monkeypatch, capsys, "new", "Two words", "--cui")
    assert rc == 2 and "name rule" in out and not posts(env)
    env.site = {"DOMAIN": "example.test"}                    # marking values not set: a CUI document cannot be marked
    rc, out = run(env, monkeypatch, capsys, "new", "Plan", "--cui")
    assert rc == 2 and "CUI_CONTROLLED_BY" in out and not posts(env)
    with pytest.raises(SystemExit):                          # --cui or --non-cui is required
        run(env, monkeypatch, capsys, "new", "Plan")
    assert not posts(env)


def test_new_fci_from_the_fci_template(tmp_path, monkeypatch, capsys):
    """Owner decision 2026-11-20: an FCI document is FCI_<title>, marked "FCI" (no CUI designation block, no CUI site
    keys needed), and it lives in CUI/Compliance with the CUI_ documents (the name rule's FCI_ prefix)."""
    env = setup(tmp_path)
    env.site = {"DOMAIN": "example.test"}                    # no CUI marking keys: FCI does not need them
    rc, out = run(env, monkeypatch, capsys, "new", "Quote-Terms", "--fci")
    assert rc == 0, out
    f = work(env) / "FCI_Quote-Terms_v0.1-DRAFT.docx"
    assert f.read_bytes() == (tmp_path / "templates/fci/Template.docx").read_bytes()    # marked by construction
    rep = M.check(f, True, M.MarkValues())
    assert rep.ok, rep.problems
    (b,) = posts(env)
    assert b == {"kind": "new", "file_id": env.stub.ids["CUI/Compliance"], "path": f.name,
                 "request_id": b["request_id"]}
    rec = DOC.Records(work(env)).get(f.name)
    assert rec["folder_id"] == env.stub.ids["CUI/Compliance"] and rec["cui"] is True
    # an unmarked FCI template (md) gets the FCI banner only
    rc, out = run(env, monkeypatch, capsys, "new", "Notes", "--fci", "--type", "md")
    assert rc == 0, out
    md = work(env) / "FCI_Notes_v0.1-DRAFT.md"
    lines = md.read_text().splitlines()
    assert lines[0] == "FCI" and lines[-1] == "FCI" and "Controlled by" not in md.read_text()
    assert M.check(md, True, M.MarkValues()).ok
    # doc check reports the FCI marking
    rc, out = run(env, monkeypatch, capsys, "check", str(md))
    assert "FCI" in out and "PROBLEM" not in out, out


def test_check_label_follows_the_checkers_reading_of_the_name(tmp_path, monkeypatch, capsys):
    """m9: a name that does not parse is checked as CUI (the strictest reading), and the label says so."""
    env = setup(tmp_path)
    work(env).mkdir(parents=True, mode=0o700)
    f = work(env) / "FCI_Two words_v1.0.md"
    f.write_text("FCI\n\nx\n\nFCI\n")
    rc, out = run(env, monkeypatch, capsys, "check", str(f))
    assert "(CUI marks)" in out and "(FCI banner)" not in out, out


def test_new_fci_refusals(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    rc, out = run(env, monkeypatch, capsys, "new", "Plan", "--fci", "--type", "xlsx")   # template not installed
    assert rc == 2 and "chp-templates" in out and "fci" in out and not posts(env)
    for both in (("--fci", "--cui"), ("--fci", "--non-cui")):
        with pytest.raises(SystemExit):                      # one of --cui, --fci, --non-cui
            run(env, monkeypatch, capsys, "new", "Plan", *both)
    # a template that carries the CUI marks is refused, never sent (the check runs before the request)
    shutil.copyfile(FX / "CUI_Access-Policy_v1.0.docx", tmp_path / "templates/fci/Template.docx")
    rc, out = run(env, monkeypatch, capsys, "new", "Plan", "--fci")
    assert rc == 2 and "a CUI banner" in out and not posts(env)


# ---------- check / mark ----------

def test_check_is_dry_run(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    w = work(env)
    w.mkdir(parents=True, mode=0o700)
    f = w / "CUI_Plan_v0.1-DRAFT.docx"
    shutil.copyfile(FX / "CUI_Plan_v0.1-DRAFT.docx", f)
    before = (f.read_bytes(), f.stat().st_mtime_ns, sorted(os.listdir(w)))
    rc, out = run(env, monkeypatch, capsys, "check", str(f))
    assert rc == 1 and "banner" in out and "-DRAFT" in out
    assert (f.read_bytes(), f.stat().st_mtime_ns, sorted(os.listdir(w))) == before
    assert not posts(env)
    # the citation check: the area's current versions come from the server listing
    n = w / "CUI_Notes_v0.1-DRAFT.md"
    shutil.copyfile(FX / "CUI_Notes_v0.1-DRAFT.md", n)
    rc, out = run(env, monkeypatch, capsys, "check", str(n))
    assert "CUI_SSP_v1.0 is cited" in out and "v1.2" in out
    assert not posts(env)
    # freshness: checked out, then the canonical copy moved on
    rc, _ = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 0
    n_posts = len(posts(env))
    rc, out = run(env, monkeypatch, capsys, "check", str(w / "CUI_SSP_v1.3-DRAFT.docx"))
    assert rc == 0 and "fresh" in out, out
    env.stub.put("CUI/Compliance/CUI_SSP_v1.2.docx", MARKED + b"x")
    rc, out = run(env, monkeypatch, capsys, "check", str(w / "CUI_SSP_v1.3-DRAFT.docx"))
    assert rc == 1 and "changed since" in out
    assert len(posts(env)) == n_posts
    # a site.conf that cannot be read is a plain message, never a traceback
    env.site = None
    env.site_dir = str(tmp_path / "no-such-site")
    rc, out = run(env, monkeypatch, capsys, "check", str(f))
    assert rc == 2 and "site.conf" in out and "Traceback" not in out


def test_mark_is_dry_run_unless_apply(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, sign_in=False)
    w = work(env)
    w.mkdir(parents=True, mode=0o700)
    f = w / "CUI_Plan_v0.1-DRAFT.docx"
    shutil.copyfile(FX / "CUI_Plan_v0.1-DRAFT.docx", f)
    before = f.read_bytes()
    rc, out = run(env, monkeypatch, capsys, "mark", str(f))
    assert rc == 0 and "dry run" in out and f.read_bytes() == before
    rc, out = run(env, monkeypatch, capsys, "mark", str(f), "--apply")
    assert rc == 0 and f.read_bytes() != before
    assert M.check(f, True, M.MarkValues.from_site(SITE)).ok
    g = w / "CUI_Plan_v1.0.docx"
    shutil.copyfile(FX / "CUI_Plan_v1.0.docx", g)
    rc, out = run(env, monkeypatch, capsys, "mark", str(g), "--apply")
    assert rc == 1 and "-DRAFT" in out


# ---------- approve / override ----------

def test_approve_shows_ledger_result(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = tmp_path / "from-alice" / "CUI_SSP_v1.3-DRAFT.docx"   # the approver's copy (no checkout of their own)
    f.parent.mkdir()
    f.write_bytes(MARKED)
    rc, out = run(env, monkeypatch, capsys, "approve", str(f), "--notes", "read in full (made-up)")
    assert rc == 0, out
    (b,) = posts(env)
    assert b["kind"] == "approve" and b["file_id"] == env.stub.ids["CUI/Compliance"]
    assert b["path"] == f.name and b["sha256"] == hashlib.sha256(MARKED).hexdigest()
    assert b["notes"] == "read in full (made-up)"
    assert "approve recorded (ledger entry 1)" in out
    # refused by the ledger: shown as it is, exit 1
    env.stub.script["*"] = ["refused: bob checked it out in this cycle, so bob is an author of this change"]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 1 and "bob is an author" in out
    # an unmarked file is refused here, before anything is sent
    g = f.parent / "CUI_Plan_v0.1-DRAFT.docx"
    shutil.copyfile(FX / "CUI_Plan_v0.1-DRAFT.docx", g)
    n = len(posts(env))
    rc, out = run(env, monkeypatch, capsys, "approve", str(g))
    assert rc == 1 and "banner" in out and len(posts(env)) == n


def test_override_needs_reason(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    f = tmp_path / "CUI_SSP_v1.3-DRAFT.docx"
    f.write_bytes(MARKED)
    with pytest.raises(SystemExit):
        cli.main(["doc", "override", str(f)])
    capsys.readouterr()
    rc, out = run(env, monkeypatch, capsys, "override", str(f), "--reason", "one-person site (made-up)")
    assert rc == 0, out
    assert posts(env)[-1]["kind"] == "override" and posts(env)[-1]["reason"] == "one-person site (made-up)"


# ---------- publish ----------

def _approved_draft(env, monkeypatch, capsys):
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 0, out
    return work(env) / "CUI_SSP_v1.3-DRAFT.docx"


def test_publish_strips_draft_only_via_explicit_rename(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    banner_pdf(monkeypatch)
    d = _approved_draft(env, monkeypatch, capsys)
    n = len(posts(env))
    rc, out = run(env, monkeypatch, capsys, "publish", str(d))
    assert rc == 2 and "-DRAFT" in out and "rename" in out
    assert len(posts(env)) == n and d.exists() and sorted(os.listdir(work(env))) == [".chp-doc", d.name]
    final = d.with_name("CUI_SSP_v1.3.docx")
    os.rename(d, final)                                      # the author renames it, unchanged
    rc, out = run(env, monkeypatch, capsys, "publish", str(final))
    assert rc == 0, out
    b = posts(env)[-1]
    assert b["kind"] == "publish" and b["path"] == "CUI_SSP_v1.3.docx"
    assert b["file_id"] == env.stub.ids["CUI/Compliance"]
    assert final.exists() and not d.exists()                 # publish renamed nothing
    assert "CR-2027-" in out


def test_publish_makes_reader_pdf_with_x2t(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    banner_pdf(monkeypatch)
    d = _approved_draft(env, monkeypatch, capsys)
    final = d.with_name("CUI_SSP_v1.3.docx")
    os.rename(d, final)
    rc, out = run(env, monkeypatch, capsys, "publish", str(final))
    assert rc == 0, out
    b = posts(env)[-1]
    assert base64.b64decode(b["content"]) == MARKED
    assert b["sha256"] == hashlib.sha256(MARKED).hexdigest()
    assert base64.b64decode(b["pdf_content"]) == b"%PDF-1.4 fake reader copy of " + MARKED[:8]
    log = (tmp_path / "x2t.log").read_text()
    assert "<m_nFormatTo>513</m_nFormatTo>" in log
    assert str(env.home / ".local/share/onlyoffice/desktopeditors/data/fonts/AllFonts.js") in log
    assert sorted(os.listdir(work(env))) == [".chp-doc", final.name]   # the PDF's work files are gone
    # a reader PDF without its banner: refused here, nothing sent
    banner_pdf(monkeypatch, ok=False)
    n = len(posts(env))
    final2 = final.with_name("CUI_SSP_v1.4.docx")
    shutil.copyfile(final, final2)
    rc, out = run(env, monkeypatch, capsys, "publish", str(final2))
    assert rc == 1 and "reader PDF" in out and len(posts(env)) == n
    # x2t needs ONLYOFFICE's first GUI run
    banner_pdf(monkeypatch)
    os.unlink(env.home / ".local/share/onlyoffice/desktopeditors/data/fonts/AllFonts.js")
    rc, out = run(env, monkeypatch, capsys, "publish", str(final2))
    assert rc == 2 and "ONLYOFFICE" in out and len(posts(env)) == n


def test_publish_refuses_a_stale_checkout_before_sending(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    banner_pdf(monkeypatch)
    d = _approved_draft(env, monkeypatch, capsys)
    final = d.with_name("CUI_SSP_v1.3.docx")
    os.rename(d, final)
    env.stub.put("CUI/Compliance/CUI_SSP_v1.2.docx", MARKED + b"admin edit")
    n = len(posts(env))
    rc, out = run(env, monkeypatch, capsys, "publish", str(final))
    assert rc == 1 and "changed since" in out and len(posts(env)) == n


# ---------- retry / pending ----------

def test_pending_message_on_retry(tmp_path, monkeypatch, capsys):
    clock = Clock()
    env = setup(tmp_path, user="bob", clock=clock)
    f = tmp_path / "CUI_SSP_v1.3-DRAFT.docx"
    f.write_bytes(MARKED)
    clock.t += 900 - 30                                       # 30 s left on the access token
    env.stub.script["*"] = ["retry"] * 50
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and "run" in out and "again" in out
    ps = env.stub.requests
    assert len(ps) == DOC.RETRIES
    assert len({b["request_id"] for b, _ in ps}) == 1         # the SAME request id every time
    assert ps[0][1] != "at1"                                  # refreshed before the first send
    assert len({t for _, t in ps}) == len(ps)                 # a fresh token for every re-send
    rid = ps[0][0]["request_id"]
    # run again: the same request id once more; a 409 on the reused id means "poll", not failure
    env.stub.script["*"] = []
    env.stub.post_status[rid] = [409]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 0 and "approve recorded" in out, out
    assert env.stub.requests[-1][0]["request_id"] == rid
    # done: the next approve is a new request
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert env.stub.requests[-1][0]["request_id"] != rid


def test_pending_when_the_ledger_never_answers(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = tmp_path / "CUI_SSP_v1.3-DRAFT.docx"
    f.write_bytes(MARKED)
    env.stub.script["*"] = ["queued"] * 100000
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and len(env.stub.requests) == 1


def test_not_signed_in_is_plain(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, sign_in=False)
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 2 and "chp-site doc login" in out and "Traceback" not in out


# ---------- close (G2) ----------

def test_close_removes_autosave_and_recents(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    d = _approved_draft(env, monkeypatch, capsys)
    oo = env.home / ".local/share/onlyoffice/desktopeditors"
    mine, other = oo / "data/recover/DE__abc123", oo / "data/recover/DE__xyz789"
    for r, name in ((mine, d.name), (other, "CUI_Other_v0.1-DRAFT.docx")):
        r.mkdir(parents=True)
        (r / name).write_bytes(b"autosaved copy (made-up)")
        (r / "Editor.bin").write_bytes(b"\0" * 8)
        (r / "asc_name.info").write_text(name)
    older = oo / "data/recover/DE__old000"                   # an earlier name of the same document (before a rename)
    older.mkdir()
    (older / "CUI_SSP_v1.3-DRAFT.docx").write_bytes(b"x")
    keep = str(env.home / "elsewhere" / "Report.docx")
    recents = oo / "data" / "recents.xml"
    recents.write_bytes(
        b'\xef\xbb\xbf<?xml version="1.0" encoding="utf-8"?><recents>'
        + f'<file path="{d}" type="65" date="12.11.2026 19:00" url="" parent="{d.parent}" />'.encode()
        + f'<file path="{keep}" type="65" date="12.11.2026 18:00" url="" parent="{env.home}" />'.encode()
        + b"</recents>")
    # the editor still running: refused, nothing removed
    env.editor_running = lambda env: True
    rc, out = run(env, monkeypatch, capsys, "close", str(d))
    assert rc == 2 and "ONLYOFFICE" in out and d.exists() and mine.exists()
    env.editor_running = lambda env: False
    rc, out = run(env, monkeypatch, capsys, "close", str(d))
    assert rc == 0, out
    assert not d.exists() and not mine.exists() and not older.exists() and other.exists()
    text = recents.read_bytes()
    assert text.startswith(b"\xef\xbb\xbf") and str(d).encode() not in text and keep.encode() in text
    assert DOC.Records(work(env)).get(d.name) is None
    # the function Task 8's sweep calls
    assert DOC.remove_editor_copies(env.home, lambda p: Path(p).name == "CUI_Other_v0.1-DRAFT.docx")
    assert not other.exists()


# ---------- fix round 1 ----------

def _draft(tmp_path):
    f = tmp_path / "CUI_SSP_v1.3-DRAFT.docx"
    f.write_bytes(MARKED)
    return f


def _pending_ids(env):
    p = Path(env.runtime) / "chp-doc" / "pending.json"
    return json.loads(p.read_text()) if p.exists() else {}


def test_session_end_after_the_post_is_pending_not_refused(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    orig = env.stub._request

    def then_logout(b, bearer):                             # `doc logout` in another terminal, right after the POST
        r = orig(b, bearer)
        os.unlink(Path(env.runtime) / "chp-doc" / "session.json")
        return r
    env.stub._request = then_logout
    env.stub.script["*"] = ["queued"]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and "chp-site doc login" in out and "run the same command again" in out
    rid = env.stub.requests[0][0]["request_id"]
    assert list(_pending_ids(env).values()) == [rid]        # the id is kept
    env.stub._request = orig
    login(env)
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 0 and env.stub.requests[-1][0]["request_id"] == rid


def test_rate_limit_on_a_reused_id_is_pending(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    env.stub.script["*"] = ["retry"] * 50
    rc, _ = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3
    rid = env.stub.requests[0][0]["request_id"]
    env.stub.script["*"] = []
    env.stub.post_status[rid] = [429]                       # the rate limit is checked before earlier results
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and list(_pending_ids(env).values()) == [rid]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 0 and env.stub.requests[-1][0]["request_id"] == rid and not _pending_ids(env)
    # the FIRST post of a new id refused by the app (nothing spooled): a refusal, the id dropped
    g = tmp_path / "CUI_Other_v0.1-DRAFT.docx"
    g.write_bytes(MARKED)
    orig = env.stub._request
    env.stub._request = lambda b, bearer: (403, {}, b'{"ocs":{"data":{"state":"refused","message":"refused: not '
                                                    b'a controlled document you can use"}}}')
    rc, out = run(env, monkeypatch, capsys, "approve", str(g))
    assert rc == 1 and "not a controlled document" in out and not _pending_ids(env)
    env.stub._request = orig


def test_unreachable_401_and_500_routes(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    stub = env.stub
    # Kanidm unreachable on the forced refresh after a retry: pending, id kept
    stub.script["*"] = ["retry"]

    def kanidm_down(method, url, headers=None, body=None):
        if "idm." in url:
            raise OSError("no route to host")
        return stub(method, url, headers, body)
    env.transport = kanidm_down
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "could not be reached" in out and len(_pending_ids(env)) == 1
    rid = stub.requests[-1][0]["request_id"]
    # NextCloud unreachable on the POST: pending, id kept
    env.transport = lambda method, url, headers=None, body=None: (_ for _ in ()).throw(OSError("connection reset")) \
        if url.endswith("/request?format=json") else stub(method, url, headers, body)
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and list(_pending_ids(env).values()) == [rid]
    # 500 on the reused id: poll it, done
    env.transport = stub
    stub.script["*"] = []
    stub.post_status[rid] = [500]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 0 and "approve recorded" in out
    # 401 on the POST (NextCloud no longer takes the token): a forced refresh, then the same request again
    n, tried = len(stub.requests), []

    def first_post_401(method, url, headers=None, body=None):
        if url.endswith("/request?format=json") and not tried:
            tried.append(headers["Authorization"])
            return 401, {}, b""
        return stub(method, url, headers, body)
    env.transport = first_post_401
    rc, out = run(env, monkeypatch, capsys, "approve", str(f), "--notes", "second (made-up)")
    assert rc == 0, out
    assert len(stub.requests) == n + 1 and "Bearer " + stub.requests[-1][1] != tried[0]   # re-sent, new token
    assert stub.requests[-1][0]["request_id"] != rid


def test_fresh_token_after_a_long_wait(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    env.poll_timeout = 5000
    env.stub.script["*"] = ["queued"] * 1000                # the checkout poll takes 1000 s: past the 900 s token
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 0, out
    env.stub.script["*"] = []
    banner_pdf(monkeypatch)
    d = work(env) / "CUI_SSP_v1.3-DRAFT.docx"
    final = d.with_name("CUI_SSP_v1.3.docx")
    os.rename(d, final)
    DOC.Records(work(env)).drop(final.name)                 # no record: the folder comes from the server (a fresh token)
    slow = DOC.reader_pdf

    def x2t_takes_long(env_, f, tmp):                       # x2t takes 1000 s
        env.clock.t += 1000
        return slow(env_, f, tmp)
    monkeypatch.setattr(DOC, "reader_pdf", x2t_takes_long)
    rc, out = run(env, monkeypatch, capsys, "publish", str(final))
    assert rc == 0, out


def test_pending_ids_are_locked(tmp_path, monkeypatch):
    import threading
    import time
    env = setup(tmp_path, sign_in=False)
    real = A.write_private

    def slow(path, obj):
        time.sleep(0.05)
        real(path, obj)
    monkeypatch.setattr(A, "write_private", slow)
    ts = [threading.Thread(target=DOC._Pending(env).put, args=(f"k{i}", f"{i:032x}")) for i in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    assert sorted(_pending_ids(env)) == sorted(f"k{i}" for i in range(6))


def test_plain_messages_not_tracebacks(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    env.stub.dav_garbage = True
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 2 and "could not be read" in out and "Traceback" not in out
    env.stub.dav_garbage = False
    tpl = tmp_path / "templates/cui/Template.docx"
    os.chmod(tpl, 0)                                        # a file you cannot read
    try:
        rc, out = run(env, monkeypatch, capsys, "new", "Plan", "--cui")
    finally:
        os.chmod(tpl, 0o644)
    assert rc == 2 and "ermission denied" in out and "Traceback" not in out and not posts(env)


def test_x2t_gets_a_private_tmpdir(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    banner_pdf(monkeypatch)
    monkeypatch.setenv("CHP_SENTINEL_MADE_UP", "x")
    x2t = Path(env.x2t)
    x2t.write_text(x2t.read_text() + "import os\nopen({!r}, 'w').write(repr(dict(os.environ)))\n".format(
        str(tmp_path / "x2t.env")))
    d = _approved_draft(env, monkeypatch, capsys)
    final = d.with_name("CUI_SSP_v1.3.docx")
    os.rename(d, final)
    rc, out = run(env, monkeypatch, capsys, "publish", str(final))
    assert rc == 0, out
    seen = eval((tmp_path / "x2t.env").read_text())
    base = str(work(env) / ".chp-doc")
    assert seen["TMPDIR"].startswith(base) and seen["TMP"] == seen["TEMP"] == seen["TMPDIR"]
    assert seen["HOME"] == str(env.home) and "CHP_SENTINEL_MADE_UP" not in seen
    assert not os.path.exists(seen["TMPDIR"])               # removed with the rest of the PDF's work files


def test_close_does_not_follow_a_symlinked_recover_folder(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    d = _approved_draft(env, monkeypatch, capsys)
    outside = tmp_path / "elsewhere"
    (outside / "DE__abc123").mkdir(parents=True)
    (outside / "DE__abc123" / d.name).write_bytes(b"not the editor's (made-up)")
    data = env.home / ".local/share/onlyoffice/desktopeditors/data"
    os.symlink(outside, data / "recover")
    rc, out = run(env, monkeypatch, capsys, "close", str(d))
    assert rc == 0 and "symbolic link" in out
    assert (outside / "DE__abc123" / d.name).exists() and not d.exists()


# ---------- Task 11a item 5: lasting refusals of a kept id; a proxy's 502/503/504 on the first POST ----------

def _kept_id(env, monkeypatch, capsys, f):
    """A request id kept from a run whose POST never reached NextCloud (so the server holds nothing for it)."""
    stub = env.stub
    env.transport = lambda method, url, headers=None, body=None: (_ for _ in ()).throw(OSError("connection reset")) \
        if url.endswith("/request?format=json") else stub(method, url, headers, body)
    rc, _ = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3
    env.transport = stub
    (rid,) = _pending_ids(env).values()
    return rid


@pytest.mark.parametrize("st", [400, 403, 413])
def test_a_lasting_4xx_on_a_kept_id_is_refused_and_the_id_dropped(tmp_path, monkeypatch, capsys, st):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    rid = _kept_id(env, monkeypatch, capsys, f)
    env.stub.post_status[rid] = [st]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 1 and "refused" in out and "pending" not in out, out
    assert not _pending_ids(env)                               # not pending forever
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))   # the next run is a new request
    assert rc == 0 and env.stub.requests[-1][0]["request_id"] != rid


def test_a_lasting_4xx_on_a_kept_id_the_server_already_answered_gives_that_answer(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    env.stub.script["*"] = ["queued"] * 100000                # spooled, not answered within this run
    rc, _ = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3
    (rid,) = _pending_ids(env).values()
    env.stub.script["*"] = []                                  # ... processed since: done
    env.stub.post_status[rid] = [403]                          # (and the re-send now refused, e.g. the file moved)
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 0 and "approve recorded" in out and not _pending_ids(env)


@pytest.mark.parametrize("sts", [[401, 401], [429], [502], [503], [504], [501]])
def test_other_answers_on_a_kept_id_stay_pending(tmp_path, monkeypatch, capsys, sts):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    rid = _kept_id(env, monkeypatch, capsys, f)
    env.stub.post_status[rid] = list(sts)
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and list(_pending_ids(env).values()) == [rid], out


@pytest.mark.parametrize("st", [500])           # 409 + nothing held: dropped (final review B M6, below)
def test_409_and_500_on_a_kept_id_poll_and_stay_pending_without_a_result(tmp_path, monkeypatch, capsys, st):
    env = setup(tmp_path, user="bob")
    env.poll_timeout = 30
    f = _draft(tmp_path)
    rid = _kept_id(env, monkeypatch, capsys, f)
    env.stub.post_status[rid] = [st]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and list(_pending_ids(env).values()) == [rid], out


@pytest.mark.parametrize("st", [502, 503, 504])
def test_a_proxy_error_on_the_first_post_is_pending_not_dropped(tmp_path, monkeypatch, capsys, st):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    stub, seen = env.stub, []

    def proxy(method, url, headers=None, body=None):
        if url.endswith("/request?format=json") and not seen:
            seen.append(json.loads(body)["request_id"])        # the request may have reached NextCloud behind it
            return st, {}, b"<html>Bad Gateway</html>"
        return stub(method, url, headers, body)
    env.transport = proxy
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and list(_pending_ids(env).values()) == seen, out
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 0 and stub.requests[-1][0]["request_id"] == seen[0]


def test_other_errors_on_the_first_post_are_still_refused(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    stub = env.stub
    env.transport = lambda method, url, headers=None, body=None: (413, {}, b"") \
        if url.endswith("/request?format=json") else stub(method, url, headers, body)
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 1 and "refused" in out and not _pending_ids(env)


# ---------- Task 11a fix round 1, I3: drop a kept id only when the server holds nothing for it ----------

def test_a_lasting_4xx_while_the_server_still_holds_the_id_queued_stays_pending(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    env.stub.script["*"] = ["queued"] * 100000                # spooled; the appender has not answered
    rc, _ = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3
    (rid,) = _pending_ids(env).values()
    env.stub.post_status[rid] = [403]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and list(_pending_ids(env).values()) == [rid], out
    env.stub.script["*"] = ["retry"]                           # a retry result: the server still holds it too
    env.stub.post_status[rid] = [400]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and list(_pending_ids(env).values()) == [rid], out


@pytest.mark.parametrize("lookup", [401, 503])
def test_a_lasting_4xx_whose_result_lookup_fails_stays_pending(tmp_path, monkeypatch, capsys, lookup):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    rid = _kept_id(env, monkeypatch, capsys, f)
    stub = env.stub
    stub.post_status[rid] = [413]
    env.transport = lambda method, url, headers=None, body=None: (lookup, {}, b"") \
        if "/result/" in url else stub(method, url, headers, body)
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3 and "pending" in out and list(_pending_ids(env).values()) == [rid], out


# ---------- Task 13a: the 11c lab defects on the workstation side ----------

def test_13a_d10_markdown_reader_pdf_gets_the_utf8_text_encoding(tmp_path):
    """P3-D10 (logs/162): x2t exits 89 on the .txt copy of a .md without m_nCsvTxtEncoding; 46 (UTF-8) makes the PDF."""
    env = setup(tmp_path, sign_in=False)
    md = tmp_path / "CUI_Notes_v0.1.md"
    md.write_text("CUI\n\nText\n\nCUI\n", encoding="utf-8")
    out_dir = tmp_path / "pdf"
    out_dir.mkdir(mode=0o700)
    pdf = DOC.reader_pdf(env, md, out_dir)
    assert pdf.read_bytes().startswith(b"%PDF-")
    log = (tmp_path / "x2t.log").read_text()
    assert "<m_nCsvTxtEncoding>46</m_nCsvTxtEncoding>" in log and "CUI_Notes_v0.1.txt" in log
    # a docx is not text: no text encoding
    assert "m_nCsvTxtEncoding" not in DOC._x2t_params(Path("/t/a.docx"), Path("/t/a.pdf"), Path("/f/AllFonts.js"))


@pytest.mark.parametrize("st", [503, 502, 504])
def test_13a_d8_nextcloud_unavailable_before_sending_is_pending(tmp_path, monkeypatch, capsys, st):
    """P3-D8 (logs/159): maintenance mode (the backup window) answers 503 to the client's own PROPFIND: pending
    (exit 3, run it again), not a refusal (exit 2); nothing is sent."""
    env = setup(tmp_path)
    stub = env.stub
    env.transport = lambda method, url, headers=None, body=None: (st, {}, b"<html>maintenance</html>") \
        if method == "PROPFIND" else stub(method, url, headers, body)
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 3 and "pending" in out and "nothing was sent" in out and "refused" not in out, out
    assert not posts(env)
    env.transport = stub                                     # maintenance over: the same command works
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 0, out


def test_13a_d9_a_401_while_kanidm_is_down_is_pending(tmp_path, monkeypatch, capsys):
    """P3-D9 (logs/161): NextCloud checks the Bearer at Kanidm's userinfo; with Kanidm down it answers 401. The client
    asks Kanidm itself: unreachable (or not answering 200) -> pending (exit 3), never "run chp-site doc login"."""
    env = setup(tmp_path)
    stub = env.stub

    def kanidm_down(method, url, headers=None, body=None):
        if "idm." in url:
            raise OSError("connection refused")
        if "files." in url:
            return 401, {}, b""
        return stub(method, url, headers, body)
    env.transport = kanidm_down
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 3 and "pending" in out and "Kanidm" in out and "doc login" not in out, out
    assert not posts(env)

    def kanidm_500(method, url, headers=None, body=None):
        if url.endswith("/status"):
            return 503, {}, b""
        return (401, {}, b"") if "files." in url else stub(method, url, headers, body)
    env.transport = kanidm_500
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 3 and "pending" in out, out
    # Kanidm answers: NextCloud really refused the sign-in -> the plain sign-in refusal as before
    env.transport = lambda method, url, headers=None, body=None: (200, {}, b"true") if url.endswith("/status") \
        else (401, {}, b"") if "files." in url else stub(method, url, headers, body)
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 2 and "doc login" in out, out


def test_13a_d9_kanidm_unreachable_on_a_refresh_before_sending_is_pending(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path)
    stub = env.stub
    env.clock.t += 3600                                      # the access token has expired: a refresh is needed

    def kanidm_down(method, url, headers=None, body=None):
        if "idm." in url:
            raise OSError("connection refused")
        return stub(method, url, headers, body)
    env.transport = kanidm_down
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 3 and "pending" in out and "nothing was sent" in out, out
    assert not posts(env)


@pytest.mark.parametrize("opt", ["--notes", "--reason"])
def test_13a_d13_notes_and_reason_over_the_ledger_limit_are_refused_here(tmp_path, monkeypatch, capsys, opt):
    """P3-D13 (logs/171): chp_ledger takes at most 2000 BYTES of notes/reason; over that the client says so in plain
    words and sends nothing (2000 bytes go through)."""
    env = setup(tmp_path, user="bob")
    f = tmp_path / "from-alice" / "CUI_SSP_v1.3-DRAFT.docx"
    f.parent.mkdir()
    f.write_bytes(MARKED)
    cmd = "approve" if opt == "--notes" else "override"
    rc, out = run(env, monkeypatch, capsys, cmd, str(f), opt, "é" * 1001)      # 2002 bytes, 1001 characters
    assert rc == 2 and "2000 bytes" in out and opt in out and not posts(env), out
    rc, out = run(env, monkeypatch, capsys, cmd, str(f), opt, "x" * 2000)
    assert rc in (0, 1) and posts(env), out
    assert len(posts(env)[-1]["notes" if opt == "--notes" else "reason"].encode()) == 2000



def test_13a_d8_unavailable_after_the_request_was_recorded_says_so(tmp_path, monkeypatch, capsys):
    """A checkout recorded by the server whose download then meets maintenance mode: pending, and it does not claim
    that nothing was sent."""
    env = setup(tmp_path)
    stub = env.stub
    env.transport = lambda method, url, headers=None, body=None: (503, {}, b"") \
        if method == "GET" and "/remote.php/dav/" in url else stub(method, url, headers, body)
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 3 and "pending" in out and "nothing was sent" not in out and "WAS recorded" in out, out
    assert "author of this cycle" in out and "checkout CUI_SSP_v1.2.docx again" in out


@pytest.mark.parametrize("kst,pending", [(500, True), (503, True), (429, True), (200, False), (404, False),
                                         (403, False), (400, False)])
def test_13a_r1_d9_only_unreachable_5xx_or_429_from_kanidm_is_pending(tmp_path, monkeypatch, capsys, kst, pending):
    env = setup(tmp_path)
    stub = env.stub
    env.transport = lambda method, url, headers=None, body=None: (kst, {}, b"") if url.endswith("/status") \
        else (401, {}, b"") if "files." in url else stub(method, url, headers, body)
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    if pending:
        assert rc == 3 and "pending" in out and "doc login" not in out, out
    else:
        assert rc == 2 and "doc login" in out, out



@pytest.mark.parametrize("fail", ["404", "401-kanidm-up"])
def test_13a_r1_a_recorded_checkout_whose_download_fails_is_not_a_refusal(tmp_path, monkeypatch, capsys, fail):
    """After the server recorded the checkout, a failed download (or a refused sign-in on it) is not "refused" with
    exit 2: the person is an author of this cycle now. It says so, and to run checkout again to download."""
    env = setup(tmp_path)
    stub = env.stub

    def t(method, url, headers=None, body=None):
        if method == "GET" and "/remote.php/dav/" in url:
            return (404, {}, b"") if fail == "404" else (401, {}, b"")
        if url.endswith("/status"):
            return 200, {}, b"true"
        return stub(method, url, headers, body)
    env.transport = t
    rc, out = run(env, monkeypatch, capsys, "checkout", "CUI_SSP_v1.2.docx")
    assert rc == 3 and "refused" not in out and "WAS recorded" in out and "author of this cycle" in out, out
    assert posts(env)
    # before anything is sent, a refusal stays a refusal (exit 2)
    (tmp_path / "b").mkdir()
    env2 = setup(tmp_path / "b")
    rc, out = run(env2, monkeypatch, capsys, "checkout", "CUI_Nothing_v1.0.docx")
    assert rc == 2 and "not found" in out


@pytest.mark.parametrize("opt", ["--notes", "--reason"])
@pytest.mark.parametrize("bad", ["two\nlines", "tab\there", "c1 \x85 x"])
def test_fixwave_a_i1_control_characters_are_refused_here(tmp_path, monkeypatch, capsys, opt, bad):
    """Final review A I-1: chp_ledger and the appender refuse a control character in notes/reason (it grew sixfold in
    the journal line and an override's alert was cut off); the client says so plainly and sends nothing."""
    env = setup(tmp_path, user="bob")
    f = tmp_path / "from-alice" / "CUI_SSP_v1.3-DRAFT.docx"
    f.parent.mkdir()
    f.write_bytes(MARKED)
    cmd = "approve" if opt == "--notes" else "override"
    rc, out = run(env, monkeypatch, capsys, cmd, str(f), opt, bad)
    assert rc == 2 and "control character" in out and opt in out and not posts(env), out


# ---------- Task 14: the final review's fix wave (B M6, M7, C-M10) ----------

def test_fixwave_b_m6_409_on_a_kept_id_the_server_holds_nothing_for_is_dropped(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    env.poll_timeout = 30
    f = _draft(tmp_path)
    rid = _kept_id(env, monkeypatch, capsys, f)
    env.stub.post_status[rid] = [409]                          # e.g. the id was taken by another sign-in's request
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 1 and "HTTP 409" in out and "dropped" in out and "pending" not in out, out
    assert not _pending_ids(env)                               # not pending forever
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))   # the next run is a new request
    assert rc == 0 and env.stub.requests[-1][0]["request_id"] != rid


def test_fixwave_b_m6_409_on_a_kept_id_with_an_answer_gives_it(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    env.stub.script["*"] = ["queued"] * 100000
    rc, _ = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 3
    (rid,) = _pending_ids(env).values()
    env.stub.script["*"] = []                                  # processed since: done
    env.stub.post_status[rid] = [409]
    rc, out = run(env, monkeypatch, capsys, "approve", str(f))
    assert rc == 0 and "approve recorded" in out and not _pending_ids(env)


def test_fixwave_b_m6_logout_forget_clears_the_kept_ids(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob")
    f = _draft(tmp_path)
    _kept_id(env, monkeypatch, capsys, f)
    assert _pending_ids(env)
    rc, out = run(env, monkeypatch, capsys, "logout")
    assert rc == 0 and _pending_ids(env)                       # kept across a plain logout
    rc, out = run(env, monkeypatch, capsys, "logout", "--forget")
    assert rc == 0 and "forgot 1 pending request" in out and not _pending_ids(env), out


def test_fixwave_b_m7_runtime_dir_must_be_run_user_uid(tmp_path, monkeypatch, capsys):
    env = setup(tmp_path, user="bob", sign_in=False)
    other = tmp_path / "elsewhere"
    other.mkdir(mode=0o700)
    os.chmod(other, 0o700)
    Path(env.mounts).write_text(Path(env.mounts).read_text() + f"tmpfs {os.path.realpath(other)} tmpfs rw 0 0\n")
    env.runtime = str(other)                                   # private tmpfs, but not logind's /run/user/<uid>
    rc, out = run(env, monkeypatch, capsys, "login")
    assert rc != 0 and f"is not {env.run_user}/{env.uid}" in out, out
    from chp_site import doc_auth as A
    assert A.Env.__init__.__kwdefaults__["run_user"] == "/run/user"


def test_fixwave_c_m10_mark_help_says_cui_or_fci():
    import argparse
    ap = argparse.ArgumentParser()
    DOC.add_parser(ap.add_subparsers())
    sub = next(a for a in ap._actions if isinstance(a, argparse._SubParsersAction)).choices["doc"]
    helps = {a.dest: a for a in sub._actions if isinstance(a, argparse._SubParsersAction)}
    mark = next(c for c in helps["doc_cmd"]._choices_actions if c.dest == "mark")
    assert "CUI/FCI marks" in mark.help
