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
    assert rc == 1 and "changed" in out and "check it out again" in out
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
