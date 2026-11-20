"""chp-templates 1.4.0's controlled-document templates (Plan 3 Task 7), read from the sibling checkout ~/chp-templates
as the other chp-templates tests do. The RPM installs doc/{cui,noncui}/<repo name> as
/usr/share/chp-templates/doc/{cui,noncui}/Template.<ext>; `chp-site doc new` fills the {{CUI_*}} placeholders from the
site keys (doc.fill_template), then marking.insert and marking.check run. Made-up values only."""
import os
import shutil
from pathlib import Path

import pytest

from chp_site import doc as DOC
from chp_site import marking as M

REPO = Path(os.environ.get("CHP_TEMPLATES_REPO") or Path.home() / "chp-templates")   # another checkout, for a branch
SRC = REPO / "doc"
EXTS = ("docx", "xlsx", "md")
REPO_NAME = {("cui", e): f"CUI_Template_v0.1-DRAFT.{e}" for e in EXTS}
REPO_NAME.update({("noncui", e): f"Template_v0.1-DRAFT.{e}" for e in EXTS})
HAVE_FCI = (SRC / "fci").is_dir()
if HAVE_FCI:                                       # Task 12 (owner decision 2026-11-20): the FCI templates
    REPO_NAME.update({("fci", e): f"FCI_Template_v0.1-DRAFT.{e}" for e in EXTS})
needs_fci = pytest.mark.skipif(not HAVE_FCI, reason="this chp-templates checkout predates the FCI templates "
                                                    "(doc/fci/, Task 12); set CHP_TEMPLATES_REPO to one that has them")
# made-up values with the characters that need escaping in XML and in Excel header/footer codes
SITE = {"DOMAIN": "example.test", "CUI_CONTROLLED_BY": "R&D Office <made-up> \"West\"",
        "CUI_CATEGORY": "PROPIN (made-up)", "CUI_POC": "A. Example, 555-0100 & B. Example (made-up)"}
VALUES = M.MarkValues.from_site(SITE)

pytestmark = pytest.mark.skipif(not (REPO / "render" / "chpfill.py").exists(), reason="no chp-templates checkout")


def install(dst):
    """The RPM's rename (chp-templates.spec %install)."""
    for (area, ext), name in REPO_NAME.items():
        (dst / area).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SRC / area / name, dst / area / f"Template.{ext}")
    return dst


@pytest.mark.parametrize("ext", EXTS)
def test_templates_pass_checker_after_fill(tmp_path, ext):
    tpl = install(tmp_path / "doc")
    raw = (tpl / "cui" / f"Template.{ext}").read_bytes()
    unfilled = tmp_path / f"CUI_Unfilled_v0.1-DRAFT.{ext}"
    unfilled.write_bytes(raw)
    rep = M.check(unfilled, True, VALUES)
    assert not rep.ok and any("designation block" in p for p in rep.problems)     # the placeholders matter
    f = tmp_path / f"CUI_Plan_v0.1-DRAFT.{ext}"
    f.write_bytes(DOC.fill_template(raw, ext, VALUES))
    rep = M.check(f, True, VALUES)
    assert rep.ok, rep.problems
    assert M.insert(f, VALUES, dry_run=True) == []                 # marked by construction: nothing to insert
    assert DOC.fill_template(raw, ext, VALUES) == f.read_bytes()   # deterministic
    # the non-CUI twin: no CUI banner, so it passes in the non-CUI area and fails in the CUI area
    n = tmp_path / f"Plan_v0.1-DRAFT.{ext}"
    n.write_bytes((tpl / "noncui" / f"Template.{ext}").read_bytes())
    assert M.check(n, False, M.MarkValues()).ok, M.check(n, False, M.MarkValues()).problems
    c = tmp_path / f"CUI_Twin_v0.1-DRAFT.{ext}"
    c.write_bytes(n.read_bytes())
    assert not M.check(c, True, VALUES).ok


def test_fill_leaves_no_placeholder_in_any_part(tmp_path):
    import zipfile
    from io import BytesIO
    tpl = install(tmp_path / "doc")
    for ext in ("docx", "xlsx"):
        z = zipfile.ZipFile(BytesIO(DOC.fill_template((tpl / "cui" / f"Template.{ext}").read_bytes(), ext, VALUES)))
        assert not any(b"{{" in z.read(n) for n in z.namelist()), ext
        assert any(b"R&amp;D Office &lt;made-up&gt;" in z.read(n) for n in z.namelist()), ext
    md = DOC.fill_template((tpl / "cui" / "Template.md").read_bytes(), "md", VALUES)
    assert b"{{" not in md and "Controlled by: R&D Office <made-up> \"West\"".encode() in md


def test_fill_refuses_a_template_that_still_holds_a_placeholder(tmp_path):
    with pytest.raises(DOC.DocError, match="placeholder"):
        DOC.fill_template(b"CUI\n\nControlled by: {{CUI_OTHER}}\n\nCUI\n", "md", VALUES)


@pytest.mark.parametrize("ext", EXTS)
def test_doc_new_from_the_installed_templates(tmp_path, monkeypatch, capsys, ext):
    from tests.test_doc_cli import run, setup, work
    env = setup(tmp_path)
    env.site = dict(SITE)
    install(Path(env.templates))                                    # the real 1.4.0 templates replace the fixtures
    rc, out = run(env, monkeypatch, capsys, "new", "Incident-Plan", "--cui", "--type", ext)
    assert rc == 0, out
    f = work(env) / f"CUI_Incident-Plan_v0.1-DRAFT.{ext}"
    assert M.check(f, True, VALUES).ok
    assert f.read_bytes() == DOC.fill_template((Path(env.templates) / "cui" / f"Template.{ext}").read_bytes(), ext,
                                               VALUES)              # filled, and insert had nothing to add
    rc, out = run(env, monkeypatch, capsys, "new", "Backup-Procedure", "--non-cui", "--type", ext)
    assert rc == 0, out
    g = work(env) / f"Backup-Procedure_v0.1-DRAFT.{ext}"
    assert g.read_bytes() == (Path(env.templates) / "noncui" / f"Template.{ext}").read_bytes()


@needs_fci
@pytest.mark.parametrize("ext", EXTS)
def test_fci_templates_pass_the_checker_as_they_are(tmp_path, ext):
    """The FCI templates are marked FCI by construction (no placeholders, no CUI site keys), and the checker refuses
    them under a CUI_ name and in the non-CUI area."""
    tpl = install(tmp_path / "doc")
    raw = (tpl / "fci" / f"Template.{ext}").read_bytes()
    f = tmp_path / f"FCI_Plan_v0.1-DRAFT.{ext}"
    f.write_bytes(raw)
    rep = M.check(f, True, M.MarkValues())
    assert rep.ok, rep.problems
    assert M.insert(f, M.MarkValues(), dry_run=True) == []
    c = tmp_path / f"CUI_Plan_v0.1-DRAFT.{ext}"
    c.write_bytes(raw)
    rep = M.check(c, True, VALUES)
    assert not rep.ok and any("an FCI banner" in p for p in rep.problems)
    n = tmp_path / f"Plan_v0.1-DRAFT.{ext}"
    n.write_bytes(raw)
    rep = M.check(n, False, M.MarkValues())
    assert not rep.ok and any("an FCI banner" in p and "non-CUI area" in p for p in rep.problems)
    # and the CUI template is refused under an FCI_ name
    g = tmp_path / f"FCI_Other_v0.1-DRAFT.{ext}"
    g.write_bytes(DOC.fill_template((tpl / "cui" / f"Template.{ext}").read_bytes(), ext, VALUES))
    assert not M.check(g, True, VALUES).ok


@needs_fci
@pytest.mark.parametrize("ext", EXTS)
def test_doc_new_fci_from_the_installed_templates(tmp_path, monkeypatch, capsys, ext):
    from tests.test_doc_cli import run, setup, work
    env = setup(tmp_path)
    env.site = {"DOMAIN": "example.test"}                           # FCI needs none of the CUI marking keys
    install(Path(env.templates))
    rc, out = run(env, monkeypatch, capsys, "new", "Quote-Terms", "--fci", "--type", ext)
    assert rc == 0, out
    f = work(env) / f"FCI_Quote-Terms_v0.1-DRAFT.{ext}"
    assert f.read_bytes() == (Path(env.templates) / "fci" / f"Template.{ext}").read_bytes()
    assert M.check(f, True, M.MarkValues()).ok
