"""Plan 3 Task 5: the CUI marking checker and inserter (chp_site.marking). Fixtures: tests/fixtures/marking/ (made by
make.py, made-up values) and the ONLYOFFICE-saved samples of the editor spike (lab/docs-spike/editor/out/)."""
import base64
import importlib.util
import re
import shutil
import struct
import subprocess
import unicodedata
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_site import marking as M

TOP = Path(__file__).resolve().parents[1]
FX = TOP / "tests/fixtures/marking"
OO = TOP / "lab/docs-spike/editor/out"
VALUES = M.MarkValues(controlled_by="Example Office (made-up)", category="PROPIN (made-up)",
                      poc="A. Example, 555-0100 (made-up)")
HAVE_PDFTOTEXT = bool(shutil.which("pdftotext") and shutil.which("pdfinfo")) or Path("/usr/bin/pdftotext").exists()


def _make():
    spec = importlib.util.spec_from_file_location("marking_make", FX / "make.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def copy(tmp_path, name, as_name=None, src=FX):
    dst = tmp_path / (as_name or name)
    shutil.copyfile(src / name, dst)
    return dst


def test_fixtures_are_reproducible():
    """The committed fixtures are exactly what make.py makes (stdlib, deterministic)."""
    built = _make().build()
    for name, data in built.items():
        assert (FX / name).read_bytes() == data, name


# ---------- docx ----------

def test_docx_marked_ok():
    r = M.check(FX / "CUI_Access-Policy_v1.0.docx", True, VALUES)
    assert r.ok, r.problems
    assert r.problems == [] and r.warnings == []
    assert r.name.prefix == "CUI_" and r.name.title == "Access-Policy" and r.name.version == "1.0"
    assert r.name.draft is False


def test_docx_missing_footer():
    r = M.check(FX / "CUI_Missing-Footer_v1.0.docx", True, VALUES)
    assert not r.ok
    assert len(r.problems) == 1
    assert "footer" in r.problems[0] and "banner" in r.problems[0] and "header" not in r.problems[0]


def test_banner_in_textbox_is_missing():
    """Review Focus: a banner drawn in a text box or shape does not mark every page; it is reported missing."""
    r = M.check(FX / "CUI_Textbox-Banner_v1.0.docx", True, VALUES)
    assert not r.ok
    text = " ".join(r.problems)
    assert any("header" in p for p in r.problems) and any("footer" in p for p in r.problems)
    assert "text box" in text


def test_docx_even_page_header_checked():
    r = M.check(FX / "CUI_Even-Pages_v1.0.docx", True, VALUES)
    assert not r.ok
    assert len(r.problems) == 1 and "even" in r.problems[0] and "header" in r.problems[0]


def test_docx_title_page_without_first_header():
    r = M.check(FX / "CUI_Title-Page_v1.0.docx", True, VALUES)
    assert not r.ok
    assert {("first", "header"), ("first", "footer")} == {
        (w, k) for p in r.problems for w in ("first",) for k in ("header", "footer") if w in p and k in p}


def test_docx_missing_block():
    r = M.check(FX / "CUI_Plan_v1.0.docx", True, VALUES)
    assert not r.ok
    text = " ".join(r.problems)
    assert "designation block" in text and "Controlled by" in text


def test_docx_onlyoffice_sample():
    """ONLYOFFICE-saved (spike): its banner reads 'CUI (odd)', which is not the banner; the block is on page one."""
    r = M.check(OO / "CUI_test-report_v0.1-DRAFT.docx", True, VALUES)
    assert not r.ok
    assert all("banner" in p for p in r.problems), r.problems
    assert not any("designation block" in p for p in r.problems)


# ---------- xlsx ----------

def test_xlsx_every_sheet():
    """Review Focus: the banner on the first sheet only is reported missing for the others."""
    ok = M.check(FX / "CUI_Inventory_v1.0.xlsx", True, VALUES)
    assert ok.ok, ok.problems
    r = M.check(FX / "CUI_First-Sheet-Only_v1.0.xlsx", True, VALUES)
    assert not r.ok
    assert all("Totals" in p for p in r.problems) and len(r.problems) == 2     # header and footer
    assert not any("Items" in p for p in r.problems)


def test_xlsx_onlyoffice_sample(tmp_path):
    """ONLYOFFICE-saved (spike): odd/even header and footer 'CUI' pass on its sheet; the GUI edit in the spike
    overwrote A1 ('Controlled by: ...') with 'Edited in the GUI', and the checker finds exactly that. Insert (it is a
    -DRAFT) puts the block in the first-page footer; then it passes."""
    r = M.check(OO / "CUI_test-data_v0.1-DRAFT.xlsx", True, VALUES)
    assert not r.ok and len(r.problems) == 1
    assert "designation block" in r.problems[0] and "Controlled by" in r.problems[0]
    assert "CUI Category" not in r.problems[0] and "banner" not in r.problems[0]
    f = copy(tmp_path, "CUI_test-data_v0.1-DRAFT.xlsx", src=OO)
    assert M.insert(f, VALUES, dry_run=False) == ["sheet 'Data': add the designation block to the first-page footer"]
    assert M.check(f, True, VALUES).ok


# ---------- md ----------

def test_md_banner_lines(tmp_path):
    assert M.check(FX / "CUI_Procedure_v1.0.md", True, VALUES).ok
    r = M.check(FX / "CUI_No-Last-Banner_v1.0.md", True, VALUES)
    assert not r.ok and len(r.problems) == 1 and "last line" in r.problems[0]
    # the banner must be the very first line, and the block follows it
    f = tmp_path / "CUI_Moved_v1.0.md"
    f.write_text("# Title\n\nCUI\n\nbody\n\nCUI\n")
    r = M.check(f, True, VALUES)
    assert any("first line" in p for p in r.problems) and any("designation block" in p for p in r.problems)
    f.write_bytes(b"\xff\xfe not utf-8")
    r = M.check(f, True, VALUES)
    assert not r.ok and "UTF-8" in r.problems[0]


# ---------- pdf ----------

@pytest.mark.skipif(not HAVE_PDFTOTEXT, reason="pdftotext/pdfinfo (poppler-utils) not installed here; "
                                               "the logic is tested through the _poppler seam below")
def test_pdf_first_last_page(tmp_path):
    assert M.check(FX / "CUI_Report_v1.0.pdf", True, VALUES).ok
    r = M.check(FX / "CUI_Report-Bad_v1.0.pdf", True, VALUES)
    assert not r.ok and len(r.problems) == 1 and "last page" in r.problems[0] and "bottom" in r.problems[0]
    # ONLYOFFICE exports (spike), under rule-following names: the xlsx export has its banners top and bottom and
    # lacks only the 'Controlled by' line (overwritten in the spike's GUI edit); the docx export's banner reads
    # "CUI (odd)", which is not the banner
    r = M.check(copy(tmp_path, "gui-data.pdf", "CUI_Data-Export_v1.0.pdf", src=OO), True, VALUES)
    assert len(r.problems) == 1 and "Controlled by" in r.problems[0] and "banner" not in r.problems[0]
    r = M.check(copy(tmp_path, "gui-report.pdf", "CUI_Report-Export_v1.0.pdf", src=OO), True, VALUES)
    assert not r.ok and all("banner" in p for p in r.problems) and len(r.problems) == 4


def _fake_poppler(pages):
    def run(tool, args):
        if tool == "pdfinfo":
            return f"Producer: test\nPages:          {len(pages)}\n"
        first = int(args[args.index("-f") + 1])
        return "\n".join(pages[first - 1]) + "\n\f"
    return run


def test_pdf_logic_through_seam(monkeypatch, tmp_path):
    f = tmp_path / "CUI_Report_v1.0.pdf"
    f.write_bytes(b"%PDF-1.4\n")
    block = ["Controlled by: Example Office (made-up)", "CUI Category: PROPIN (made-up)",
             "POC: A. Example, 555-0100 (made-up)"]
    monkeypatch.setattr(M, "_tool", lambda name: "/bin/true")
    monkeypatch.setattr(M, "_poppler", _fake_poppler([["CUI"] + block + ["x", "CUI"], ["CUI", "y", "CUI"]]))
    assert M.check(f, True, VALUES).ok
    monkeypatch.setattr(M, "_poppler", _fake_poppler([["CUI", "x", "CUI"], ["y", "z", "CUI"]]))
    r = M.check(f, True, VALUES)
    assert any("designation block" in p for p in r.problems)
    assert any("last page" in p and "top" in p for p in r.problems)


def test_pdf_tool_missing_or_failing_is_a_problem(monkeypatch, tmp_path):
    f = tmp_path / "CUI_Report_v1.0.pdf"
    f.write_bytes(b"%PDF-1.4\n")
    monkeypatch.setattr(M, "_tool", lambda name: None)
    r = M.check(f, True, VALUES)
    assert not r.ok and "poppler-utils" in r.problems[0]

    def boom(tool, args):
        raise subprocess.TimeoutExpired(tool, 1)
    monkeypatch.setattr(M, "_tool", lambda name: "/bin/true")
    monkeypatch.setattr(M, "_poppler", boom)
    r = M.check(f, True, VALUES)
    assert not r.ok and r.problems


# ---------- non-CUI area ----------

def test_non_cui_needs_no_banner(tmp_path):
    r = M.check(FX / "Access-Policy_v1.0.docx", False, M.MarkValues())
    assert r.ok, r.problems
    # a CUI-marked file in the non-CUI area is flagged (CUI does not belong there)
    f = copy(tmp_path, "CUI_Access-Policy_v1.0.docx", "Access-Policy_v1.0.docx")
    r = M.check(f, False, M.MarkValues())
    assert not r.ok and any("non-CUI area" in p for p in r.problems)


def test_cui_needs_marking_values():
    r = M.check(FX / "CUI_Access-Policy_v1.0.docx", True, M.MarkValues(controlled_by="Example Office (made-up)"))
    assert not r.ok
    text = " ".join(r.problems)
    assert "CUI_CATEGORY" in text and "CUI_POC" in text


# ---------- the name rule ----------

def test_name_rule_edge_cases(tmp_path):
    """Review Focus: spaces, NFD/NFC, a second _v, the prefix per area: parsed the same on both ends (the
    workstation and the appender use this one parser), refused with the name rule's message, never a traceback."""
    def refused(name, why):
        with pytest.raises(M.NameRuleError) as e:
            M.parse_name(name)
        msg = str(e.value)
        assert msg.startswith("name rule:") and why in msg, msg
        assert isinstance(e.value, ValueError)
        return msg

    # spaces
    refused("CUI_Access Policy_v1.0.docx", "space")
    refused("CUI_Access-Policy_v1.0 .docx", "space")
    refused("CUI_Access Policy_v1.0.docx", "space")
    # NFD and NFC give the same parts
    nfc, nfd = "CUI_Café_v1.0.docx", unicodedata.normalize("NFD", "CUI_Café_v1.0.docx")
    assert nfc != nfd and M.parse_name(nfc) == M.parse_name(nfd)
    assert M.parse_name(nfd).title == "Café"
    # a second _v in the title is refused (only the version at the end may look like _vX.Y)
    refused("CUI_SSP_v2_v1.0.docx", "second _v")
    refused("CUI_SSP_v1.0_v1.1.docx", "second _v")
    refused("CUI_SSP_V1.0_v1.1.docx", "second _v")
    assert M.parse_name("CUI_Dev_vendors_v1.0.docx").title == "Dev_vendors"
    # draft, version and prefix shapes
    p = M.parse_name("FCI_Plan_v0.3-DRAFT.md")
    assert (p.prefix, p.title, p.version, p.draft, p.ext) == ("FCI_", "Plan", "0.3", True, "md")
    assert M.parse_name("Plan_v12.10.xlsx").prefix == ""
    refused("CUI_Plan_v0.3-draft.md", "-DRAFT")
    refused("cui_Plan_v1.0.md", "capitals")
    refused("CUI_Plan_v01.0.md", "_vX.Y")
    refused("CUI_Plan.docx", "_vX.Y")
    refused("CUI_Plan_v1.0", "_vX.Y")
    refused("CUI__v1.0.docx", "title")
    refused("../CUI_Plan_v1.0.docx", "path")
    refused("CUI_Pl​an_v1.0.docx", "letters, digits")
    refused("", "empty")
    refused("CUI_" + "a" * 300 + "_v1.0.md", "long")
    with pytest.raises(M.NameRuleError):
        M.parse_name(None)
    # fix round 1: version digits are ASCII only (no lookalike versions); a non-ASCII digit after _v in the title is
    # refused too
    refused("CUI_SSP_v1.1\u0660.docx", "_vX.Y")          # Arabic-Indic zero: not v1.10
    refused("CUI_SSP_v\u0661.0.docx", "_vX.Y")
    refused("CUI_SSP_v\uff11.\uff10.docx", "_vX.Y")     # fullwidth digits
    refused("CUI_SSP_v\u0662_v1.0.docx", "second _v")
    # fix round 1: lookalike prefixes (fullwidth, compatibility forms, Cyrillic/Greek letters) are refused in both
    # areas with the rule's message
    refused("\uff23\uff35\uff29_SSP_v1.0.docx", "prefix")      # fullwidth CUI
    refused("CUI\uff3fSSP_v1.0.docx", "prefix")                  # fullwidth low line
    refused("\u0421UI_SSP_v1.0.docx", "prefix")                   # Cyrillic Es
    refused("FC\u0399_SSP_v1.0.docx", "prefix")                   # Greek Iota
    assert M.parse_name("Cuisine_v1.0.docx").prefix == ""
    # the prefix per area: check reports it as a problem (not a traceback)
    f = copy(tmp_path, "CUI_Access-Policy_v1.0.docx", "Access-Policy_v1.0.docx")
    r = M.check(f, True, VALUES)
    assert not r.ok and any("CUI_ or FCI_" in p for p in r.problems)
    r = M.check(FX / "CUI_Access-Policy_v1.0.docx", False, M.MarkValues())
    assert not r.ok and any("non-CUI area" in p and "prefix" in p for p in r.problems)
    # a bad name is a problem in the report, with the rule's message
    g = copy(tmp_path, "CUI_Access-Policy_v1.0.docx", "CUI_Access Policy_v1.0.docx")
    r = M.check(g, True, VALUES)
    assert not r.ok and r.name is None and r.problems[0].startswith("name rule:")
    # the NFD-named file checks the same as the NFC one
    h = copy(tmp_path, "CUI_Access-Policy_v1.0.docx", nfd)
    assert M.check(h, True, VALUES).ok


def test_name_rule_same_on_the_appender():
    """The appender (Task 4) parses names with this parser: same key for NFD and NFC, refusals carry the rule."""
    from chp_site import doc_ledger as L
    ctx = SimpleNamespace(marking=M)
    nfd = unicodedata.normalize("NFD", "CUI_Café_v1.0-DRAFT.docx")
    assert L._series(ctx, nfd)[0] == L._series(ctx, "CUI_Café_v2.0.docx")[0] == "CUI_Café.docx"
    with pytest.raises(L._Refuse) as e:
        L._series(ctx, "CUI_SSP_v1.0_v1.1.docx")
    assert "name rule" in str(e.value) and "second _v" in str(e.value)


# ---------- insert ----------

def test_insert_only_draft(tmp_path):
    f = copy(tmp_path, "CUI_Plan_v1.0.docx")
    before = f.read_bytes()
    for dry in (True, False):
        with pytest.raises(M.MarkingError) as e:
            M.insert(f, VALUES, dry_run=dry)
        assert "-DRAFT" in str(e.value)
    assert f.read_bytes() == before
    # a non-CUI name takes no CUI marks; a PDF is never marked in place
    g = tmp_path / "Plan_v0.1-DRAFT.md"
    g.write_text("# x\n")
    with pytest.raises(M.MarkingError, match="non-CUI"):
        M.insert(g, VALUES, dry_run=False)
    h = tmp_path / "CUI_Plan_v0.1-DRAFT.pdf"
    h.write_bytes(b"%PDF-1.4\n")
    with pytest.raises(M.MarkingError, match="PDF"):
        M.insert(h, VALUES, dry_run=False)
    # the marking values must be set on the site stick
    d = copy(tmp_path, "CUI_Notes_v0.1-DRAFT.md")
    with pytest.raises(M.MarkingError, match="CUI_POC"):
        M.insert(d, M.MarkValues(controlled_by="x", category="y"), dry_run=False)


@pytest.mark.parametrize("name", ["CUI_Plan_v0.1-DRAFT.docx", "CUI_Data_v0.1-DRAFT.xlsx", "CUI_Notes_v0.1-DRAFT.md"])
def test_insert_dry_run_changes_nothing(tmp_path, name):
    f = copy(tmp_path, name)
    before = f.read_bytes()
    assert not M.check(f, True, VALUES).ok
    plan = M.insert(f, VALUES)                       # dry run is the default
    assert plan and all(isinstance(x, str) for x in plan)
    assert f.read_bytes() == before and sorted(p.name for p in tmp_path.iterdir()) == [name]
    done = M.insert(f, VALUES, dry_run=False)
    assert done == plan
    r = M.check(f, True, VALUES)
    assert r.ok, r.problems
    assert M.insert(f, VALUES, dry_run=False) == []  # already marked: nothing to do
    # deterministic: the same input and values give the same bytes (the approved hash covers the marked file)
    (tmp_path / "x").mkdir()
    g2 = copy(tmp_path / "x", name, src=FX)
    M.insert(g2, VALUES, dry_run=False)
    assert g2.read_bytes() == f.read_bytes()
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([name, "x"])


def test_insert_keeps_xlsx_content(tmp_path):
    f = copy(tmp_path, "CUI_Data_v0.1-DRAFT.xlsx")
    M.insert(f, VALUES, dry_run=False)
    with zipfile.ZipFile(f) as z:
        s1 = z.read("xl/worksheets/sheet1.xml").decode()
        s2 = z.read("xl/worksheets/sheet2.xml").decode()
    assert "Internal list" in s1 and "<t>Item</t>" in s1 and "<t>Total</t>" in s2
    assert s1.index("<headerFooter") > s1.index("<pageMargins") and s2.index("<headerFooter") > s2.index("</sheetData>")


def test_insert_onlyoffice_docx(tmp_path):
    """The ONLYOFFICE-saved sample (banner 'CUI (odd)'/'CUI (even)', even pages on): insert adds the banner to all
    four parts; afterwards it passes."""
    f = copy(tmp_path, "CUI_test-report_v0.1-DRAFT.docx", src=OO)
    plan = M.insert(f, VALUES, dry_run=False)
    assert len(plan) == 4
    r = M.check(f, True, VALUES)
    assert r.ok, r.problems
    with zipfile.ZipFile(f) as z, zipfile.ZipFile(OO / "CUI_test-report_v0.1-DRAFT.docx") as o:
        assert z.namelist() == o.namelist()
        assert z.read("word/styles.xml") == o.read("word/styles.xml")
        assert 'mc:Ignorable="w14 w15 wp14"' in z.read("word/footer1.xml").decode()


def test_banner_hidden_by_style_is_missing(tmp_path):
    """Fix round 1 (m1, m2): a banner run hidden directly, or through its character style or its paragraph style
    (basedOn chains, docDefaults), does not count; an explicit direct 'not hidden' wins; style cycles do not hang."""
    mk = _make()
    hid_r = '<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:rStyle w:val="Hid"/></w:rPr><w:t>CUI</w:t>' \
            '</w:r></w:p>'
    hid_p = '<w:p><w:pPr><w:pStyle w:val="HidP"/></w:pPr><w:r><w:t>CUI</w:t></w:r></w:p>'
    direct = '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>CUI</w:t></w:r></w:p>'
    shown = '<w:p><w:r><w:rPr><w:rStyle w:val="Hid"/><w:vanish w:val="0"/></w:rPr><w:t>CUI</w:t></w:r></w:p>'
    styles = ('<w:style w:type="character" w:styleId="HidBase"><w:rPr><w:vanish/></w:rPr></w:style>'
              '<w:style w:type="character" w:styleId="Hid"><w:basedOn w:val="HidBase"/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Base"><w:basedOn w:val="Base2"/><w:rPr><w:vanish/></w:rPr>'
              '</w:style><w:style w:type="paragraph" w:styleId="Base2"><w:basedOn w:val="HidP"/></w:style>'
              '<w:style w:type="paragraph" w:styleId="HidP"><w:basedOn w:val="Base"/></w:style>')
    ftr = ("ftr", "footer1.xml", mk.p("CUI", True))
    cases = {"rstyle": hid_r, "pstyle": hid_p, "direct": direct}
    for label, hdr in cases.items():
        f = tmp_path / f"CUI_Hidden-{label}_v1.0.docx"
        f.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", hdr), ftr], mk.REFS, styles=styles))
        r = M.check(f, True, VALUES)
        assert not r.ok and len(r.problems) == 1 and "header" in r.problems[0], (label, r.problems)
    f = tmp_path / "CUI_Shown_v1.0.docx"
    f.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", shown), ftr], mk.REFS, styles=styles))
    assert M.check(f, True, VALUES).ok
    # docDefaults hiding everything: nothing counts (and the block is hidden too)
    f = tmp_path / "CUI_Defaults_v1.0.docx"
    f.write_bytes(mk.docx(mk.BLOCK_XML, [mk.BANNER_HDR, ftr], mk.REFS,
                          styles="<w:docDefaults><w:rPrDefault><w:rPr><w:vanish/></w:rPr></w:rPrDefault>"
                                 "</w:docDefaults>"))
    r = M.check(f, True, VALUES)
    assert not r.ok and any("header" in p for p in r.problems) and any("designation block" in p for p in r.problems)
    # insert sees the same hiding: it adds a visible banner, and the result passes
    d = tmp_path / "CUI_Hidden_v0.1-DRAFT.docx"
    d.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", hid_r), ftr], mk.REFS, styles=styles))
    assert M.insert(d, VALUES, dry_run=False) == ["word/header1.xml: add the CUI banner to the default header"]
    assert M.check(d, True, VALUES).ok


def test_xlsx_even_and_first_parts_required(tmp_path):
    """Fix round 1 (m2): differentOddEven / differentFirst switched on without the even / first header or footer."""
    mk = _make()
    rows = [[x] for x in mk.BLOCK]
    f = tmp_path / "CUI_Even_v1.0.xlsx"
    f.write_bytes(mk.xlsx([("Items", mk.sheet(rows, dict(mk.HF, differentOddEven="1", evenHeader="&CCUI")))]))
    r = M.check(f, True, VALUES)
    assert not r.ok and len(r.problems) == 1 and "even-page footer" in r.problems[0]
    f = tmp_path / "CUI_First_v1.0.xlsx"
    f.write_bytes(mk.xlsx([("Items", mk.sheet(rows, dict(mk.HF, differentFirst="1", firstFooter="&CCUI")))]))
    r = M.check(f, True, VALUES)
    assert not r.ok and len(r.problems) == 1 and "first-page header" in r.problems[0]


@pytest.mark.parametrize("enc", ["utf-16", "utf-16-le", "utf-16-be"])
def test_non_utf8_part_refused(tmp_path, enc):
    """Fix round 1: a UTF-16 part (with or without BOM) cannot carry a DTD past the byte search; any part that is
    not UTF-8 is refused."""
    with zipfile.ZipFile(FX / "CUI_Access-Policy_v1.0.docx") as z:
        hdr = z.read("word/header1.xml").decode()
    body = hdr.split("?>", 1)[1].replace(">CUI<", ">&b;<", 1)
    new = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY b "CUI">]>' + body
    f = tmp_path / "CUI_U16_v1.0.docx"
    with zipfile.ZipFile(FX / "CUI_Access-Policy_v1.0.docx") as s, zipfile.ZipFile(f, "w") as d:
        for n in s.namelist():
            d.writestr(n, new.encode(enc) if n == "word/header1.xml" else s.read(n))
    r = M.check(f, True, VALUES)
    assert not r.ok and any("UTF-8" in p for p in r.problems), r.problems
    # a UTF-8 part that declares another encoding is refused as well
    with zipfile.ZipFile(FX / "CUI_Access-Policy_v1.0.docx") as s, zipfile.ZipFile(f, "w") as d:
        for n in s.namelist():
            b = s.read(n)
            d.writestr(n, b.replace(b'encoding="UTF-8"', b'encoding="ISO-8859-1"') if n == "word/header1.xml" else b)
    r = M.check(f, True, VALUES)
    assert not r.ok and any("UTF-8" in p for p in r.problems), r.problems


def test_citation_ascii_digits_only(tmp_path):
    f = tmp_path / "CUI_Note_v1.0.md"
    f.write_text("CUI\n\nCites CUI_SSP_v1.\u0660 and CUI_SSP_v1.1.\n")
    r = M.check(f, True, VALUES, current={"CUI_SSP": "1.2"})
    assert r.warnings == ["CUI_SSP_v1.1 is cited, but the current version in the Compliance area is v1.2 "
                          "(a superseded citation)"]


# ---------- defensive parsing ----------

def test_malformed_files_are_problems_not_tracebacks(tmp_path, monkeypatch):
    f = tmp_path / "CUI_Bad_v1.0.docx"
    f.write_bytes(b"not a zip")
    r = M.check(f, True, VALUES)
    assert not r.ok and "not a valid" in r.problems[0]
    # an XML part with a DTD (entity expansion) is refused
    data = (FX / "CUI_Access-Policy_v1.0.docx").read_bytes()
    with zipfile.ZipFile(FX / "CUI_Access-Policy_v1.0.docx") as src, zipfile.ZipFile(f, "w") as dst:
        for n in src.namelist():
            b = src.read(n)
            if n == "word/header1.xml":
                b = b.replace(b"<w:hdr", b'<!DOCTYPE x [<!ENTITY a "aaaa">]><w:hdr', 1)
            dst.writestr(n, b)
    r = M.check(f, True, VALUES)
    assert not r.ok and any("DTD" in p for p in r.problems)
    # duplicate part names (a reader could see one and Word the other)
    with zipfile.ZipFile(f, "w") as dst:
        with zipfile.ZipFile(FX / "CUI_Access-Policy_v1.0.docx") as src:
            for n in src.namelist():
                dst.writestr(n, src.read(n))
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            dst.writestr("WORD/header1.xml", b"<x/>")
    r = M.check(f, True, VALUES)
    assert not r.ok and any("twice" in p for p in r.problems)
    # zip bomb caps: total uncompressed size and member count
    f.write_bytes(data)
    monkeypatch.setattr(M, "MAX_UNCOMPRESSED", 1000)
    r = M.check(f, True, VALUES)
    assert not r.ok and any("too large" in p for p in r.problems)
    monkeypatch.setattr(M, "MAX_UNCOMPRESSED", 256 << 20)
    monkeypatch.setattr(M, "MAX_MEMBERS", 3)
    r = M.check(f, True, VALUES)
    assert not r.ok and any("too many" in p for p in r.problems)
    monkeypatch.setattr(M, "MAX_MEMBERS", 2000)
    # broken XML, unsupported format, missing file
    with zipfile.ZipFile(f, "w") as dst:
        with zipfile.ZipFile(FX / "CUI_Access-Policy_v1.0.docx") as src:
            for n in src.namelist():
                dst.writestr(n, b"<w:document" if n == "word/document.xml" else src.read(n))
    assert not M.check(f, True, VALUES).ok
    t = tmp_path / "CUI_Bad_v1.0.txt"
    t.write_text("CUI\n")
    r = M.check(t, True, VALUES)
    assert not r.ok and "docx, xlsx, md or pdf" in r.problems[0]
    r = M.check(tmp_path / "CUI_Gone_v1.0.md", True, VALUES)
    assert not r.ok and r.problems
    # an insert into a malformed draft is refused plainly and changes nothing
    d = tmp_path / "CUI_Bad_v0.1-DRAFT.docx"
    d.write_bytes(b"not a zip")
    with pytest.raises(M.MarkingError):
        M.insert(d, VALUES, dry_run=False)
    assert d.read_bytes() == b"not a zip"


# ---------- marking values ----------

def test_mark_values_from_site(tmp_path):
    v = M.MarkValues.from_site({"CUI_CONTROLLED_BY": "Example Office", "CUI_CATEGORY": "PROPIN", "CUI_POC": ""})
    assert (v.controlled_by, v.category, v.poc) == ("Example Office", "PROPIN", "")
    assert M.MarkValues.from_site({}) == M.MarkValues()
    key = base64.b64encode(b"".join(struct.pack(">I", len(x)) + x for x in
                                    (b"ecdsa-sha2-nistp384", b"nistp384", b"\x04" + b"\x01" * 96))).decode()
    (tmp_path / "site.conf").write_text(
        "DOMAIN=example.test\nSUBNET=192.168.100.0/24\nGATEWAY=192.168.100.1\nNTP_UPSTREAM=192.168.100.1\n"
        "TIMEZONE=America/Denver\nISSO_NAME=A. Example\nALERT_HOOK=\n"
        f"ADMIN_SSH_PUBKEY=ecdsa-sha2-nistp384 {key} admin@example\n"
        "CUI_CONTROLLED_BY=Example Office (made-up)\nCUI_CATEGORY=PROPIN (made-up)\n"
        "CUI_POC=A. Example, 555-0100 (made-up)\n")
    got = M.MarkValues.from_site(site_dir=tmp_path)
    assert got == VALUES


# ---------- citation check ----------

def test_citation_warns_on_superseded():
    f = FX / "CUI_Runbook_v1.0.docx"
    current = {"CUI_SSP": "1.2", "CUI_IR-Plan": "2.0", "CUI_Runbook": "1.0", "cui_access-policy": (1, 0)}
    r = M.check(f, True, VALUES, current=current)
    assert r.ok, r.problems                          # a warning, never a refusal
    assert len(r.warnings) == 2, r.warnings
    assert any("CUI_SSP_v1.0" in w and "v1.2" in w for w in r.warnings)
    assert any("CUI_Access-Policy_v0.3" in w and "v1.0" in w for w in r.warnings)     # also inside a text box
    assert not any("Runbook" in w or "IR-Plan" in w for w in r.warnings)  # own series; current version
    assert M.check(f, True, VALUES).warnings == []   # current=None: no citation check
    r = M.check(FX / "CUI_Notes_v0.1-DRAFT.md", True, VALUES, current={"CUI_SSP": "1.1"})
    assert not r.ok and r.warnings and "CUI_SSP_v1.0" in r.warnings[0]


def test_chp_documents_requires_poppler():
    spec = (TOP / "appliance/rpm/chp-documents/chp-documents.spec").read_text()
    assert re.search(r"^Requires:\s+poppler-utils\s*$", spec, re.M)


# ---------- FCI (owner decision 2026-11-20: "FCI should be marked as FCI") ----------
# In the CUI area an FCI_ document carries the banner "FCI" (top and bottom, the same places and the same false-pass
# defences as the CUI banner) and no CUI designation block; a CUI banner on it is a problem, and an FCI banner on a
# CUI_ document is a problem. check() learns the document is FCI from its name (parse_name: the FCI_ prefix).

NO_VALUES = M.MarkValues()


@pytest.mark.parametrize("name", ["FCI_Notice_v1.0.docx", "FCI_Quote_v1.0.xlsx", "FCI_Notes_v1.0.md"])
def test_fci_marked_ok_without_the_cui_site_keys(name):
    for values in (VALUES, NO_VALUES):                # the CUI marking keys are not needed for FCI
        r = M.check(FX / name, True, values)
        assert r.ok, (name, r.problems)
        assert r.name.prefix == "FCI_"


@pytest.mark.skipif(not HAVE_PDFTOTEXT, reason="pdftotext/pdfinfo (poppler-utils) not installed here")
def test_fci_pdf_fixture():
    assert M.check(FX / "FCI_Report_v1.0.pdf", True, NO_VALUES).ok


def test_fci_pdf_through_seam(monkeypatch, tmp_path):
    f = tmp_path / "FCI_Report_v1.0.pdf"
    f.write_bytes(b"%PDF-1.4\n")
    monkeypatch.setattr(M, "_tool", lambda name: "/bin/true")
    monkeypatch.setattr(M, "_poppler", _fake_poppler([["FCI", "x", "FCI"], ["FCI", "y", "FCI"]]))
    assert M.check(f, True, NO_VALUES).ok
    monkeypatch.setattr(M, "_poppler", _fake_poppler([["FCI", "x", "FCI"], ["y", "z", "FCI"]]))
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and len(r.problems) == 1 and "last page" in r.problems[0] and "FCI banner" in r.problems[0]
    # the CUI banner on an FCI document is a problem, and so is the CUI designation block
    monkeypatch.setattr(M, "_poppler", _fake_poppler([["CUI", "CUI Category: PROPIN (made-up)", "x", "CUI"],
                                                      ["CUI", "y", "CUI"]]))
    r = M.check(f, True, VALUES)
    text = " ".join(r.problems)
    assert not r.ok and "FCI banner" in text and "a CUI banner" in text and "designation block" in text
    # an FCI banner on a CUI_ document is a problem
    g = tmp_path / "CUI_Report_v1.0.pdf"
    g.write_bytes(b"%PDF-1.4\n")
    block = ["Controlled by: Example Office (made-up)", "CUI Category: PROPIN (made-up)",
             "POC: A. Example, 555-0100 (made-up)"]
    monkeypatch.setattr(M, "_poppler", _fake_poppler([["CUI", "FCI"] + block + ["x", "CUI"], ["CUI", "y", "CUI"]]))
    r = M.check(g, True, VALUES)
    assert not r.ok and any("an FCI banner" in p and "CUI_" in p for p in r.problems), r.problems


def test_fci_name_with_the_cui_marks_is_refused(tmp_path):
    """A CUI-marked document renamed FCI_: no FCI banner, a CUI banner present, a CUI designation block present."""
    f = copy(tmp_path, "CUI_Access-Policy_v1.0.docx", "FCI_Access-Policy_v1.0.docx")
    r = M.check(f, True, VALUES)
    assert not r.ok
    assert any("header" in p and "no FCI banner" in p for p in r.problems), r.problems
    assert any("footer" in p and "no FCI banner" in p for p in r.problems), r.problems
    assert any("a CUI banner" in p and "FCI_" in p for p in r.problems), r.problems
    assert any("designation block" in p and "FCI" in p for p in r.problems), r.problems
    for name, as_name in (("CUI_Inventory_v1.0.xlsx", "FCI_Inventory_v1.0.xlsx"),
                          ("CUI_Procedure_v1.0.md", "FCI_Procedure_v1.0.md")):
        r = M.check(copy(tmp_path, name, as_name), True, VALUES)
        text = " ".join(r.problems)
        assert not r.ok and "FCI banner" in text and "a CUI banner" in text and "designation block" in text, \
            (as_name, r.problems)


def test_cui_name_with_the_fci_banner_is_refused(tmp_path):
    f = copy(tmp_path, "FCI_Notice_v1.0.docx", "CUI_Notice_v1.0.docx")
    r = M.check(f, True, VALUES)
    text = " ".join(r.problems)
    assert not r.ok and "no CUI banner" in text and "an FCI banner" in text and "designation block" in text
    for name, as_name in (("FCI_Quote_v1.0.xlsx", "CUI_Quote_v1.0.xlsx"), ("FCI_Notes_v1.0.md", "CUI_Notes_v1.0.md")):
        r = M.check(copy(tmp_path, name, as_name), True, VALUES)
        text = " ".join(r.problems)
        assert not r.ok and "CUI banner" in text and "an FCI banner" in text, (as_name, r.problems)
    # an FCI banner added beside a complete set of CUI marks is still a problem
    mk = _make()
    g = tmp_path / "CUI_Both_v1.0.docx"
    g.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", mk.p("CUI", True) + mk.p("FCI", True)),
                                         mk.BANNER_FTR], mk.REFS))
    r = M.check(g, True, VALUES)
    assert not r.ok and len(r.problems) == 1 and "an FCI banner" in r.problems[0]


def test_fci_banner_defences(tmp_path):
    """The CUI banner's false-pass defences hold for FCI: text box, hidden run (direct and by style), even-page and
    title-page headers, every sheet, Excel even/first parts, lookalike letters and fullwidth forms."""
    mk = _make()
    ftr = mk.FCI_FTR

    def docx(name, parts, refs=mk.REFS, **kw):
        f = tmp_path / name
        f.write_bytes(mk.docx(mk.FILLER, parts, refs, **kw))
        return M.check(f, True, NO_VALUES)

    r = docx("FCI_Box_v1.0.docx", [("hdr", "header1.xml", mk.textbox("FCI")), ftr])
    assert not r.ok and len(r.problems) == 1 and "header" in r.problems[0] and "text box" in r.problems[0]
    hidden = '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>FCI</w:t></w:r></w:p>'
    r = docx("FCI_Hidden_v1.0.docx", [("hdr", "header1.xml", hidden), ftr])
    assert not r.ok and len(r.problems) == 1 and "header" in r.problems[0]
    styles = '<w:style w:type="character" w:styleId="Hid"><w:rPr><w:vanish/></w:rPr></w:style>'
    hid_r = '<w:p><w:r><w:rPr><w:rStyle w:val="Hid"/></w:rPr><w:t>FCI</w:t></w:r></w:p>'
    r = docx("FCI_Hidden-Style_v1.0.docx", [("hdr", "header1.xml", hid_r), ftr], styles=styles)
    assert not r.ok and len(r.problems) == 1 and "header" in r.problems[0]
    r = docx("FCI_Even_v1.0.docx", [mk.FCI_HDR, ftr, ("hdr", "header2.xml", mk.p("Even page")),
                                    ("ftr", "footer2.xml", mk.p("FCI", True))],
             mk.REFS + [("hdr", "even", "header2.xml"), ("ftr", "even", "footer2.xml")], even=True)
    assert not r.ok and len(r.problems) == 1 and "even" in r.problems[0] and "header" in r.problems[0]
    r = docx("FCI_Title_v1.0.docx", [mk.FCI_HDR, ftr], title_pg=True)
    assert not r.ok and len(r.problems) == 2 and all("first" in p and "FCI banner" in p for p in r.problems)
    for label, word in (("cyrillic", "FСI"), ("greek", "FCΙ"), ("fullwidth", "ＦＣＩ"),
                        ("lower", "fci"), ("suffix", "FCI (odd)"), ("cui-style", "FCI//SP-PROPIN")):
        r = docx(f"FCI_Look-{label}_v1.0.docx", [("hdr", "header1.xml", mk.p(word, True)), ftr])
        assert not r.ok and any("header" in p and "no FCI banner" in p for p in r.problems), (label, r.problems)
    # xlsx: every sheet, and the even / first parts when they are switched on
    f = tmp_path / "FCI_One-Sheet_v1.0.xlsx"
    f.write_bytes(mk.xlsx([("Items", mk.sheet([["A"]], mk.FCI_HF)), ("Totals", mk.sheet([["B"]]))]))
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and len(r.problems) == 2 and all("Totals" in p and "FCI banner" in p for p in r.problems)
    f = tmp_path / "FCI_First_v1.0.xlsx"
    f.write_bytes(mk.xlsx([("Items", mk.sheet([["A"]], dict(mk.FCI_HF, differentFirst="1", firstFooter="&CFCI")))]))
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and len(r.problems) == 1 and "first-page header" in r.problems[0]
    f = tmp_path / "FCI_Even_v1.0.xlsx"
    f.write_bytes(mk.xlsx([("Items", mk.sheet([["A"]], dict(mk.FCI_HF, differentOddEven="1", evenHeader="&CFCI")))]))
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and len(r.problems) == 1 and "even-page footer" in r.problems[0]
    # md: the first and the last line, exactly FCI
    f = tmp_path / "FCI_Look_v1.0.md"
    f.write_text("FСI\n\nbody\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and len(r.problems) == 1 and "first line" in r.problems[0] and "FCI" in r.problems[0]
    f.write_text("FCI\n\nbody\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and len(r.problems) == 1 and "last line" in r.problems[0]


def test_lookalike_wrong_banner_is_still_seen(tmp_path):
    """The wrong banner is looked for with lookalikes folded (a Cyrillic CUI on an FCI document, an FCI in the
    non-CUI area): spelling it with other letters does not hide it."""
    mk = _make()
    f = tmp_path / "FCI_Mixed_v1.0.docx"
    f.write_bytes(mk.docx(mk.FILLER, [("hdr", "header1.xml", mk.p("FCI", True) + mk.p("СUI", True)),
                                      mk.FCI_FTR], mk.REFS))
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and len(r.problems) == 1 and "a CUI banner" in r.problems[0]
    g = tmp_path / "Notes_v1.0.md"
    g.write_text("ＦＣＩ\n\nbody\n", encoding="utf-8")
    r = M.check(g, False, NO_VALUES)
    assert not r.ok and any("an FCI banner" in p and "non-CUI area" in p for p in r.problems), r.problems


def test_fci_banner_in_the_non_cui_area_is_a_problem(tmp_path, monkeypatch):
    for name, as_name in (("FCI_Notice_v1.0.docx", "Notice_v1.0.docx"), ("FCI_Quote_v1.0.xlsx", "Quote_v1.0.xlsx"),
                          ("FCI_Notes_v1.0.md", "Notes_v1.0.md")):
        r = M.check(copy(tmp_path, name, as_name), False, NO_VALUES)
        assert not r.ok and len(r.problems) == 1, (as_name, r.problems)
        assert "an FCI banner" in r.problems[0] and "non-CUI area" in r.problems[0]
    f = tmp_path / "Report_v1.0.pdf"
    f.write_bytes(b"%PDF-1.4\n")
    monkeypatch.setattr(M, "_tool", lambda name: "/bin/true")
    monkeypatch.setattr(M, "_poppler", _fake_poppler([["FCI", "x", "FCI"]]))
    r = M.check(f, False, NO_VALUES)
    assert not r.ok and "an FCI banner" in r.problems[0]
    # unchanged: the non-CUI twin passes
    assert M.check(FX / "Access-Policy_v1.0.docx", False, NO_VALUES).ok


@pytest.mark.parametrize("name", ["FCI_Plan_v0.1-DRAFT.docx", "FCI_Data_v0.1-DRAFT.xlsx", "FCI_Notes_v0.1-DRAFT.md"])
def test_fci_insert_adds_the_fci_banner_only(tmp_path, name):
    f = copy(tmp_path, name)
    before = f.read_bytes()
    assert not M.check(f, True, NO_VALUES).ok
    plan = M.insert(f, NO_VALUES)                    # no CUI site keys needed for FCI
    assert plan and all("FCI banner" in x for x in plan), plan
    assert not any("designation block" in x or "CUI" in x for x in plan), plan
    assert f.read_bytes() == before
    assert M.insert(f, NO_VALUES, dry_run=False) == plan
    r = M.check(f, True, NO_VALUES)
    assert r.ok, r.problems
    if f.suffix == ".md":
        assert f.read_text().splitlines()[0] == "FCI" and "Controlled by" not in f.read_text()
    else:
        with zipfile.ZipFile(f) as z:
            text = b"".join(z.read(n) for n in z.namelist()).decode("utf-8", "replace")
        assert "Controlled by" not in text and ">CUI<" not in text and "&amp;CCUI" not in text
    assert M.insert(f, VALUES, dry_run=False) == []
    (tmp_path / "x").mkdir()
    g = copy(tmp_path / "x", name, src=FX)
    M.insert(g, VALUES, dry_run=False)               # the values do not matter for FCI: the same bytes
    assert g.read_bytes() == f.read_bytes()


def test_fci_insert_refuses_a_cui_marked_draft(tmp_path):
    """insert never removes a mark: an FCI_ draft that carries the CUI marks still fails after the FCI banner is
    added, so it is refused and nothing changes."""
    mk = _make()
    f = tmp_path / "FCI_Old_v0.1-DRAFT.docx"
    f.write_bytes(mk.docx(mk.BLOCK_XML, [mk.BANNER_HDR, mk.BANNER_FTR], mk.REFS))
    before = f.read_bytes()
    with pytest.raises(M.MarkingError, match="a CUI banner"):
        M.insert(f, NO_VALUES, dry_run=False)
    assert f.read_bytes() == before


# ---------- fix round 1 (Task 12 review) ----------

def test_md_insert_refuses_a_draft_with_the_other_banner(tmp_path):
    """IMPORTANT 1: insert must not push a wrong banner inward behind the right one (a false pass)."""
    f = tmp_path / "FCI_Probe_v0.1-DRAFT.md"
    f.write_text("CUI\n\nBody\n\nCUI\n")
    before = f.read_bytes()
    with pytest.raises(M.MarkingError, match="a CUI banner"):
        M.insert(f, NO_VALUES, dry_run=False)
    assert f.read_bytes() == before
    g = tmp_path / "CUI_Probe_v0.1-DRAFT.md"
    g.write_text("FCI\n\nBody\n\nFCI\n")
    before = g.read_bytes()
    with pytest.raises(M.MarkingError, match="an FCI banner"):
        M.insert(g, VALUES, dry_run=False)
    assert g.read_bytes() == before


def test_md_wrong_banner_anywhere_outside_code_fences(tmp_path):
    """A hand-written FCI_ md with a CUI banner line inside, and the reverse, fail; a fenced example does not."""
    f = tmp_path / "FCI_Hand_v1.0.md"
    f.write_text("FCI\n\nCUI\n\nBody\n\nFCI\n")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), r.problems
    f.write_text("FCI\n\nBody\n\nCUI//SP-PROPIN\n\nmore\n\nFCI\n")
    assert not M.check(f, True, NO_VALUES).ok
    g = tmp_path / "CUI_Hand_v1.0.md"
    block = "".join(f"{x}\n\n" for x in VALUES.block()[0])
    g.write_text("CUI\n\n" + block + "Body\n\nFCI\n\nCUI\n")
    r = M.check(g, True, VALUES)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), r.problems
    g.write_text("CUI\n\n" + block + "Example:\n\n```\nFCI\n```\n\n~~~\nFCI\n~~~\n\nCUI\n")
    r = M.check(g, True, VALUES)
    assert r.ok, r.problems


@pytest.mark.parametrize("word", ["CU​I", "‍CUI", "CUl", "CU1", "cuΙ", "C­UI"])
def test_wrong_banner_fold_catches_more_disguises(tmp_path, word):
    """m1: the wrong-banner search drops format characters (zero-width, soft hyphen) and folds l and 1 to i."""
    mk = _make()
    f = tmp_path / "FCI_Disguise_v1.0.docx"
    f.write_bytes(mk.docx(mk.FILLER, [("hdr", "header1.xml", mk.p("FCI", True) + mk.p(word, True)), mk.FCI_FTR],
                          mk.REFS))
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (word, r.problems)
    # the required banner stays exact: a disguised FCI is not an FCI banner
    g = tmp_path / "FCI_Disguise2_v1.0.docx"
    g.write_bytes(mk.docx(mk.FILLER, [("hdr", "header1.xml", mk.p("FC​I", True)), mk.FCI_FTR], mk.REFS))
    assert not M.check(g, True, NO_VALUES).ok


@pytest.mark.parametrize("line", ["CUI Category: PROPIN", "CUI  category :PROPIN", "cui​category: X",
                                  "CUl Category: X"])
def test_fci_block_label_variants(tmp_path, line):
    f = tmp_path / "FCI_Block_v1.0.md"
    f.write_text(f"FCI\n\n{line}\n\nBody\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("designation block" in p for p in r.problems), (line, r.problems)


def test_wrong_banner_in_a_docx_text_box_and_spelled_out(tmp_path):
    """m2: a wrong banner drawn in a header text box counts as present; "FCI - Federal Contract Information"-style
    lines count as an FCI banner on a CUI_ document (and CUI-style lines on an FCI_ one)."""
    mk = _make()
    f = tmp_path / "CUI_Box_v1.0.docx"
    f.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", mk.p("CUI", True) + mk.textbox("FCI")),
                                         mk.BANNER_FTR], mk.REFS))
    r = M.check(f, True, VALUES)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), r.problems
    for text in ("FCI - Federal Contract Information", "FCI – Federal Contract Information",
                 "FCI: Federal Contract Information", "Federal Contract Information"):
        g = tmp_path / "CUI_Spelled_v1.0.docx"
        g.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", mk.p("CUI", True) + mk.p(text, True)),
                                             mk.BANNER_FTR], mk.REFS))
        r = M.check(g, True, VALUES)
        assert not r.ok and any("an FCI banner" in p for p in r.problems), (text, r.problems)
    for text in ("CUI - Controlled Unclassified Information", "Controlled Unclassified Information"):
        h = tmp_path / "FCI_Spelled_v1.0.docx"
        h.write_bytes(mk.docx(mk.FILLER, [("hdr", "header1.xml", mk.p("FCI", True) + mk.p(text, True)), mk.FCI_FTR],
                              mk.REFS))
        r = M.check(h, True, NO_VALUES)
        assert not r.ok and any("a CUI banner" in p for p in r.problems), (text, r.problems)
    # the existing marks still pass
    assert M.check(FX / "CUI_Access-Policy_v1.0.docx", True, VALUES).ok
    assert M.check(FX / "FCI_Notice_v1.0.docx", True, NO_VALUES).ok


# ---------- fix round 2 (Task 12 re-review) ----------

MD_WRAPS = ["# {}", "## {} ##", "**{}**", "*{}*", "_{}_", "> {}", "> > {}", "{}\\", "<p>{}</p>", "`{}`",
            "- {}", "1. {}", "<b>{}</b>", "{} //SP-PROPIN", "C U I"]


@pytest.mark.parametrize("wrap", MD_WRAPS)
def test_md_wrong_banner_in_markdown_markup_is_seen(tmp_path, wrap):
    """Round 2 IMPORTANT 1: a wrong banner wrapped in Markdown markup still shows as a banner: it is seen."""
    inner = wrap.format("CUI") if "{}" in wrap else wrap
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{inner}\n\nBody\n\nFCI\n")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (inner, r.problems)
    if "{}" in wrap:
        g = tmp_path / "CUI_H_v1.0.md"
        block = "".join(f"{x}\n\n" for x in VALUES.block()[0])
        g.write_text(f"CUI\n\n{block}{wrap.format('FCI')}\n\nBody\n\nCUI\n")
        r = M.check(g, True, VALUES)
        assert not r.ok and any("an FCI banner" in p for p in r.problems), (wrap, r.problems)


@pytest.mark.parametrize("inner", ["# FCI", "**FCI**", "> FCI", "<p>FCI</p>"])
def test_md_insert_refuses_a_markup_wrapped_wrong_banner(tmp_path, inner):
    f = tmp_path / "CUI_D_v0.1-DRAFT.md"
    f.write_text(f"{inner}\n\nBody\n\n{inner}\n")
    before = f.read_bytes()
    with pytest.raises(M.MarkingError, match="an FCI banner"):
        M.insert(f, VALUES, dry_run=False)
    assert f.read_bytes() == before


BLOCK_MD = "".join(f"{x}\n\n" for x in VALUES.block()[0])
PROSE = [
    ("CUI_P_v1.0.md", True, "CUI\n\n" + BLOCK_MD + "Federal Contract Information (FCI) is defined in FAR 52.204-21 and "
                                                   "is\nhandled in the FCI folder.\n\nCUI\n"),
    ("CUI_P_v1.0.md", True, "CUI\n\n" + BLOCK_MD + "Our documents mark FCI as follows, per the owner decision:\nFCI: the "
                                                   "banner line at top and bottom.\n\nCUI\n"),
    ("CUI_P_v1.0.md", True, "CUI\n\n" + BLOCK_MD + "An FCI document carries the banner\nFCI (no designation block) at "
                                                   "top and bottom.\n\nCUI\n"),
    # Task 12b ruling (1): "# CUI handling policy" as the FIRST line of a non-CUI file is now refused (the word and
    # white space in a banner position); in the body it passes
    ("Policy_v1.0.md", False, "Notes\n\n# CUI handling policy\n\nControlled Unclassified Information (CUI) is "
                              "information the government\ncreates or possesses.\n"),
    # round 3 (controller ruling (c)): the first and last lines of a non-CUI Markdown file are banner positions, so
    # these prose lines sit in the body here; "CUI (Controlled Unclassified Information) ..." is refused, see below
    ("Policy_v1.0.md", False, "Notes\n\nStaff must mark documents that hold\nCUI - see the CUI handling procedure.\n\n"
                              "End.\n"),
    ("Policy_v1.0.md", False, "Notes\n\nDirections: turn into the\nCul-de-sac at the end of the road.\n\nEnd.\n"),
    ("Policy_v1.0.md", False, "Notes\n\nOur tooling uses the\nFCl: field in the form.\n\nEnd.\n"),
    ("Policy_v1.0.md", False, "See the CUI policy. The word CUI appears mid-line, fine.\n"),
    ("Policy_v1.0.md", False, "Notes\n\n# Federal Contract Information handling\n\nThe rules for FCI at this "
                              "site.\n"),
]


@pytest.mark.parametrize("name,cui,text", PROSE)
def test_md_prose_about_cui_and_fci_is_not_a_banner(tmp_path, name, cui, text):
    """Round 2 NEW IMPORTANT: ordinary sentences about CUI and FCI are not banners (no false alarm)."""
    f = tmp_path / name
    f.write_text(text)
    r = M.check(f, cui, VALUES if name.startswith("CUI_") else NO_VALUES)
    assert r.ok, r.problems


@pytest.mark.parametrize("line", ["FCI - Federal Contract Information", "Federal Contract Information",
                                  "FCI (Federal Contract Information)", "**Federal Contract Information**"])
def test_md_short_banner_forms_still_seen(tmp_path, line):
    """The spelled-out banner forms with a short tail stay wrong banners in a Markdown body."""
    g = tmp_path / "CUI_Short_v1.0.md"
    g.write_text("CUI\n\n" + BLOCK_MD + f"{line}\n\nBody\n\nCUI\n")
    r = M.check(g, True, VALUES)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), (line, r.problems)


# ---------- fix round 3 (controller design: normalise, wide ends, phrase tails, l/1 restored) ----------

# every probe of the reviewer's q.py and r.py (a wrong CUI banner inside an FCI_ Markdown file)
MD_PROBES = ["__CUI__", "[CUI](x)", "~~CUI~~", "<span>C</span>UI", "&#67;UI", "&#x43;UI", "CUI\n===", "CUI\n---",
             "| CUI |", "|CUI|", "C U I", "CUI // SP-PROPIN", "***CUI***", "1) CUI", "* * CUI", "[**CUI**]", "CUI<br>",
             "CUI  ", "\\*CUI\\*", "CUI&nbsp;", "&#x200b;CUI", "Controlled Unclassified Information",
             "CONTROLLED UNCLASSIFIED INFORMATION //SP-PROPIN",
             "CUI – Controlled Unclassified Information per DoDI 5200.48", "CUI//SP-PROPIN//NOFORN", "(CUI)", "CUI.",
             "**CUI:** SP-PROPIN", "<!-- --> CUI", "CUI <!-- x -->", "![CUI](x.png)", "[CUI]: http://x", "<CUI>",
             "C&#85;I", "- [ ] CUI", "- [x] CUI", ":CUI:",
             "| CUI |\n|---|\n| body |", "CUI |\n--- |", "[CUI][r]\n\n[r]: http://x", "<a href=x>CUI</a>", "&#x46;CI",
             "\\CUI", "CUI\\*", "**C**UI", "C*U*I", "&amp;#67;UI"]


@pytest.mark.parametrize("inner", MD_PROBES)
def test_round3_md_probes_fail(tmp_path, inner):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{inner}\n\nBody\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    want = "an FCI banner" if inner == "&#x46;CI" else "a CUI banner"     # &#x46;CI is FCI: not wrong in an FCI file
    if inner == "&#x46;CI":
        g = tmp_path / "CUI_H_v1.0.md"
        g.write_text(f"CUI\n\n{BLOCK_MD}{inner}\n\nBody\n\nCUI\n", encoding="utf-8")
        r = M.check(g, True, VALUES)
    assert not r.ok and any(want in p for p in r.problems), (inner, r.problems)


@pytest.mark.parametrize("inner", ["[FCI](x)", "&#70;CI", "| FCI |\n|---|", "\\*FCI\\*", "(FCI)", "FCI.", "- [ ] FCI",
                                   "FCI – Federal Contract Information per FAR 52.204-21"])
def test_round3_md_probes_fail_the_other_way(tmp_path, inner):
    g = tmp_path / "CUI_H_v1.0.md"
    g.write_text(f"CUI\n\n{BLOCK_MD}{inner}\n\nBody\n\nCUI\n", encoding="utf-8")
    r = M.check(g, True, VALUES)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), (inner, r.problems)


LONG = ["CUI – Controlled Unclassified Information per DoDI 5200.48",
        "CUI - Controlled Unclassified Information - handle per policy",
        "FCI – Federal Contract Information per FAR 52.204-21",
        "CUI: this document contains controlled technical information",
        "Controlled Unclassified Information per DoDI 5200.48 and 32 CFR 2002"]


@pytest.mark.parametrize("banner", LONG)
@pytest.mark.parametrize("where", ["first", "last", "both"])
def test_round3_non_cui_first_and_last_lines_are_banner_positions(tmp_path, banner, where):
    """Ruling (c): in the non-CUI area the first and last non-blank lines use the wide forms (fail closed)."""
    text = {"first": f"{banner}\n\nBody text.\n\nEnd\n", "last": f"Notes\n\nBody text.\n\n{banner}\n",
            "both": f"{banner}\n\nBody text.\n\n{banner}\n"}[where]
    f = tmp_path / "Policy_v1.0.md"
    f.write_text(text, encoding="utf-8")
    r = M.check(f, False, NO_VALUES)
    assert not r.ok and any("non-CUI area" in p for p in r.problems), (banner, where, r.problems)


@pytest.mark.parametrize("name,banner,values", [
    ("FCI_D_v0.1-DRAFT.md", "CUI – Controlled Unclassified Information per DoDI 5200.48", NO_VALUES),
    ("CUI_D_v0.1-DRAFT.md", "FCI – Federal Contract Information per FAR 52.204-21", VALUES),
    ("FCI_D_v0.1-DRAFT.md", "[CUI](x)", NO_VALUES), ("FCI_D_v0.1-DRAFT.md", "&#67;UI", NO_VALUES),
    ("FCI_D_v0.1-DRAFT.md", "| CUI |\n|---|", NO_VALUES),
    ("FCI_D_v0.1-DRAFT.md", "CUI: this document contains controlled technical information", NO_VALUES)])
def test_round3_insert_refuses_long_and_disguised_wrong_banners(tmp_path, name, banner, values):
    """Insert never wraps a wrong banner (CUI under-marked as FCI is the worst direction)."""
    f = tmp_path / name
    f.write_text(f"{banner}\n\nBody\n\n{banner}\n", encoding="utf-8")
    before = f.read_bytes()
    with pytest.raises(M.MarkingError, match="an FCI banner" if name.startswith("CUI_") else "a CUI banner"):
        M.insert(f, values, dry_run=False)
    assert f.read_bytes() == before


@pytest.mark.parametrize("text", ["CUl - SP-PROPIN", "CU1 – Controlled Unclassified Information", "CUl: PROPIN",
                                  "CUl (SP-PROPIN)", "ControIIed UncIassified Information",
                                  "Contro11ed Unc1assified Information", "CUl//SP-PROPIN"])
def test_round3_l1_fold_in_docx_and_xlsx_headers(tmp_path, text):
    """Ruling (d): the wide forms read l and 1 as i again, separator and phrase forms included."""
    mk = _make()
    f = tmp_path / "FCI_Hdr_v1.0.docx"
    f.write_bytes(mk.docx(mk.FILLER, [("hdr", "header1.xml", mk.p("FCI", True) + mk.p(text, True)), mk.FCI_FTR],
                          mk.REFS))
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (text, r.problems)
    g = tmp_path / "FCI_Hdr_v1.0.xlsx"
    hf = dict(mk.FCI_HF, oddHeader="&CFCI\n" + text.replace("&", "&&"))
    g.write_bytes(mk.xlsx([("Items", mk.sheet([["A"]], hf))]))
    r = M.check(g, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (text, r.problems)


@pytest.mark.parametrize("text", ["FCl - Federal Contract Information", "FederaI Contract Information",
                                  "Federa1 Contract Information (FAR 52.204-21)"])
def test_round3_l1_fold_fci_forms_in_docx_headers(tmp_path, text):
    mk = _make()
    f = tmp_path / "CUI_Hdr_v1.0.docx"
    f.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", mk.p("CUI", True) + mk.p(text, True)),
                                         mk.BANNER_FTR], mk.REFS))
    r = M.check(f, True, VALUES)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), (text, r.problems)


# prose forms that are now REFUSED in a Markdown body (to tell authors; recorded in the report and the guide)
REFUSED_PROSE = ["## Controlled Unclassified Information", "CUI: see section 3.", "CUI - what it is", "# CUI", "- CUI",
                 "| CUI | yes |", "CUI | FCI | none of them apply here",
                 "CUI (Controlled Unclassified Information) with the banner."]


@pytest.mark.parametrize("line", REFUSED_PROSE)
def test_round3_banner_shaped_prose_is_refused_in_a_body(tmp_path, line):
    f = tmp_path / "Policy_v1.0.md"
    f.write_text(f"Policy\n\n{line}\n\nmore text here\n", encoding="utf-8")
    r = M.check(f, False, NO_VALUES)
    assert not r.ok, line


def test_round3_prose_that_still_passes(tmp_path):
    for line in ["**CUI** documents go in the CUI area.", "Controlled Unclassified Information (CUI) is defined in 32 "
                 "CFR 2002.", "Cuisine - a note", "Fcilities: map", "Cul-de-sac at the end of the road.",
                 "FCl: field in the form."]:
        f = tmp_path / "Policy_v1.0.md"
        f.write_text(f"Policy\n\n{line}\n\nmore text here\n", encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert r.ok, (line, r.problems)


# ---------- Task 12b (round-3 re-review: combining marks, <br>, minor disguises, DoS, indented code) ----------

def _fci_md(tmp_path, inner):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{inner}\n\nBody\n\nFCI\n", encoding="utf-8")
    return M.check(f, True, NO_VALUES)


def _cui_md(tmp_path, inner):
    g = tmp_path / "CUI_H_v1.0.md"
    g.write_text(f"CUI\n\n{BLOCK_MD}{inner}\n\nBody\n\nCUI\n", encoding="utf-8")
    return M.check(g, True, VALUES)


def _fci_docx_header(tmp_path, text):
    mk = _make()
    f = tmp_path / "FCI_Hdr_v1.0.docx"
    f.write_bytes(mk.docx(mk.FILLER, [("hdr", "header1.xml", mk.p("FCI", True) + mk.p(text, True)), mk.FCI_FTR],
                          mk.REFS))
    return M.check(f, True, NO_VALUES)


COMBINING = ["C̲U̲I̲", "ĆUI", "CUÍ", "CÜI", "CÚI", "C⃝U⃝I⃝",
             "Controlled Unclassified Informatión", "ĆUI//SP-PROPIN"]


@pytest.mark.parametrize("inner", COMBINING)
def test_12b_combining_marks_are_folded(tmp_path, inner):
    """12b item 1: a wrong banner with combining marks (accents, underline, enclosing circles) is still seen, in a
    Markdown body and in a docx header (the wide forms)."""
    r = _fci_md(tmp_path, inner)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (inner, r.problems)
    assert M._looks_like(inner, "cui", True) and M._looks_like(inner, "cui", False), inner
    r = _fci_docx_header(tmp_path, inner)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (inner, r.problems)


@pytest.mark.parametrize("inner", ["F̲C̲I̲", "F́CI", "Federal Contract Informatión"])
def test_12b_combining_marks_fci_forms(tmp_path, inner):
    r = _cui_md(tmp_path, inner)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), (inner, r.problems)


@pytest.mark.parametrize("first", ["C̲U̲I̲", "ĆUI", "CÚI"])
def test_12b_required_banner_stays_exact_ascii(tmp_path, first):
    """The required banner is never folded: a CUI_ file whose banner lines carry marks is not marked."""
    f = tmp_path / "CUI_X_v1.0.md"
    f.write_text(f"{first}\n\n{BLOCK_MD}Body\n\n{first}\n", encoding="utf-8")
    r = M.check(f, True, VALUES)
    assert not r.ok
    assert any("the first line must be the CUI banner" in p for p in r.problems), r.problems
    assert any("the last line must be the CUI banner" in p for p in r.problems), r.problems


BR = ["CUI<br/>SP-PROPIN", "CUI<br>SP-PROPIN", "CUI<BR class=x />SP-PROPIN", "CUI< br >SP-PROPIN",
      "Intro text<br>CUI<br>more words follow here", "CUI</p><p>SP-PROPIN", "<div>CUI</div>SP-PROPIN",
      "<td>CUI</td><td>yes</td>"]


@pytest.mark.parametrize("inner", BR)
def test_12b_html_line_breaks_split_the_line(tmp_path, inner):
    """12b item 2: <br> (any case, attributes, self-closing) and block tags render as a line break: each piece is
    judged as a line."""
    r = _fci_md(tmp_path, inner)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (inner, r.problems)


MINOR = ["“CUI”", "«CUI»", "‹CUI›", "„CUI“", "CUI…", "CUI[^1]",
         "# CUI {#id}", "## CUI {.cls}", "C-U-I", "C.U.I.", "C_U_I", "C/U/I", "C-U-I: SP-PROPIN",
         "C.U.I. - SP-PROPIN", "CUI / / SP-PROPIN", "CUI / /SP-PROPIN", "CUI ∕∕ SP-PROPIN",
         "Controlled-Unclassified-Information", "Controlled_Unclassified_Information",
         "Controlled-Unclassified-Information - SP-PROPIN", "#CUI", "★CUI★"]


@pytest.mark.parametrize("inner", MINOR)
def test_12b_minor_disguises_are_seen(tmp_path, inner):
    """12b item 3: curly and angle quotes, ellipsis, footnote references, heading attributes, spelled-out letters,
    a spaced //, a hyphenated phrase."""
    r = _fci_md(tmp_path, inner)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (inner, r.problems)


@pytest.mark.parametrize("inner", ["“FCI”", "F.C.I.", "F-C-I", "Federal-Contract-Information", "FCI[^1]",
                                   "# FCI {#x}", "FCI / / X", "FCI…"])
def test_12b_minor_disguises_fci_forms(tmp_path, inner):
    r = _cui_md(tmp_path, inner)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), (inner, r.problems)


@pytest.mark.parametrize("text", ["“CUI”", "C.U.I.", "C-U-I", "CUI / / SP-PROPIN",
                                  "Controlled-Unclassified-Information", "CUI…"])
def test_12b_minor_disguises_in_docx_headers(tmp_path, text):
    r = _fci_docx_header(tmp_path, text)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (text, r.problems)


def test_12b_prose_still_passes(tmp_path):
    for line in ["The “CUI” label is defined in 32 CFR 2002.", "See the footnote[^1] about the CUI area.",
                 "Line one<br>more words about the CUI area here", "Cu, I think, is copper.",
                 "**CUI** documents go in the CUI area.", "Cul-de-sac at the end of the road.",
                 "<b>CUI</b> documents go in the CUI area.", "# Handling {#handling}"]:
        f = tmp_path / "Policy_v1.0.md"
        f.write_text(f"Policy\n\n{line}\n\nmore text here\n", encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert r.ok, (line, r.problems)


# 12b item 4: no Markdown reading is quadratic; a line over the cap is refused, not scanned
ADVERSARIAL = ["![", "[", "<!--", "[a](", "](", "<", "&amp;", "\\", "* ", "  ", "|", "{", "C", "Controlled ", "/ ",
               "<br>", "[^", "``", "- ", "a_", "CUI_a_", "x_v1.2"]


def test_12b_long_markdown_line_is_refused(tmp_path):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text("FCI\n\n" + "a" * (M.MD_MAX_LINE + 1) + "\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any(f"longer than {M.MD_MAX_LINE} characters" in p and "cannot be checked" in p
                            for p in r.problems), r.problems
    d = tmp_path / "FCI_D_v0.1-DRAFT.md"
    d.write_text("Body\n\n" + "a" * (M.MD_MAX_LINE + 1) + "\n", encoding="utf-8")
    before = d.read_bytes()
    with pytest.raises(M.MarkingError, match="cannot be checked"):
        M.insert(d, NO_VALUES, dry_run=False)
    assert d.read_bytes() == before
    # a long line inside a code fence is not judged, so it is no problem
    f.write_text("FCI\n\n```\n" + "a" * (M.MD_MAX_LINE + 1) + "\n```\n\nFCI\n", encoding="utf-8")
    assert M.check(f, True, NO_VALUES).ok


def test_12b_adversarial_lines_check_quickly(tmp_path):
    import time
    f = tmp_path / "FCI_H_v1.0.md"
    t = time.monotonic()
    f.write_text("FCI\n\n" + "![" * (32 << 10) + "\n\nFCI\n", encoding="utf-8")            # 64 KiB line: refused
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("cannot be checked" in p for p in r.problems)
    assert time.monotonic() - t < 2, "a 64 KiB line took too long"
    for unit in ADVERSARIAL:
        line = (unit * (M.MD_MAX_LINE // len(unit)))[:M.MD_MAX_LINE]                         # just under the cap
        t = time.monotonic()
        f.write_text(f"FCI\n\n{line}\n\n{line}CUI\n\nFCI\n", encoding="utf-8")
        M.check(f, True, NO_VALUES)
        assert time.monotonic() - t < 2, (unit, time.monotonic() - t)


# 12b item 5: an indented code block (CommonMark: 4 spaces or a tab, after a blank line, not inside a list) renders
# as code, so it is exempt like a fenced block; anything that renders as text stays judged
@pytest.mark.parametrize("body", ["Para\n\n    CUI\n\nBody", "Para\n\n\tCUI\n\nBody",
                                  "Para\n\n    code line\n\n    CUI\n    more code\n\nBody",
                                  "- item\n\ntext after the list\n\n    CUI\n\nBody",
                                  "> quoted\n\n    CUI\n\nBody", "  \t  CUI\n\nBody"])
def test_12b_indented_code_is_exempt(tmp_path, body):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{body}\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert r.ok, (body, r.problems)


@pytest.mark.parametrize("body", ["Para\n    CUI\n\nBody",                     # a paragraph continuation, not code
                                  "- item\n\n    CUI\n\nBody",                  # a paragraph in the list item
                                  "1. item\n\n    CUI\n\nBody",
                                  "- item\nlazy continuation\n\n    CUI\n\nBody",
                                  "- item\n\n  - nested\n\n    CUI\n\nBody",
                                  "   CUI\n\nBody"])                            # 3 spaces: not code
def test_12b_indented_text_that_renders_as_text_is_judged(tmp_path, body):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{body}\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (body, r.problems)


def test_12b_indented_code_at_the_ends_is_still_a_banner_position(tmp_path):
    """The first and last non-blank lines stay banner positions (fail closed) even when they are indented code."""
    for text in ["    CUI\n\nBody text.\n\nEnd\n", "Notes\n\nBody text.\n\n    CUI\n"]:
        f = tmp_path / "Policy_v1.0.md"
        f.write_text(text, encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert not r.ok and any("non-CUI area" in p for p in r.problems), (text, r.problems)


# ---------- Task 12b pre-review additions (controller rulings 2026-11-20) ----------

@pytest.mark.parametrize("text", ["CUI SP-PROPIN", "CUI\tSP-PROPIN", "CUI PROPIN", "C̲UI SP-PROPIN",
                                  "“CUI” SP-PROPIN"])
def test_12b_wide_word_and_space_is_a_banner_docx_xlsx(tmp_path, text):
    """Ruling (1): in a banner position the other kind's word, white space and anything is a banner (fail closed)."""
    r = _fci_docx_header(tmp_path, text)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (text, r.problems)
    mk = _make()
    g = tmp_path / "FCI_Hdr_v1.0.xlsx"
    g.write_bytes(mk.xlsx([("Items", mk.sheet([["A"]], dict(mk.FCI_HF, oddHeader="&CFCI\n" + text)))]))
    r = M.check(g, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (text, r.problems)
    assert M._looks_like(text, "cui", True)


@pytest.mark.parametrize("text", ["FCI contract data", "FCI SP-X"])
def test_12b_wide_word_and_space_fci_in_a_cui_docx_header(tmp_path, text):
    mk = _make()
    f = tmp_path / "CUI_Hdr_v1.0.docx"
    f.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", mk.p("CUI", True) + mk.p(text, True)),
                                         mk.BANNER_FTR], mk.REFS))
    r = M.check(f, True, VALUES)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), (text, r.problems)


@pytest.mark.parametrize("name,cui,text,want", [
    ("Policy_v1.0.md", False, "# CUI handling policy\n\nBody text.\n\nEnd\n", "a CUI banner"),
    ("Policy_v1.0.md", False, "Notes\n\nBody text.\n\nCUI SP-PROPIN\n", "a CUI banner"),
    ("Policy_v1.0.md", False, "FCI contract data\n\nBody text.\n\nEnd\n", "an FCI banner"),
    ("FCI_H_v1.0.md", True, "FCI\n\nBody\n\nFCI\n\nCUI SP-PROPIN\n", "a CUI banner"),
    ("CUI_H_v1.0.md", True, "FCI contract data\n\n" + BLOCK_MD + "Body\n\nCUI\n", "an FCI banner")])
def test_12b_wide_word_and_space_md_ends(tmp_path, name, cui, text, want):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    r = M.check(f, cui, VALUES if name.startswith("CUI_") else NO_VALUES)
    assert not r.ok and any(want in p for p in r.problems), (text, r.problems)


def test_12b_word_and_space_in_the_md_body_still_passes(tmp_path):
    """Ruling (1): the Markdown body is unchanged; prose that starts with the word passes there."""
    for line in ["CUI handling policy", "CUI documents go in the CUI area.", "FCI contract data is kept apart."]:
        f = tmp_path / "Policy_v1.0.md"
        f.write_text(f"Policy\n\n{line}\n\nmore text here\n", encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert r.ok, (line, r.problems)


def test_12b_correctly_marked_documents_still_pass(tmp_path):
    """The right banner (with //markings for CUI) and the designation block are not caught by the wide rule."""
    for name in ("CUI_Access-Policy_v1.0.docx", "CUI_Access-Policy_v1.0.xlsx", "FCI_Access-Policy_v1.0.docx",
                 "FCI_Access-Policy_v1.0.xlsx"):
        if (FX / name).exists():
            r = M.check(FX / name, True, NO_VALUES if name.startswith("FCI_") else VALUES)
            assert r.ok, (name, r.problems)
    f = tmp_path / "CUI_Ok_v1.0.md"
    f.write_text("CUI//SP-PROPIN\n\n" + BLOCK_MD + "Body about FCI contract data.\n\nCUI//SP-PROPIN\n", encoding="utf-8")
    assert M.check(f, True, VALUES).ok
    g = tmp_path / "FCI_Ok_v1.0.md"
    g.write_text("FCI\n\nBody: CUI handling is elsewhere.\n\nFCI\n", encoding="utf-8")
    assert M.check(g, True, NO_VALUES).ok
    mk = _make()
    h = tmp_path / "CUI_Hdr_v1.0.docx"
    h.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", mk.p("CUI//SP-PROPIN", True)), mk.BANNER_FTR],
                          mk.REFS))
    assert M.check(h, True, VALUES).ok


def test_12b_server_packages_pin_the_current_chp_site():
    """Ruling (3): the server's publish re-check is never more lenient than the workstation checker: chp-documents
    and chp-identity-server require chp-site's current release."""
    cs = (TOP / "appliance/chp-site/chp-site.spec").read_text()
    cur = re.search(r"^Version:\s+(\S+)", cs, re.M).group(1) + "-" + re.search(r"^Release:\s+(\d+)\.chp", cs,
                                                                                re.M).group(1)
    for spec in ("chp-documents/chp-documents.spec", "chp-identity-server/chp-identity-server.spec"):
        s = (TOP / "appliance/rpm" / spec).read_text()
        pin = re.search(r"^Requires:.*\bchp-site >= (\S+?),?(?:\s|$)", s, re.M)
        assert pin and pin.group(1) == cur, (spec, pin and pin.group(1), cur)


# ---------- Task 12b fix round 1 (review I1, I2; controller rulings) ----------

@pytest.mark.parametrize("body", ["See it[^1].\n\n[^1]: A note.\n\n    CUI//SP-PROPIN\n\nBody",
                                  "See it[^n].\n\n   [^n]: A note.\n\n    CUI\n\nBody",
                                  "Term\n: definition\n\n    CUI\n\nBody",
                                  "!!! note\n\n    CUI\n\nBody", "??? note \"Title\"\n\n    CUI\n\nBody"])
def test_12b_r1_footnote_definition_and_admonition_open_a_container(tmp_path, body):
    """I1: indented text after a footnote definition, a definition line or an admonition head belongs to it and
    renders as text: it is judged (fail closed), like the text of a list item."""
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{body}\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (body, r.problems)


def test_12b_r1_container_ends_at_a_column_0_paragraph(tmp_path):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text("FCI\n\nSee it[^1].\n\n[^1]: A note.\n\nA paragraph.\n\n    CUI\n\nBody\n\nFCI\n", encoding="utf-8")
    assert M.check(f, True, NO_VALUES).ok


WIDE_SEPS = ["CUI/SP-PROPIN", "CUI_SP-PROPIN", "CUI.SP-PROPIN", "CUI;SP-PROPIN", "CUI•SP", "CUI·SP",
             "CUI's handling", "CUI,SP", "CUI+SP"]


@pytest.mark.parametrize("text", WIDE_SEPS)
def test_12b_r1_wide_word_and_any_non_alphanumeric(tmp_path, text):
    """I2: in a banner position the other kind's word followed by any character that is not a letter or digit (or by
    white space) is a banner."""
    assert M._looks_like(text, "cui", True), text
    r = _fci_docx_header(tmp_path, text)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (text, r.problems)
    f = tmp_path / "Policy_v1.0.md"
    f.write_text(f"Notes\n\nBody text.\n\n{text}\n", encoding="utf-8")
    r = M.check(f, False, NO_VALUES)
    assert not r.ok and any("non-CUI area" in p for p in r.problems), (text, r.problems)


@pytest.mark.parametrize("text", ["FCI/contract", "FCI_contract", "FCI.data"])
def test_12b_r1_wide_fci_word_and_any_non_alphanumeric(tmp_path, text):
    mk = _make()
    f = tmp_path / "CUI_Hdr_v1.0.docx"
    f.write_bytes(mk.docx(mk.BLOCK_XML, [("hdr", "header1.xml", mk.p("CUI", True) + mk.p(text, True)),
                                         mk.BANNER_FTR], mk.REFS))
    r = M.check(f, True, VALUES)
    assert not r.ok and any("an FCI banner" in p for p in r.problems), (text, r.problems)


@pytest.mark.parametrize("line", ["CUI/X", "CUI·X", "CUI•X", "CUI/SP-PROPIN", "CUI / X"])
def test_12b_r1_md_body_slash_and_dot_separators(tmp_path, line):
    r = _fci_md(tmp_path, line)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (line, r.problems)


def test_12b_r1_md_body_prose_with_a_slash_still_passes(tmp_path):
    for line in ["The CUI/FCI split is explained in the policy.", "CUI/FCI handling rules apply to every document here.",
                 "Cuisine/food notes", "Cuisine•a note about food"]:
        f = tmp_path / "Policy_v1.0.md"
        f.write_text(f"Policy\n\n{line}\n\nmore text here\n", encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert r.ok, (line, r.problems)
    assert not M._looks_like("Cuisine Ltd", "cui", True) and not M._looks_like("CUI2 Ltd", "cui", True)


# ---------- Task 12b fix round 2 (re-review: pandoc/tab containers; citations in banner positions) ----------

@pytest.mark.parametrize("body", ["Term\n~ definition\n\n    CUI\n\nBody", "Term\n  ~ def\n\n    CUI\n\nBody",
                                  "Term\n:   def\n\n    CUI\n\nBody", "=== \"Tab\"\n\n    CUI\n\nBody"])
def test_12b_r2_pandoc_definitions_and_tabs_open_a_container(tmp_path, body):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{body}\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (body, r.problems)


CITE_LINES = ["- CUI_SSP_v1.2", "1. CUI_SSP_v1.2", "- [CUI_SSP_v1.2](CUI_SSP_v1.2.docx)",
              "- CUI_SSP_v1.2 - System Security Plan", "[CUI_SSP_v1.2](x)", "| CUI_SSP_v1.2 | SSP |", "CUI_SSP_v1.2",
              "- FCI_Contract_v1.0", "FCI_Contract_v1.0", "# CUI_SSP_v1.2 review notes", "CUI_SSP_v1.2 cross-reference",
              "CUI_SSP_v1.2-DRAFT.docx", "CUI_POAM_v2.0.xlsx"]


@pytest.mark.parametrize("line", CITE_LINES)
def test_12b_r2_citations_in_banner_positions_pass(tmp_path, line):
    """A document name (<prefix><title>_vX.Y[-DRAFT][.ext]) on the first or last line is a citation, not a banner."""
    for text in (f"{line}\n\nIntro.\n\nMore.\n", f"Handbook\n\nIntro.\n\nReferences:\n\n{line}\n"):
        f = tmp_path / "Handbook_v1.0.md"
        f.write_text(text, encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert r.ok, (text, r.problems)


@pytest.mark.parametrize("text", ["CUI_SSP_v1.2 — page 1", "CUI_SSP_v1.2", "Doc: CUI_SSP_v1.2"])
def test_12b_r2_fci_docx_header_naming_a_cui_document(tmp_path, text):
    r = _fci_docx_header(tmp_path, text)
    assert r.ok, (text, r.problems)


@pytest.mark.parametrize("line", ["CUI_SP-PROPIN", "CUI_X", "FCI_contract", "CUI_SSP_v1", "CUI_SSP_vX.Y",
                                  "CUI_SSP_v١.٢"])
def test_12b_r2_underscore_without_a_citation_is_still_a_banner(tmp_path, line):
    kind = "fci" if line.startswith("FCI") else "cui"
    assert M._looks_like(line, kind, True), line
    f = tmp_path / "Handbook_v1.0.md"
    f.write_text(f"Handbook\n\nIntro.\n\n{line}\n", encoding="utf-8")
    assert not M.check(f, False, NO_VALUES).ok, line
    if kind == "cui":
        r = _fci_docx_header(tmp_path, line)
        assert not r.ok and any("a CUI banner" in p for p in r.problems), (line, r.problems)


# ---------- Task 12b fix round 3 (re-review: tab variants; judge what follows a cited name; SP- titles) ----------

@pytest.mark.parametrize("head", ['===+ "Tab"', '===! "Tab"', '===!+ "Tab"'])
def test_12b_r3_tab_head_variants_open_a_container(tmp_path, head):
    f = tmp_path / "FCI_H_v1.0.md"
    f.write_text(f"FCI\n\n{head}\n\n    CUI\n\nBody\n\nFCI\n", encoding="utf-8")
    r = M.check(f, True, NO_VALUES)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (head, r.problems)


CITE_BANNER_TAILS = ["CUI_SSP_v1.2 // SP-PROPIN", "CUI_SSP_v1.2//SP-PROPIN", "CUI_SSP_v1.2 ⁄⁄ SP-PROPIN",
                     "CUI_x_v1.0 // NOFORN", "CUI_SP_PROPIN_v1.0 // NOFORN", "CUI_SSP_v1.2 - CUI//SP-PROPIN",
                     "CUI_x_v1.0 CUI//SP-PROPIN", "CUI_SSP_v1.2 CUI", "CUI_SSP_v1.2 Controlled Unclassified Information",
                     "CUI_x_v1.0 SP-PROPIN", "CUI_SSP_v1.2 | CUI", "CUI_SSP_v1.2_CUI//SP-PROPIN",
                     "CUI_SSP_v1.2 NOFORN", "CUI_SSP_v1.2·SP-PROPIN", "CUI_SSP_v1.2CUI", "CUI_SP-PROPIN_v1.0",
                     "CUI_SP-PROPIN_v1.0-DRAFT.docx", "CUI_v1.0", "CUI__SSP_v1.2", "C-U-I_SSP_v1.2", "CUI_SSP_v1.2.3",
                     "CUI_SSP_v01.2", "CUI_-_v1.0"]


@pytest.mark.parametrize("line", CITE_BANNER_TAILS)
def test_12b_r3_what_follows_a_cited_name_is_judged(tmp_path, line):
    """Only the name token is a citation; a //, the word, the phrase or a capitals marking after it is a banner;
    an SP- title, an empty title or a broken version is no citation at all. Same verdict in docx and md."""
    assert M._looks_like(line, "cui", True), line
    r = _fci_docx_header(tmp_path, line)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (line, r.problems)
    for text in (f"{line}\n\nIntro.\n\nMore.\n", f"Handbook\n\nIntro.\n\n{line}\n"):
        f = tmp_path / "Handbook_v1.0.md"
        f.write_text(text, encoding="utf-8")
        assert not M.check(f, False, NO_VALUES).ok, text


@pytest.mark.parametrize("line", ["CUI_SSP_v1.2 - System Security Plan", "CUI_SSP_v1.2 review notes",
                                  "CUI_SSP_v1.2 — page 1", "CUI_SSP_v1.2 cross-reference", "CUI_SSP_v1.2",
                                  "CUI_SSP_V1.2", "CUI_SSP_v1.2-DRAFT.docx (draft)", "CUI_PROPIN_v1.0",
                                  "CUI_SSP_v1.2: see page 3"])
def test_12b_r3_allowed_tails_after_a_cited_name_pass(tmp_path, line):
    assert not M._looks_like(line, "cui", True), line
    assert _fci_docx_header(tmp_path, line).ok, line
    for text in (f"{line}\n\nIntro.\n\nMore.\n", f"Handbook\n\nIntro.\n\n{line}\n"):
        f = tmp_path / "Handbook_v1.0.md"
        f.write_text(text, encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert r.ok, (text, r.problems)


# ---------- Task 12b fix round 4: one Latin-confusables fold; the tail read like a line start; further citations ----

def _judged_everywhere(tmp_path, line):
    """A wrong CUI banner in every banner position: _looks_like (wide), an FCI_ docx header, and the first and the
    last line of a non-CUI Markdown file."""
    assert M._looks_like(line, "cui", True), line
    r = _fci_docx_header(tmp_path, line)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (line, r.problems)
    for text in (f"{line}\n\nIntro.\n\nMore.\n", f"Handbook\n\nIntro.\n\n{line}\n"):
        f = tmp_path / "Handbook_v1.0.md"
        f.write_text(text, encoding="utf-8")
        assert not M.check(f, False, NO_VALUES).ok, text


def _passes_everywhere(tmp_path, line):
    assert not M._looks_like(line, "cui", True), line
    r = _fci_docx_header(tmp_path, line)
    assert r.ok, (line, r.problems)
    for text in (f"{line}\n\nIntro.\n\nMore.\n", f"Handbook\n\nIntro.\n\n{line}\n"):
        f = tmp_path / "Handbook_v1.0.md"
        f.write_text(text, encoding="utf-8")
        r = M.check(f, False, NO_VALUES)
        assert r.ok, (text, r.problems)


# item 1: letters from other scripts that look like Latin letters are read as those letters before every check
R4_CONFUSABLE = ["CUI_SР-PROPIN_v1.0",          # Cyrillic Er: an SP- title, no citation
                 "CUI_ЅP-PROPIN_v1.0",          # Cyrillic Dze
                 "CUI_SSP_v1.2 SР-PROPIN",      # Cyrillic Er in the capitals marking
                 "CUI_SSP_v1.2 NОFORN",         # Cyrillic O
                 "CUI_SSP_v1.2 ΝΟFORN",    # Greek Nu, Omicron
                 "CUI_SSP_v1.2 SΡ-PROPIN",      # Greek Rho
                 "CUI_SSP_v1.2 ᏟᏚP",       # Cherokee Tli, Du: "CSP"
                 "ᏟUI//SP-PROPIN",              # Cherokee Tli at the line start
                 "C∪I//SP-PROPIN",              # union sign as U
                 "ꓚꓴI SP-PROPIN",          # Lisu Ca, U
                 "CUI_SSP_v1.2 ᏟUI"]            # the word, disguised, after a cited name


@pytest.mark.parametrize("line", R4_CONFUSABLE)
def test_12b_r4_confusable_letters_are_folded_everywhere(tmp_path, line):
    _judged_everywhere(tmp_path, line)


@pytest.mark.parametrize("inner", ["ᏟUI", "C∪I", "ᏟUI//SP-PROPIN", "ꓚꓴI"])
def test_12b_r4_confusable_word_in_the_md_body(tmp_path, inner):
    r = _fci_md(tmp_path, inner)
    assert not r.ok and any("a CUI banner" in p for p in r.problems), (inner, r.problems)


def test_12b_r4_confusables_table():
    """The fold table: non-ASCII sources only, one ASCII letter each; the earlier hand-made lookalikes kept; a few
    entries from the Unicode confusables data (UTS #39) checked by hand."""
    t = M._LATIN_FOLD
    assert t and all(k > 127 and isinstance(v, str) and len(v) == 1 and v.isascii() and v.isalpha()
                     for k, v in t.items())
    for src, dst in {"С": "C", "с": "c", "Ϲ": "C", "ϲ": "c", "І": "I", "і": "i",
                     "Ι": "I", "ι": "i", "Ӏ": "I", "Յ": "U", "Ս": "U", "ս": "u",
                     "υ": "u", "У": "U", "ᗅ": "F", "Ƒ": "F", "Ϝ": "F",
                     "Р": "P", "О": "O", "Ν": "N", "Ρ": "P", "Ꮯ": "C", "Ѕ": "S",
                     "∪": "U"}.items():
        assert t.get(ord(src)) == dst, (hex(ord(src)), t.get(ord(src)), dst)
    assert M._wfold("SР-PROPIN NОFORN", li=False, cf=False) == "SP-PROPIN NOFORN"


def test_12b_r4_required_banner_is_not_folded(tmp_path):
    """The fold never touches the REQUIRED banner: lookalike letters in a CUI_ file's banner lines are no banner."""
    for first in ("СUI", "CUI//SP-PRОPIN", "ᏟUI"):
        f = tmp_path / "CUI_X_v1.0.md"
        f.write_text(f"{first}\n\n{BLOCK_MD}Body\n\n{first}\n", encoding="utf-8")
        r = M.check(f, True, VALUES)
        assert not r.ok
        assert any("the first line must be the CUI banner" in p for p in r.problems), (first, r.problems)
        assert any("the last line must be the CUI banner" in p for p in r.problems), (first, r.problems)


def test_12b_r4_confusable_prefix_is_refused():
    for name in ("ᏟUI_SSP_v1.0.docx", "FCІ_SSP_v1.0.docx", "ꓝꓚI_SSP_v1.0.docx"):
        with pytest.raises(M.NameRuleError, match="prefix"):
            M.parse_name(name)


# items 2 and 3: what follows a cited name is read like a line start (the spelled-out word; l and 1 as i)
R4_TAIL_READING = ["CUI_SSP_v1.2: C U I", "CUI_SSP_v1.2 C.U.I.", "CUI_SSP_v1.2 — C/U/I", "CUI_SSP_v1.2 (C-U-I)",
                   "CUI_SSP_v1.2 cul", "CUI_SSP_v1.2 Cu1", "CUI_SSP_v1.2 CUl", "CUI_SSP_v1.2 — cu1",
                   "CUI_SSP_v1.2 C U l"]


@pytest.mark.parametrize("line", R4_TAIL_READING)
def test_12b_r4_tail_is_read_like_a_line_start(tmp_path, line):
    _judged_everywhere(tmp_path, line)


# item 4: a further citation in the tail is a citation, not the word; what follows it is judged the same way
R4_FURTHER_BAD = ["CUI_SSP_v1.2, CUI_POAM_v1.0 SP-PROPIN", "CUI_SSP_v1.2, CUI_POAM_v1.0 // SP-PROPIN",
                  "CUI_SSP_v1.2 CUI_POAM_v1.0 NOFORN", "CUI_SSP_v1.2, CUI_POAM_v1.0, CUI",
                  "CUI_SSP_v1.2, CUI_POAM_v1.0: C U I", "CUI_SSP_v1.2, CUI_SP-PROPIN_v1.0",
                  "CUI_SSP_v1.2, CUI_POAM_v1.0 cul", "CUI_SSP_v1.2, CUI_POAM_v1.0 SР-PROPIN",
                  "CUI_SSP_v1.2, CUI_POAM_v1.0, CUI_IRP_v2.1 NOFORN", "CUI_SSP_v1.2, CUI_POAM_v1.0 FCI",
                  "CUI_SSP_v1.2, CUI_POAM", "CUI_SSP_v1.2, CUI_POAM_v1.0 Controlled Unclassified Information"]
R4_FURTHER_OK = ["CUI_SSP_v1.2, CUI_POAM_v1.0", "CUI_SSP_v1.2 and CUI_POAM_v1.0",
                 "CUI_SSP_v1.2, CUI_POAM_v1.0, CUI_IRP_v2.1 review notes",
                 "CUI_SSP_v1.2 — CUI_POAM_v1.0-DRAFT.xlsx (draft)", "CUI_SSP_v1.2 supersedes CUI_SSP_v1.1",
                 "CUI_SSP_v1.2 — обзор документа",
                 "CUI_SSP_v1.2 — Ελληνική μετάφραση"]


@pytest.mark.parametrize("line", R4_FURTHER_BAD)
def test_12b_r4_what_follows_a_further_citation_is_judged(tmp_path, line):
    _judged_everywhere(tmp_path, line)


@pytest.mark.parametrize("line", R4_FURTHER_OK)
def test_12b_r4_further_citations_and_ordinary_tails_pass(tmp_path, line):
    _passes_everywhere(tmp_path, line)


def test_12b_r4_non_latin_prose_still_passes(tmp_path):
    """The fold reads lookalike letters as Latin; ordinary Cyrillic and Greek text is still no banner."""
    for line in ("Руководство по СИ",
                 "Ελληνικά κείμενο",
                 "СУД и СИЗ"):
        _passes_everywhere(tmp_path, line)
        f = tmp_path / "FCI_H_v1.0.md"
        f.write_text(f"FCI\n\n{line}\n\nBody\n\nFCI\n", encoding="utf-8")
        assert M.check(f, True, NO_VALUES).ok, line


def test_12b_r4_many_citations_in_a_header_line_check_quickly():
    import time
    for unit in ("CUI_", "CUI_a", "CUI_SSP_v1.2 ", "CUI_SSP_v1.2, ", "CUI_x_v", "C U I "):
        line = "CUI_SSP_v1.2 " + unit * (100000 // len(unit))
        t = time.monotonic()
        M._looks_like(line, "cui", True)
        assert time.monotonic() - t < 2, (unit, time.monotonic() - t)


# ---------- Task 13a (12b minor): a lower-case or split SP- category marking after a cited name ----------

@pytest.mark.parametrize("line", ["CUI_SSP_v1.2 sp-propin", "CUI_SSP_v1.2 Sp-Propin", "CUI_SSP_v1.2 sp - propin",
                                  "CUI_SSP_v1.2 see sp-noforn", "CUI_SSP_v1.2 (sp-propin)"])
def test_13a_lower_case_or_split_sp_category_after_a_citation_is_judged(tmp_path, line):
    _judged_everywhere(tmp_path, line)


@pytest.mark.parametrize("line", ["CUI_SSP_v1.2 crisp-looking tables", "CUI_SSP_v1.2 wasp-nest notes"])
def test_13a_sp_inside_a_word_after_a_citation_passes(tmp_path, line):
    _passes_everywhere(tmp_path, line)
