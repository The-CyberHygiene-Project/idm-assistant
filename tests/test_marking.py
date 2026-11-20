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
