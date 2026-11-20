"""doc.fill_template (Plan 3 Task 7 fix round 1, m1/m2): self-contained, no ~/chp-templates checkout needed. Inline
docx/xlsx packages in the 1.4.0 templates' shape; made-up values only."""
import zipfile
from io import BytesIO

import pytest

from chp_site import doc as DOC
from chp_site import marking as M

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PR = "http://schemas.openxmlformats.org/package/2006/relationships"
OX = "application/vnd.openxmlformats-officedocument."
XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
BLOCK = ["Controlled by: {{CUI_CONTROLLED_BY}}", "CUI Category: {{CUI_CATEGORY}}", "POC: {{CUI_POC}}"]
VALUES = M.MarkValues(controlled_by='R&D <Office> "West" (made-up)', category="PROPIN (made-up)",
                      poc="A. Example & B. Example, 555-0100 (made-up)")


def pkg(members):
    b = BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in members:
            zi = zipfile.ZipInfo(n, (1980, 1, 1, 0, 0, 0))
            z.writestr(zi, d)
    return b.getvalue()


def types(over):
    return (f'{XML}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            + "".join(f'<Override PartName="{p}" ContentType="{c}"/>' for p, c in over) + "</Types>")


def rels(items):
    return (f'{XML}<Relationships xmlns="{PR}">'
            + "".join(f'<Relationship Id="{i}" Type="{R}/{t}" Target="{g}"/>' for i, t, g in items) + "</Relationships>")


def p(t):
    return f'<w:p><w:r><w:t xml:space="preserve">{t}</w:t></w:r></w:p>'


def docx(block=BLOCK):
    hdr = f'{XML}<w:hdr xmlns:w="{W}">{p("CUI")}</w:hdr>'
    ftr = f'{XML}<w:ftr xmlns:w="{W}">{p("CUI")}</w:ftr>'
    ftr1 = f'{XML}<w:ftr xmlns:w="{W}">{"".join(p(x) for x in block)}{p("CUI")}</w:ftr>'
    refs = [("header", "default", "rId1", "header1.xml"), ("header", "first", "rId2", "header2.xml"),
            ("footer", "default", "rId3", "footer1.xml"), ("footer", "first", "rId4", "footer2.xml")]
    sect = "<w:sectPr>" + "".join(f'<w:{k}Reference w:type="{t}" r:id="{i}"/>' for k, t, i, _ in refs) + \
        "<w:titlePg/></w:sectPr>"
    doc = f'{XML}<w:document xmlns:w="{W}" xmlns:r="{R}"><w:body>{p("Title")}{sect}</w:body></w:document>'
    return pkg([("[Content_Types].xml", types([("/word/document.xml", OX + "wordprocessingml.document.main+xml")]
                                              + [(f"/word/{f}", OX + f"wordprocessingml.{k}+xml") for k, _, _, f in refs])),
                ("_rels/.rels", rels([("rId1", "officeDocument", "word/document.xml")])),
                ("word/document.xml", doc),
                ("word/_rels/document.xml.rels", rels([(i, k, f) for k, _, i, f in refs])),
                ("word/header1.xml", hdr), ("word/header2.xml", hdr), ("word/footer1.xml", ftr),
                ("word/footer2.xml", ftr1)])


def xlsx(block=BLOCK):
    cells = "".join(f'<row r="{n}"><c r="A{n}" t="inlineStr"><is><t>{x}</t></is></c></row>'
                    for n, x in enumerate(block, 1))
    sheet = (f'{XML}<worksheet xmlns="{S}"><sheetData>{cells}</sheetData><headerFooter><oddHeader>&amp;CCUI'
             '</oddHeader><oddFooter>&amp;CCUI</oddFooter></headerFooter></worksheet>')
    wb = f'{XML}<workbook xmlns="{S}" xmlns:r="{R}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    return pkg([("[Content_Types].xml", types([("/xl/workbook.xml", OX + "spreadsheetml.sheet.main+xml"),
                                               ("/xl/worksheets/sheet1.xml", OX + "spreadsheetml.worksheet+xml")])),
                ("_rels/.rels", rels([("rId1", "officeDocument", "xl/workbook.xml")])),
                ("xl/workbook.xml", wb), ("xl/_rels/workbook.xml.rels", rels([("rId1", "worksheet", "worksheets/sheet1.xml")])),
                ("xl/worksheets/sheet1.xml", sheet)])


MD = ("CUI\n\n" + "\n\n".join(BLOCK) + "\n\n# Title\n\nCUI\n").encode()


@pytest.mark.parametrize("ext,make", [("docx", docx), ("xlsx", xlsx), ("md", lambda: MD)])
def test_fill_escapes_and_passes_the_checker(tmp_path, ext, make):
    out = DOC.fill_template(make(), ext, VALUES)
    f = tmp_path / f"CUI_Plan_v0.1-DRAFT.{ext}"
    f.write_bytes(out)
    rep = M.check(f, True, VALUES)
    assert rep.ok, rep.problems
    if ext == "md":
        assert b'Controlled by: R&D <Office> "West" (made-up)' in out
    else:
        z = zipfile.ZipFile(BytesIO(out))
        allx = b"".join(z.read(n) for n in z.namelist())
        assert b"R&amp;D &lt;Office&gt; &quot;West&quot;" in allx and b"A. Example &amp; B. Example" in allx
        assert b"{{" not in allx
    assert DOC.fill_template(make(), ext, VALUES) == out                  # deterministic


@pytest.mark.parametrize("ext,make", [("docx", docx), ("xlsx", xlsx), ("md", lambda: MD)])
def test_a_value_holding_a_placeholder_is_not_expanded_or_refused(ext, make):
    v = M.MarkValues(controlled_by="Office {{CUI_POC}} {{CUI_OTHER}} (made-up)", category="X (made-up)",
                     poc="P (made-up)")
    out = DOC.fill_template(make(), ext, v)
    text = out if ext == "md" else b"".join(zipfile.ZipFile(BytesIO(out)).read(n)
                                             for n in zipfile.ZipFile(BytesIO(out)).namelist())
    assert b"Controlled by: Office {{CUI_POC}} {{CUI_OTHER}} (made-up)" in text      # literal: one pass only
    assert b"POC: P (made-up)" in text


@pytest.mark.parametrize("ext,make", [("docx", docx), ("xlsx", xlsx), ("md", None)])
def test_an_unknown_placeholder_in_the_template_is_refused(ext, make):
    blk = BLOCK + ["Owner: {{CUI_OWNER}}"]
    data = (("CUI\n\n" + "\n\n".join(blk) + "\n\nCUI\n").encode() if make is None else make(blk))
    with pytest.raises(DOC.DocError, match="CUI_OWNER"):
        DOC.fill_template(data, ext, VALUES)
