"""Make the marking-checker test fixtures (Plan 3 Task 5). Stdlib only, deterministic (fixed zip dates), made-up
values only: no real CUI and no site values. Usage: python3 -I make.py [OUTDIR] (default: this folder).

The ONLYOFFICE-saved samples are not made here: the tests read them from lab/docs-spike/editor/out/ (saved by
ONLYOFFICE 10.0.0.169 in the editor spike, made-up content)."""
import sys
import zipfile
from pathlib import Path

# the made-up marking values (the same as the editor spike's samples, so those pass with them)
CONTROLLED_BY = "Example Office (made-up)"
CATEGORY = "PROPIN (made-up)"
POC = "A. Example, 555-0100 (made-up)"
BLOCK = [f"Controlled by: {CONTROLLED_BY}", f"CUI Category: {CATEGORY}", f"POC: {POC}"]

DATE = (2026, 1, 1, 0, 0, 0)
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PR = "http://schemas.openxmlformats.org/package/2006/relationships"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
OD = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
WNS = (f'xmlns:w="{W}" xmlns:r="{R}" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
       'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" '
       'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
       'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:v="urn:schemas-microsoft-com:vml" '
       'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" mc:Ignorable="w14"')


def _zip(members):
    import io
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in members:
            zi = zipfile.ZipInfo(name, DATE)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data.encode() if isinstance(data, str) else data)
    return b.getvalue()


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def p(text, center=False):
    jc = '<w:pPr><w:jc w:val="center"/></w:pPr>' if center else ""
    return f'<w:p>{jc}<w:r><w:t xml:space="preserve">{esc(text)}</w:t></w:r></w:p>'


def textbox(text):
    """A shape holding a text box (DrawingML with a VML fallback), as editors write a 'banner' drawn in a shape."""
    inner = f"<w:txbxContent>{p(text, True)}</w:txbxContent>"
    return ('<w:p><w:r><mc:AlternateContent><mc:Choice Requires="wps"><w:drawing><wp:anchor>'
            '<a:graphic><a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">'
            f'<wps:wsp><wps:txbx>{inner}</wps:txbx></wps:wsp></a:graphicData></a:graphic></wp:anchor></w:drawing>'
            f'</mc:Choice><mc:Fallback><w:pict><v:rect><v:textbox>{inner}</v:textbox></v:rect></w:pict>'
            '</mc:Fallback></mc:AlternateContent></w:r></w:p>')


def docx(body, parts=(), refs=(), even=False, title_pg=False, styles=None):
    """body: paragraph XML; parts: [(kind 'hdr'|'ftr', file name, inner XML)]; refs: [(kind, type, file name)];
    styles: the inner XML of word/styles.xml (None: no styles part)."""
    ct = [f'<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.'
          'wordprocessingml.document.main+xml"/>',
          '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.'
          'wordprocessingml.settings+xml"/>']
    rels = [f'<Relationship Id="rId1" Type="{OD}settings" Target="settings.xml"/>']
    members, rid = [], {}
    for i, (kind, fname, inner) in enumerate(parts, 2):
        what = "header" if kind == "hdr" else "footer"
        ct.append(f'<Override PartName="/word/{fname}" ContentType="application/vnd.openxmlformats-officedocument.'
                  f'wordprocessingml.{what}+xml"/>')
        rels.append(f'<Relationship Id="rId{i}" Type="{OD}{what}" Target="{fname}"/>')
        rid[fname] = f"rId{i}"
        members.append((f"word/{fname}", f"{XML}<w:{kind} {WNS}>{inner}</w:{kind}>"))
    if styles is not None:
        ct.append('<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.'
                  'wordprocessingml.styles+xml"/>')
        rels.append(f'<Relationship Id="rId99" Type="{OD}styles" Target="styles.xml"/>')
        members.append(("word/styles.xml", f"{XML}<w:styles {WNS}>{styles}</w:styles>"))
    sect = "".join(f'<w:{"headerReference" if k == "hdr" else "footerReference"} w:type="{t}" r:id="{rid[f]}"/>'
                   for k, t, f in refs)
    sect += ('<w:titlePg/>' if title_pg else "") + '<w:pgSz w:w="12240" w:h="15840"/>'
    settings = f'{XML}<w:settings {WNS}>' + ('<w:evenAndOddHeaders/>' if even else "") + '</w:settings>'
    return _zip([
        ("[Content_Types].xml", f'{XML}<Types xmlns="{CT}"><Default Extension="rels" ContentType="application/'
                                'vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" '
                                f'ContentType="application/xml"/>{"".join(ct)}</Types>'),
        ("_rels/.rels", f'{XML}<Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{OD}officeDocument" '
                        'Target="word/document.xml"/></Relationships>'),
        ("word/document.xml", f'{XML}<w:document {WNS}><w:body>{body}<w:sectPr>{sect}</w:sectPr></w:body>'
                              '</w:document>'),
        ("word/_rels/document.xml.rels", f'{XML}<Relationships xmlns="{PR}">{"".join(rels)}</Relationships>'),
        ("word/settings.xml", settings),
    ] + members)


BANNER_HDR = ("hdr", "header1.xml", p("CUI", True))
BANNER_FTR = ("ftr", "footer1.xml", p("CUI", True) + p("Page 1"))
BLOCK_XML = "".join(p(x) for x in BLOCK)
FILLER = "".join(p(f"Paragraph {i}. Made-up filler text for the test document.") for i in range(1, 6))
REFS = [("hdr", "default", "header1.xml"), ("ftr", "default", "footer1.xml")]


def sheet(rows, hf=None):
    """rows: [[cell text]] as inline strings; hf: dict of headerFooter children (raw codes) + attributes."""
    out = []
    for r, row in enumerate(rows, 1):
        cells = "".join(f'<c r="{chr(65 + c)}{r}" t="inlineStr"><is><t>{esc(v)}</t></is></c>'
                        for c, v in enumerate(row))
        out.append(f'<row r="{r}">{cells}</row>')
    x = f'{XML}<worksheet xmlns="{S}" xmlns:r="{R}"><sheetData>{"".join(out)}</sheetData>'
    x += '<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>'
    if hf is not None:
        attrs = "".join(f' {k}="{v}"' for k, v in hf.items() if k[0].islower() and k.startswith("different"))
        kids = "".join(f"<{k}>{esc(v)}</{k}>" for k, v in hf.items() if not k.startswith("different"))
        x += f"<headerFooter{attrs}>{kids}</headerFooter>"
    return x + "</worksheet>"


def xlsx(sheets):
    """sheets: [(name, sheet XML)]."""
    ct = ['<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.'
          'spreadsheetml.sheet.main+xml"/>']
    rels, entries, members = [], [], []
    for i, (name, x) in enumerate(sheets, 1):
        ct.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-'
                  'officedocument.spreadsheetml.worksheet+xml"/>')
        rels.append(f'<Relationship Id="rId{i}" Type="{OD}worksheet" Target="worksheets/sheet{i}.xml"/>')
        entries.append(f'<sheet name="{esc(name)}" sheetId="{i}" r:id="rId{i}"/>')
        members.append((f"xl/worksheets/sheet{i}.xml", x))
    return _zip([
        ("[Content_Types].xml", f'{XML}<Types xmlns="{CT}"><Default Extension="rels" ContentType="application/'
                                'vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" '
                                f'ContentType="application/xml"/>{"".join(ct)}</Types>'),
        ("_rels/.rels", f'{XML}<Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{OD}officeDocument" '
                        'Target="xl/workbook.xml"/></Relationships>'),
        ("xl/workbook.xml", f'{XML}<workbook xmlns="{S}" xmlns:r="{R}"><sheets>{"".join(entries)}</sheets>'
                            '</workbook>'),
        ("xl/_rels/workbook.xml.rels", f'{XML}<Relationships xmlns="{PR}">{"".join(rels)}</Relationships>'),
    ] + members)


HF = {"oddHeader": "&CCUI", "oddFooter": "&CCUI&RPage &P"}
# owner decision 2026-11-20: an FCI_ document carries the banner "FCI" (top and bottom), and no CUI designation block
FCI_HDR = ("hdr", "header1.xml", p("FCI", True))
FCI_FTR = ("ftr", "footer1.xml", p("FCI", True) + p("Page 1"))
FCI_HF = {"oddHeader": "&CFCI", "oddFooter": "&CFCI&RPage &P"}


def pdf(pages):
    """A minimal PDF, one text line per entry, top to bottom (Helvetica), for pdftotext."""
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for lines in pages:
        y, ops = 760, []
        for i, line in enumerate(lines):
            if i == len(lines) - 1:
                y = 40                               # the last line sits at the bottom of the page
            t = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            ops.append(f"BT /F1 11 Tf 72 {y} Td ({t}) Tj ET")
            y -= 18
        stream = "\n".join(ops).encode("latin-1")
        objs.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> "
                    f"/Contents {len(objs)} 0 R >>")
        kids.append(f"{len(objs)} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + (o if isinstance(o, bytes) else o.encode()) + b"\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    return bytes(out)


def md(lines):
    return ("\n".join(lines) + "\n").encode()


def build():
    f = {}
    f["CUI_Access-Policy_v1.0.docx"] = docx(BLOCK_XML + FILLER, [BANNER_HDR, BANNER_FTR], REFS)
    f["CUI_Missing-Footer_v1.0.docx"] = docx(BLOCK_XML + FILLER, [BANNER_HDR, ("ftr", "footer1.xml", p("Page 1"))],
                                             REFS)
    f["CUI_Textbox-Banner_v1.0.docx"] = docx(BLOCK_XML + FILLER, [("hdr", "header1.xml", textbox("CUI")),
                                                                  ("ftr", "footer1.xml", textbox("CUI"))], REFS)
    f["CUI_Even-Pages_v1.0.docx"] = docx(BLOCK_XML + FILLER, [BANNER_HDR, BANNER_FTR,
                                                              ("hdr", "header2.xml", p("Even page")),
                                                              ("ftr", "footer2.xml", p("CUI", True))],
                                         REFS + [("hdr", "even", "header2.xml"), ("ftr", "even", "footer2.xml")],
                                         even=True)
    f["CUI_Title-Page_v1.0.docx"] = docx(BLOCK_XML + FILLER, [BANNER_HDR, BANNER_FTR], REFS, title_pg=True)
    f["CUI_Runbook_v1.0.docx"] = docx(
        BLOCK_XML + p("This runbook follows CUI_SSP_v1.0 and CUI_IR-Plan_v2.0 (made-up names).")
        + p("It replaces CUI_Runbook_v0.9.") + textbox("See also CUI_Access-Policy_v0.3."),
        [BANNER_HDR, BANNER_FTR], REFS)
    f["CUI_Plan_v0.1-DRAFT.docx"] = docx(FILLER)
    f["CUI_Plan_v1.0.docx"] = docx(FILLER)
    f["Access-Policy_v1.0.docx"] = docx(p("Internal policy (made-up), not CUI.") + FILLER)

    f["CUI_Inventory_v1.0.xlsx"] = xlsx([("Items", sheet([[x] for x in BLOCK] + [[], ["Item", "Qty"], ["A", "1"]],
                                                         HF)),
                                         ("Totals", sheet([["Total", "1"]], HF))])
    f["CUI_First-Sheet-Only_v1.0.xlsx"] = xlsx([("Items", sheet([[x] for x in BLOCK] + [["Item", "Qty"]], HF)),
                                                ("Totals", sheet([["Total", "1"]]))])
    f["CUI_Data_v0.1-DRAFT.xlsx"] = xlsx([("Items", sheet([["Item", "Qty"], ["A", "1"]],
                                                          {"oddHeader": "&LInternal list"})),
                                          ("Totals", sheet([["Total", "1"]]))])

    f["CUI_Procedure_v1.0.md"] = md(["CUI", ""] + [x for b in BLOCK for x in (b, "")]
                                    + ["# Procedure (made-up)", "", "Step one.", "", "CUI"])
    f["CUI_No-Last-Banner_v1.0.md"] = md(["CUI", ""] + [x for b in BLOCK for x in (b, "")]
                                         + ["# Procedure (made-up)", "", "Step one."])
    f["CUI_Notes_v0.1-DRAFT.md"] = md(["# Notes (made-up)", "", "Cites CUI_SSP_v1.0."])

    f["CUI_Report_v1.0.pdf"] = pdf([["CUI"] + BLOCK + ["Report text (made-up).", "CUI"],
                                    ["CUI", "Page two text.", "CUI"],
                                    ["CUI", "Last page text.", "CUI"]])
    f["CUI_Report-Bad_v1.0.pdf"] = pdf([["CUI"] + BLOCK + ["Report text (made-up).", "CUI"],
                                        ["CUI", "Page two text.", "CUI"],
                                        ["CUI", "Last page text, no bottom banner.", "More text.", "More text.", "More text.",
                                         "End of report"]])

    f["FCI_Notice_v1.0.docx"] = docx(FILLER, [FCI_HDR, FCI_FTR], REFS)
    f["FCI_Plan_v0.1-DRAFT.docx"] = docx(FILLER)
    f["FCI_Quote_v1.0.xlsx"] = xlsx([("Items", sheet([["Item", "Qty"], ["A", "1"]], FCI_HF)),
                                     ("Totals", sheet([["Total", "1"]], FCI_HF))])
    f["FCI_Data_v0.1-DRAFT.xlsx"] = xlsx([("Items", sheet([["Item", "Qty"], ["A", "1"]],
                                                          {"oddHeader": "&LInternal list"})),
                                          ("Totals", sheet([["Total", "1"]]))])
    f["FCI_Notes_v1.0.md"] = md(["FCI", "", "# Notes (made-up)", "", "Step one.", "", "FCI"])
    f["FCI_Notes_v0.1-DRAFT.md"] = md(["# Notes (made-up)", "", "Step one."])
    f["FCI_Report_v1.0.pdf"] = pdf([["FCI", "Report text (made-up).", "FCI"], ["FCI", "Last page text.", "FCI"]])
    return f


def main(argv):
    out = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(build().items()):
        (out / name).write_bytes(data)
    print(f"wrote {len(build())} fixtures to {out}")


if __name__ == "__main__":
    main(sys.argv)
