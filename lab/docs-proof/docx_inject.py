"""docx_inject.py (lab/docs-proof, Plan 3 round 3; on a workstation, python3 -I - FILE CASE): make one B1/B2 test
docx from a marked template copy, in place. Cases:
  hidden-cui     a paragraph of one hidden run "CUI" (w:vanish) at the end of word/header1.xml (B1)
  textbox-cui    a text box (w:txbxContent) holding "CUI" in word/header1.xml (B1)
  sect-in-table  a w:sectPr inside a paragraph in a table cell in the body (B2)
  sect-deleted   a section break on a tracked-deleted paragraph mark (B2, refused in every mode)
Prints what it changed. Keeps the zip order."""
import io
import re
import sys
import zipfile

f, case = sys.argv[1], sys.argv[2]
SECT = "<w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/></w:sectPr>"


def header(s):
    if case == "hidden-cui":
        return s.replace("</w:hdr>", '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>CUI</w:t></w:r></w:p></w:hdr>', 1)
    if case == "textbox-cui":
        box = ('<w:r><w:pict><v:shape xmlns:v="urn:schemas-microsoft-com:vml" style="width:60pt;height:20pt">'
               '<v:textbox><w:txbxContent><w:p><w:r><w:t>CUI</w:t></w:r></w:p></w:txbxContent></v:textbox>'
               '</v:shape></w:pict></w:r>')
        return re.sub(r"(<w:p\b[^>]*>.*?)(</w:p>)", lambda m: m.group(1) + box + m.group(2), s, count=1, flags=re.S)
    return s


def body(s):
    i = s.rfind("<w:sectPr")
    if case == "sect-in-table":
        t = (f"<w:tbl><w:tr><w:tc><w:p><w:pPr>{SECT}</w:pPr><w:r><w:t>cell</w:t></w:r></w:p></w:tc></w:tr></w:tbl>"
             "<w:p/>")
        return s[:i] + t + s[i:]
    if case == "sect-deleted":
        p = (f'<w:p><w:pPr><w:rPr><w:del w:id="9001" w:author="lab" w:date="2026-11-23T00:00:00Z"/></w:rPr>{SECT}'
             '</w:pPr><w:r><w:t>deleted break</w:t></w:r></w:p>')
        return s[:i] + p + s[i:]
    return s


zin = zipfile.ZipFile(f); buf = io.BytesIO(); zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
for it in zin.infolist():
    d = zin.read(it.filename)
    if it.filename == "word/header1.xml":
        d = header(d.decode()).encode()
    elif it.filename == "word/document.xml":
        d = body(d.decode()).encode()
    zout.writestr(it, d)
zout.close(); open(f, "wb").write(buf.getvalue()); print("injected", case, "into", f)
