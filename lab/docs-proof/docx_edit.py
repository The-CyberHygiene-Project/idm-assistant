"""docx_edit.py (lab/docs-proof, Plan 3 11c; on a workstation, python3 -I - FILE TEXT [--strip-marks]): the lab
stand-in for an author editing in ONLYOFFICE (no display in the lab VMs): adds one body paragraph TEXT before the
final section properties of word/document.xml. --strip-marks also blanks every header/footer part and the CUI
designation block text in the body (to make a file with MISSING marks). Keeps the zip order."""
import re, sys, zipfile, io
f, text = sys.argv[1], sys.argv[2]
strip = "--strip-marks" in sys.argv
zin = zipfile.ZipFile(f); buf = io.BytesIO(); zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
for it in zin.infolist():
    d = zin.read(it.filename)
    if it.filename == "word/document.xml":
        s = d.decode()
        i = s.rfind("<w:sectPr")
        s = s[:i] + f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>" + s[i:]
        if strip:
            s = re.sub(r"(<w:t[^>]*>)[^<]*(CUI|Controlled by|Category|POC)[^<]*(</w:t>)", r"\1\3", s)
        d = s.encode()
    elif strip and re.match(r"word/(header|footer)\d*\.xml", it.filename):
        d = re.sub(rb"(<w:t[^>]*>)[^<]*(</w:t>)", rb"\1\2", d)
    zout.writestr(it, d)
zout.close(); open(f, "wb").write(buf.getvalue()); print("edited", f)
