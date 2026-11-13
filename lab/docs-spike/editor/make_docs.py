"""Make the Task 3 test documents (made-up content; no real CUI). Usage: python3 -I make_docs.py OUTDIR"""
import sys, os
from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt
import openpyxl

out = sys.argv[1]; os.makedirs(out, exist_ok=True)
BANNER = "CUI"
BLOCK = ["Controlled by: Example Office (made-up)", "CUI Category: PROPIN (made-up)",
         "Distribution/Dissemination Control: FEDCON", "POC: A. Example, 555-0100 (made-up)"]

d = Document()
sec = d.sections[0]
st = d.settings.element
st.append(OxmlElement("w:evenAndOddHeaders"))
for hf, kind in ((sec.header, "odd"), (sec.footer, "odd")):
    hf.paragraphs[0].text = BANNER + " (odd)"; hf.paragraphs[0].alignment = 1
for hf in (sec.even_page_header, sec.even_page_footer):
    hf.is_linked_to_previous = False
    hf.paragraphs[0].text = BANNER + " (even)"; hf.paragraphs[0].alignment = 1
p = sec.footer.add_paragraph("Page ")
for t, txt in (("begin", None), (None, "PAGE"), ("end", None)):
    r = p.add_run()
    if t: e = OxmlElement("w:fldChar"); e.set(qn("w:fldCharType"), t)
    else: e = OxmlElement("w:instrText"); e.text = txt
    r._r.append(e)
d.add_heading("Test Report (made-up content)", 1)
for l in BLOCK: d.add_paragraph(l)
for i in range(1, 121):
    d.add_paragraph(f"Paragraph {i}. The quick brown fox jumps over the lazy dog; this sentence is filler to make pages.")
d.save(f"{out}/CUI_test-report_v0.1-DRAFT.docx")

wb = openpyxl.Workbook(); ws = wb.active; ws.title = "Data"
for i, l in enumerate(BLOCK, 1): ws.cell(i, 1, l)
ws.cell(6, 1, "Item"); ws.cell(6, 2, "Qty"); ws.cell(6, 3, "Total")
for r in range(7, 207):
    ws.cell(r, 1, f"Item {r-6}"); ws.cell(r, 2, r % 7 + 1); ws.cell(r, 3, f"=B{r}*10")
ws.oddHeader.center.text = BANNER; ws.evenHeader.center.text = BANNER
ws.oddFooter.center.text = BANNER; ws.evenFooter.center.text = BANNER
ws.HeaderFooter.differentOddEven = True
ws.print_title_rows = "6:6"
wb.save(f"{out}/CUI_test-data_v0.1-DRAFT.xlsx")
