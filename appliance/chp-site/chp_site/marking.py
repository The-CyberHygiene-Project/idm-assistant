# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The CUI and FCI marking checker and inserter for controlled documents (ISO 0.7.0 Plan 3, spec §5). It runs on the
workstation (`chp-site doc check|mark`) and again on the server at publish (doc_ledger), so both ends judge a file
with the same code, including the name rule (parse_name).

Name rule: <CUI_|FCI_><title>_vX.Y[-DRAFT].<ext> in the CUI area, <title>_vX.Y[-DRAFT].<ext> in the non-CUI area.
  - The name is normalised to NFC first, so NFD and NFC spellings parse the same.
  - The version is the `_vX.Y` at the end (before -DRAFT and the extension); X and Y are 0-9999, no leading zeros.
  - A title that itself holds `_v<digit>` (any case) is refused as ambiguous, so a citation `<prefix><title>_vX.Y`
    always has one reading. Title characters: letters, digits (any script), combining marks, `-` and `_`; it starts
    with a letter or digit. No spaces, no dots, no paths; 200 characters at most. The prefix is CUI_ or FCI_ in
    capitals; `-DRAFT` in capitals.

Which marks (owner decision 2026-11-20, "FCI should be marked as FCI"): the target area and the name's prefix
(parse_name) decide; nothing else is trusted.
  - CUI area, CUI_ name (or a name that does not parse: the strictest reading): the CUI banner and the designation
    block;
  - CUI area, FCI_ name: the FCI banner (a line that reads exactly `FCI`), in the same places and with the same
    defences as the CUI banner, and NO designation block (a `CUI Category:` line on page one is a problem); the CUI
    marking site keys are not needed;
  - non-CUI area: no banner.
  The other banner is a problem wherever a banner is looked for: a CUI banner on an FCI_ document, an FCI banner on
  a CUI_ document, either one in the non-CUI area. That search folds lookalikes (fullwidth and compatibility forms,
  Cyrillic/Greek letters, case), so a wrong banner cannot hide behind other letters; the banner that is required
  must be the exact ASCII text.

Marks (when the target is the CUI area; spec §4: the CUI banner applies in the CUI and FCI folders):
  - banner: a line that reads `CUI` (or `CUI//<category markings>`; for an FCI_ document exactly `FCI`), checked on
    top and bottom of every page:
      docx: a paragraph in the header and the footer part in effect for every section and page kind (default; first
            when the section has a title page; even when the document has even/odd headers). Text in a text box,
            shape or drawing, hidden text and deleted text do not count;
      xlsx: a line of the header and the footer (odd; even and first when switched on) of every sheet;
      md:   the first line and the last non-blank line;
      pdf:  the first two and the last three text lines of the first and the last page (pdftotext).
  - designation block (page one), one line each, from the site keys (never typed per file):
      `Controlled by: <CUI_CONTROLLED_BY>`, `CUI Category: <CUI_CATEGORY>`, `POC: <CUI_POC>`;
      docx: in the body before the first page break (first 60 paragraphs), or in the header/footer of page one;
      xlsx: in rows 1-20 of the first visible sheet, or in its page-one header/footer;
      md:   the lines after the first banner (blank lines between them allowed);
      pdf:  anywhere in the text of page one.
  - In the non-CUI area a CUI or FCI banner is itself a problem (CUI and FCI do not belong there).

Insert (only into a -DRAFT file with a CUI_/FCI_ name, before approval; dry run by default): adds what is missing
(a CUI_ file: the CUI banner and the designation block; an FCI_ file: the FCI banner only; insert never removes a
mark, so a draft that carries the other banner is refused),
with byte-level edits that leave every other part as it was, checks the result, and writes it atomically. The same
input and values always give the same bytes (the approved hash covers the marked file). PDFs are never marked in
place (a reader PDF is derived from the approved source).

Citation check (my call on the spec's "builder: how far to automate"): with `current` (series -> the current version
in the Compliance area), every `<prefix><title>_vX.Y` in the text older than the current version is listed in
Report.warnings; it never changes `ok`. Citations inside PDFs are not checked (the source document is).

Defensive: documents come from users. Size caps on the file, the members and the total uncompressed size; a part
named twice (any case) is refused; XML with a DTD is refused (no entity expansion); anything malformed is a plain
problem, never a traceback."""
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import List, Optional

BANNER = "CUI"
FCI_BANNER = "FCI"
_BANNER_RE = re.compile(r"CUI(?://[A-Z0-9][A-Z0-9 ,/-]*)?")
_FCI_RE = re.compile(r"FCI")
# kind -> (the banner text, the exact pattern a required banner must match, the folded pattern a banner that must
# not be there is found by: lookalikes, compatibility forms and case folded, with or without //<markings> after it)
_KINDS = {"cui": (BANNER, _BANNER_RE, re.compile(r"cui(?:\s*//.*)?")),
          "fci": (FCI_BANNER, _FCI_RE, re.compile(r"fci(?:\s*//.*)?"))}
_ART = {"cui": "a CUI", "fci": "an FCI"}
RULE = "<CUI_|FCI_><title>_vX.Y[-DRAFT].<ext> in the CUI area, <title>_vX.Y[-DRAFT].<ext> in the non-CUI area"
FORMATS = {"docx": "docx", "xlsx": "xlsx", "md": "md", "pdf": "pdf"}
LABELS = (("CUI_CONTROLLED_BY", "controlled_by", "Controlled by"), ("CUI_CATEGORY", "category", "CUI Category"),
          ("CUI_POC", "poc", "POC"))

MAX_FILE = 64 << 20               # the publish cap (Task 3)
MAX_MEMBERS = 2000
MAX_UNCOMPRESSED = 256 << 20
MAX_PDF_TEXT = 4 << 20            # per page of pdftotext output
PDF_TIMEOUT = 60
BLOCK_PARAS = 60                  # docx: page one is at most this many body paragraphs before a break
BLOCK_ROWS = 20                   # xlsx: page one rows searched for the block

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
W_NS = W[1:-1]
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PR = "{http://schemas.openxmlformats.org/package/2006/relationships}"
MC = "{http://schemas.openxmlformats.org/markup-compatibility/2006}"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
# subtrees whose text is not "in the header/footer/body" as a page mark: text boxes, shapes, drawings, VML, objects,
# alternate content, deleted and moved-away text
_SKIP = {W + "txbxContent", W + "pict", W + "drawing", W + "object", MC + "AlternateContent", W + "del",
         W + "moveFrom"}


class NameRuleError(ValueError):
    """The name does not follow the name rule; the message starts with 'name rule:' and states the rule."""


class MarkingError(ValueError):
    """insert refused (plain message; nothing was changed)."""


class _Bad(Exception):
    """The file cannot be read as its format (reported as a problem)."""


# ---------- names ----------

@dataclass(frozen=True)
class NameParts:
    prefix: str          # "CUI_", "FCI_" or ""
    title: str
    version: str         # "X.Y"
    draft: bool
    ext: str = ""        # without the dot, as written

    @property
    def series(self):
        return self.prefix + self.title

    @property
    def version_tuple(self):
        return tuple(int(x) for x in self.version.split("."))


_NAME = re.compile(r"(?P<stem>.+)_v(?P<ver>(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3}))(?P<draft>-DRAFT)?"
                   r"\.(?P<ext>[A-Za-z0-9]{1,10})")


def parse_name(name) -> NameParts:
    if not isinstance(name, str):
        raise NameRuleError(f"name rule: the name is not text; the rule is {RULE}")
    n = unicodedata.normalize("NFC", name)

    def bad(why):
        raise NameRuleError(f"name rule: {n!r}: {why}; the rule is {RULE}")

    if not n:
        bad("the name is empty")
    if len(n) > 200:
        bad("the name is too long (200 characters at most)")
    if "/" in n or "\\" in n or "\0" in n:
        bad("give a file name, not a path")
    if any(c.isspace() for c in n):
        bad("no spaces (use - or _ between words)")
    m = _NAME.fullmatch(n)
    if not m:
        if re.search(r"-draft\.", n, re.I):
            bad("write -DRAFT in capitals, right after the version")
        bad("it must end in _vX.Y (for example _v1.0), then -DRAFT while in progress, then the extension "
            "(no leading zeros in X or Y)")
    stem = m["stem"]
    prefix = ""
    if stem.startswith(("CUI_", "FCI_")):
        prefix, stem = stem[:4], stem[4:]
    elif _fold(stem[:8]).startswith(("cui_", "fci_")):
        bad("the prefix is CUI_ or FCI_, in capitals and plain letters (not lower case, fullwidth or lookalike letters)")
    title = stem
    if not title:
        bad("the title is empty")
    if re.search(r"_[vV]\d", title):                     # \d is any script's digit on purpose: refuse lookalikes
        bad("the title has a second _v<number>; only the version at the end may look like _vX.Y")
    if re.search(r"-draft$", title, re.I):
        bad("-DRAFT goes after the version, not before it")
    if not title[0].isalnum():
        bad("the title starts with a letter or digit")
    for c in title:
        if not (c.isalnum() or c in "-_" or unicodedata.category(c).startswith("M")):
            bad(f"the title holds letters, digits, - and _ only (not {c!r})")
    return NameParts(prefix=prefix, title=title, version=m["ver"], draft=bool(m["draft"]), ext=m["ext"])


# Latin lookalikes from other scripts for the letters of the prefixes (NFKC does not fold these)
_LOOKALIKE = str.maketrans({"\u0421": "C", "\u0441": "c", "\u03f9": "C", "\u03f2": "c", "\u216d": "C",
                            "\u217d": "c", "\u0406": "I", "\u0456": "i", "\u0399": "I", "\u03b9": "i",
                            "\u04c0": "I", "\u2160": "I", "\u2170": "i", "\u0545": "U", "\u054d": "U",
                            "\u057d": "u", "\u03c5": "u", "\u0423": "U", "\u15c5": "F", "\u0191": "F",
                            "\u03dc": "F", "\u2131": "F"})


def _fold(s):
    """For the prefix test only: compatibility forms (fullwidth etc.), cross-script lookalikes and case folded."""
    return unicodedata.normalize("NFKC", s).translate(_LOOKALIKE).casefold()


def _series_key(s):
    return unicodedata.normalize("NFC", str(s)).casefold()


# ---------- marking values ----------

@dataclass(frozen=True)
class MarkValues:
    controlled_by: str = ""
    category: str = ""
    poc: str = ""

    @classmethod
    def from_site(cls, site=None, site_dir="/etc/chp"):
        """site: the parsed site.conf (sitefile.parse_site); without it, <site_dir>/site.conf is read and parsed.
        CUI_CONTROLLED_BY, CUI_CATEGORY and CUI_POC are optional site keys ("" when not set)."""
        if site is None:
            from .sitefile import parse_site, read_file
            site = parse_site(read_file(Path(site_dir) / "site.conf", "site.conf"))
        return cls(**{attr: str(site.get(key, "") or "").strip() for key, attr, _ in LABELS})

    def block(self):
        """(the block lines, the site keys that are not set)."""
        lines, missing = [], []
        for key, attr, label in LABELS:
            v = _norm(getattr(self, attr, "") or "")
            if v:
                lines.append(f"{label}: {v}")
            else:
                missing.append(key)
        return lines, missing


# ---------- the report ----------

@dataclass
class Report:
    ok: bool
    problems: List[str]
    name: Optional[NameParts]
    warnings: List[str] = field(default_factory=list)
    format: str = ""


def _norm(s):
    s = unicodedata.normalize("NFC", s)
    return " ".join(s.split())


def _is_banner(line, kind="cui"):
    return bool(_KINDS[kind][1].fullmatch(_norm(line)))


def _has_banner(lines, kind="cui"):
    return any(_is_banner(x, kind) for x in lines)


def _looks_like(line, kind):
    """The folded search for a banner that must NOT be there (see the module notes)."""
    return bool(_KINDS[kind][2].fullmatch(_fold(_norm(line)).strip()))


def _wrong(lines, mode):
    """The banner kinds among `lines` that do not belong to a document of this mode ('cui', 'fci' or 'none')."""
    return {k for k in _KINDS if k != mode and any(_looks_like(x, k) for x in lines)}


def _mode(cui, parts):
    """'none' (the non-CUI area), 'fci' (the CUI area, an FCI_ name) or 'cui' (the CUI area, any other name: the
    strictest reading when the name does not parse)."""
    if not cui:
        return "none"
    return "fci" if parts is not None and parts.prefix == "FCI_" else "cui"


def _wrong_problems(found, mode, where, problems):
    for k in sorted(found):
        if mode == "none":
            name = "a CUI_ or FCI_" if k == "cui" else "an FCI_"
            problems.append(f"{_ART[k]} banner is {where}, but this is the non-CUI area: {_ART[k]} document goes in "
                            f"the CUI area with {name} name")
        elif mode == "fci":
            problems.append(f"{_ART[k]} banner is {where}, but this is an FCI_ document: it carries the FCI banner "
                            "only (a document that holds CUI is named CUI_)")
        else:
            problems.append(f"{_ART[k]} banner is {where}, but this is a CUI_ document: it carries the CUI banner")


_CUI_BLOCK_LABEL = LABELS[1][2].casefold() + ":"         # "cui category:"


def _fci_block_problems(lines, where, problems):
    """An FCI_ document carries no CUI designation block: a `CUI Category:` line (lookalikes folded) is a problem."""
    if any(_fold(_norm(x)).startswith(_CUI_BLOCK_LABEL) for x in lines):
        problems.append(f"a CUI designation block (CUI Category) is on {where}, but this is an FCI_ document: an FCI "
                        "document carries no CUI designation block")


# ---------- containers ----------

class _Zip:
    """A capped, read-everything view of an OOXML package. Part names are matched case-insensitively (OPC)."""
    def __init__(self, data):
        try:
            zf = zipfile.ZipFile(BytesIO(data))
            infos = zf.infolist()
        except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError):
            raise _Bad("is not a valid Office file (not a zip package)") from None
        if len(infos) > MAX_MEMBERS:
            raise _Bad(f"has too many parts ({len(infos)}; at most {MAX_MEMBERS})")
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
            raise _Bad(f"is too large when unpacked (more than {MAX_UNCOMPRESSED >> 20} MiB)")
        self.infos, self.data, self.lower = [], {}, {}
        total = 0
        for i in infos:
            k = i.filename.casefold()
            if k in self.lower:
                raise _Bad(f"holds the part {i.filename} twice; refused (a reader could see one copy and the "
                           "editor the other)")
            if i.flag_bits & 0x1:
                raise _Bad("has an encrypted part; refused")
            try:
                with zf.open(i) as fh:
                    b = fh.read(min(i.file_size, MAX_UNCOMPRESSED) + 1)
            except (zipfile.BadZipFile, OSError, EOFError, ValueError, NotImplementedError, RuntimeError) as e:
                raise _Bad(f"has a damaged part {i.filename} ({type(e).__name__})") from None
            total += len(b)
            if len(b) > i.file_size or total > MAX_UNCOMPRESSED:
                raise _Bad(f"is too large when unpacked (more than {MAX_UNCOMPRESSED >> 20} MiB)")
            self.lower[k] = i.filename
            self.infos.append(i)
            self.data[i.filename] = b

    def has(self, name):
        return name is not None and name.casefold() in self.lower

    def real(self, name):
        return self.lower.get(name.casefold())

    def read(self, name):
        real = self.real(name)
        if real is None:
            raise _Bad(f"is missing its part {name}")
        return self.data[real]

    def xml(self, name):
        b = self.read(name)
        _utf8_xml(b, name)
        if re.search(rb"<!DOCTYPE", b, re.I) or re.search(rb"<!ENTITY", b, re.I):
            raise _Bad(f"part {name} has a DTD; refused (no entities in Office XML)")
        try:
            return ET.fromstring(b)
        except ET.ParseError as e:
            raise _Bad(f"part {name} is not valid XML ({e})") from None

    def rels(self, part):
        """{rId: (type tail, target part name or None for external)} for a part ('' = the package)."""
        d, base = posixpath.split(part)
        rp = posixpath.join(d, "_rels", base + ".rels")
        if not self.has(rp):
            return {}
        out = {}
        for r in self.xml(rp).iter(PR + "Relationship"):
            rid, typ, tgt = r.get("Id"), r.get("Type") or "", r.get("Target") or ""
            if not rid:
                continue
            if (r.get("TargetMode") or "").lower() == "external":
                out[rid] = (typ.rsplit("/", 1)[-1], None)
                continue
            t = tgt[1:] if tgt.startswith("/") else posixpath.join(d, tgt)
            t = posixpath.normpath(t)
            out[rid] = (typ.rsplit("/", 1)[-1], None if t.startswith("..") or t.startswith("/") else t)
        return out

    def main(self):
        for typ, tgt in self.rels("").values():
            if typ == "officeDocument" and tgt and self.has(tgt):
                return self.real(tgt)
        raise _Bad("has no main document part")


_DECL = re.compile(rb"<\?xml[^>]*?encoding\s*=\s*[\"']([^\"']*)[\"']")


def _utf8_xml(b, name):
    """Only UTF-8 XML is read (with or without a UTF-8 BOM, encoding absent or UTF-8): a UTF-16/32 part could hide
    a DTD from the byte search above, and Office writes UTF-8."""
    if b[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in b:
        raise _Bad(f"part {name} is not UTF-8 XML (UTF-16 or UTF-32); refused")
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        raise _Bad(f"part {name} is not UTF-8 XML; refused") from None
    m = _DECL.match(b[3:] if b.startswith(b"\xef\xbb\xbf") else b)
    if m and m.group(1).strip().lower() not in (b"utf-8", b"utf8"):
        raise _Bad(f"part {name} declares the encoding {m.group(1).decode('ascii', 'replace')!r}, not UTF-8; "
                   "refused")


def _on(el, attr=W + "val"):
    return el is not None and (el.get(attr) or "true").lower() not in ("false", "0", "off")


# ---------- docx ----------

def _vanish(rpr):
    """True/False when the run properties set hidden text explicitly, None when they do not say."""
    if rpr is None:
        return None
    for tag in ("vanish", "specVanish"):
        el = rpr.find(W + tag)
        if el is not None:
            if _on(el):
                return True
            return False if tag == "vanish" else None
    return None


class _Styles:
    """Hidden text through styles (styles.xml): a style is hidden when it or any style it is basedOn (at most 32
    deep, cycle-safe) sets vanish. Conservative: Word's toggle-property rules could un-hide in rare chains; here any
    hidden level hides, unless the run itself says vanish off (direct formatting wins)."""
    DEPTH = 32

    def __init__(self, root=None):
        self.by_id, self.default_p, self.default_r, self.docdef, self._memo = {}, None, None, False, {}
        if root is None:
            return
        for st in root.findall(W + "style"):
            sid = st.get(W + "styleId")
            if not sid:
                continue
            based = st.find(W + "basedOn")
            self.by_id[sid] = (based.get(W + "val") if based is not None else None,
                               _vanish(st.find(W + "rPr")) is True)
            if _on(st, W + "default") and st.get(W + "default") is not None:
                if st.get(W + "type") == "paragraph":
                    self.default_p = sid
                elif st.get(W + "type") == "character":
                    self.default_r = sid
        dd = root.find(W + "docDefaults")
        rd = dd.find(W + "rPrDefault") if dd is not None else None
        self.docdef = rd is not None and _vanish(rd.find(W + "rPr")) is True

    def hidden(self, sid):
        if not sid:
            return False
        if sid in self._memo:
            return self._memo[sid]
        seen, cur, out = set(), sid, False
        for _ in range(self.DEPTH):
            if cur is None or cur in seen or cur not in self.by_id:
                break
            seen.add(cur)
            based, hid = self.by_id[cur]
            if hid:
                out = True
                break
            cur = based
        self._memo[sid] = out
        return out

    def run_hidden(self, rpr, pstyle):
        direct = _vanish(rpr)
        if direct is not None:
            return direct
        rs = rpr.find(W + "rStyle") if rpr is not None else None
        return bool(self.docdef or self.hidden(rs.get(W + "val") if rs is not None else self.default_r)
                    or self.hidden(pstyle or self.default_p))


_NO_STYLES = _Styles()


def _p_lines(p, styles=None):
    styles = styles or _NO_STYLES
    buf = []
    ppr = p.find(W + "pPr")
    ps = ppr.find(W + "pStyle") if ppr is not None else None
    pstyle = ps.get(W + "val") if ps is not None else None

    def walk(e):
        for c in e:
            t = c.tag
            if t in _SKIP:
                continue
            if t == W + "r":
                if styles.run_hidden(c.find(W + "rPr"), pstyle):
                    continue
            if t == W + "t":
                buf.append(c.text or "")
            elif t == W + "tab":
                buf.append(" ")
            elif t in (W + "br", W + "cr"):
                buf.append("\n")
            walk(c)
    walk(p)
    return [_norm(x) for x in "".join(buf).split("\n")]


def _paras(e):
    """w:p elements in document order, outside text boxes, shapes and the other skipped subtrees."""
    for c in e:
        if c.tag in _SKIP:
            continue
        if c.tag == W + "p":
            yield c
        else:
            yield from _paras(c)


def _part_lines(root, styles=None):
    return [x for p in _paras(root) for x in _p_lines(p, styles) if x]


def _boxed_lines(root):
    """Lines inside text boxes (only to explain why a banner there does not count)."""
    out = []
    for tb in root.iter(W + "txbxContent"):
        for p in tb.iter(W + "p"):
            out += ["".join(t.text or "" for t in p.iter(W + "t"))]
    return out


class _Docx:
    def __init__(self, data):
        self.z = _Zip(data)
        self.main = self.z.main()
        self.doc = self.z.xml(self.main)
        self.body = self.doc.find(W + "body")
        if self.body is None:
            raise _Bad("is not a Word document (no body)")
        self.rels = self.z.rels(self.main)
        self.even = False
        self.styles = _NO_STYLES
        for typ, tgt in self.rels.values():
            if typ == "settings" and tgt and self.z.has(tgt):
                self.even = _on(self.z.xml(tgt).find(W + "evenAndOddHeaders"))
            elif typ == "styles" and tgt and self.z.has(tgt):
                self.styles = _Styles(self.z.xml(tgt))
        nested = set()
        for ch in self.doc.iter(W + "sectPrChange"):
            nested.update(id(x) for x in ch.iter(W + "sectPr"))
        self.all_sects = list(self.body.iter(W + "sectPr"))
        self.sects = [s for s in self.all_sects if id(s) not in nested]
        self._parts = {}

    def part(self, name):
        if name not in self._parts:
            self._parts[name] = self.z.xml(name)
        return self._parts[name]

    def plan(self):
        """Per section: [(kind, type, part name or None, the sectPr element or None)] for every header/footer the
        pages of that section show, following Word's inheritance from the section before."""
        carry, out = {}, []
        sects = self.sects or [None]
        for s in sects:
            if s is not None:
                for kind, tag in (("header", "headerReference"), ("footer", "footerReference")):
                    for ref in s.findall(W + tag):
                        typ = ref.get(W + "type") or "default"
                        rid = ref.get("{%s}id" % R_NS)
                        tgt = self.rels.get(rid, (None, None))[1]
                        carry[(kind, typ)] = tgt if tgt else ("?" + str(rid))
            types = ["default"]
            if s is not None and _on(s.find(W + "titlePg")):
                types.append("first")
            if self.even:
                types.append("even")
            out.append([(kind, typ, carry.get((kind, typ)), s) for kind in ("header", "footer") for typ in types])
        return out

    def page_one_parts(self):
        first = self.plan()[0]
        types = {t for _, t, _, _ in first}
        want = "first" if "first" in types else "default"
        return [p for k, t, p, _ in first if t == want and p and not p.startswith("?")]

    def body_page_one(self):
        lines, n = [], 0
        for p in _paras(self.body):
            ppr = p.find(W + "pPr")
            if n and ppr is not None and _on(ppr.find(W + "pageBreakBefore")):
                break
            lines += [x for x in _p_lines(p, self.styles) if x]
            n += 1
            brk = any(b.get(W + "type") == "page" for b in p.iter(W + "br")) or \
                any(True for _ in p.iter(W + "lastRenderedPageBreak"))
            if brk or (ppr is not None and ppr.find(W + "sectPr") is not None) or n >= BLOCK_PARAS:
                break
        return lines

    def check(self, mode, block, problems):
        want = None if mode == "none" else mode
        word = _KINDS[want][0] if want else ""
        plan = self.plan()
        multi = len(plan) > 1
        seen = set()
        wrong = set()
        for i, sect in enumerate(plan, 1):
            for kind, typ, part, _ in sect:
                where = (f"section {i}: " if multi else "") + f"the {typ} {kind}"
                if part is None or part.startswith("?"):
                    if want and (kind, typ, part) not in seen:
                        what = {"default": "", "first": " (the section has a title page)",
                                "even": " (the document has different even and odd pages)"}[typ]
                        problems.append(f"{where} is missing{what}: the {word} banner must be in the {kind} of every "
                                        "page")
                    seen.add((kind, typ, part))
                    continue
                if (kind, typ, part) in seen:
                    continue
                seen.add((kind, typ, part))
                if not self.z.has(part):
                    problems.append(f"{where} part {part} is missing from the file")
                    continue
                root = self.part(part)
                lines = _part_lines(root, self.styles)
                wrong |= _wrong(lines, mode)
                if want and not _has_banner(lines, want):
                    hint = ""
                    if _has_banner(_boxed_lines(root), want):
                        hint = " (a banner in a text box or shape does not count: it is not in the header/footer " \
                               "itself and does not mark every page)"
                    problems.append(f"{where} ({part}) has no {word} banner line{hint}")
        _wrong_problems(wrong, mode, "in the header or footer", problems)
        if mode == "none":
            return
        have = set(self.body_page_one())
        for part in self.page_one_parts():
            if self.z.has(part):
                have.update(_part_lines(self.part(part), self.styles))
        if mode == "fci":
            _fci_block_problems(have, "page one", problems)
        else:
            _block_problems(block, have, "page one", problems)

    def text(self):
        out = []
        for name in [self.main] + [t for typ, t in self.rels.values()
                                   if t and typ in ("header", "footer", "footnotes", "endnotes", "comments")]:
            if self.z.has(name):
                root = self.doc if name == self.main else self.part(name)
                out += ["".join(t.text or "" for t in p.iter(W + "t")) for p in root.iter(W + "p")]
        return "\n".join(out)


def _block_problems(block, have, where, problems):
    have = {_norm(x) for x in have}
    lines, missing = block
    absent = [x for x in lines if x not in have]
    if absent:
        problems.append(f"the designation block is not on {where}: missing " + "; ".join(repr(x) for x in absent))


# ---------- xlsx ----------

_HF_PARTS = (("oddHeader", "header"), ("oddFooter", "footer"), ("evenHeader", "even-page header"),
             ("evenFooter", "even-page footer"), ("firstHeader", "first-page header"),
             ("firstFooter", "first-page footer"))


def _hf_tokens(s):
    """Tokens of an Excel header/footer string: ('sec', 'L'|'C'|'R', start, end) and ('ch', text, start, end)."""
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "&" and i + 1 < n:
            c = s[i + 1]
            if c == "&":
                yield ("ch", "&", i, i + 2)
                i += 2
            elif c in "LCR":
                yield ("sec", c, i, i + 2)
                i += 2
            elif c == '"':
                j = s.find('"', i + 2)
                i = n if j == -1 else j + 1
            elif c.isdigit():
                j = i + 1
                while j < n and s[j].isdigit():
                    j += 1
                i = j
            elif c == "K":
                m = re.match(r"K(?:[0-9A-Fa-f]{6}|\d\d[+-]\d{3})", s[i + 1:])
                i += 1 + (len(m.group(0)) if m else 1)
            elif c in "PNDTFAZG":
                yield ("ch", "\x01", i, i + 2)               # a field (page number, date, ...): never a banner
                i += 2
            else:
                i += 2                                        # &B &I &U &E &S &X &Y &O &H and unknown codes
        else:
            yield ("ch", ch, i, i + 1)
            i += 1


def _hf_lines(s):
    secs = {"L": [], "C": [], "R": []}
    cur = "C"
    for kind, v, _, _ in _hf_tokens(s or ""):
        if kind == "sec":
            cur = v
        else:
            secs[cur].append(v)
    return [x for sec in secs.values() for x in "".join(sec).split("\n")]


def _xon(v):
    return (v or "").lower() in ("1", "true")


class _Xlsx:
    def __init__(self, data):
        self.z = _Zip(data)
        self.main = self.z.main()
        self.wb = self.z.xml(self.main)
        rels = self.z.rels(self.main)
        self.sst = None
        for typ, tgt in rels.values():
            if typ == "sharedStrings" and tgt and self.z.has(tgt):
                self.sst = [self._si(si) for si in self.z.xml(tgt).iter(S + "si")]
        self.sheets = []        # (name, state, part name or None, type)
        sheets = self.wb.find(S + "sheets")
        for sh in (sheets if sheets is not None else []):
            rid = sh.get("{%s}id" % R_NS)
            typ, tgt = rels.get(rid, (None, None))
            self.sheets.append((sh.get("name") or "?", (sh.get("state") or "visible"), tgt, typ))
        if not self.sheets:
            raise _Bad("is not a spreadsheet (no sheets)")

    @staticmethod
    def _si(si):
        out = []
        for c in si:
            if c.tag == S + "t":
                out.append(c.text or "")
            elif c.tag == S + "r":
                out += [t.text or "" for t in c.iter(S + "t")]
        return "".join(out)

    def hf(self, part):
        root = self.z.xml(part)
        hf = root.find(S + "headerFooter")
        return root, hf

    @staticmethod
    def needed(hf):
        names = ["oddHeader", "oddFooter"]
        if hf is not None and _xon(hf.get("differentOddEven")):
            names += ["evenHeader", "evenFooter"]
        if hf is not None and _xon(hf.get("differentFirst")):
            names += ["firstHeader", "firstFooter"]
        return names

    def cells(self, root, rows=None):
        out = []
        for c in root.iter(S + "c"):
            ref = c.get("r") or ""
            m = re.match(r"[A-Z]+(\d+)$", ref)
            if rows is not None and (not m or int(m.group(1)) > rows):
                continue
            t = c.get("t")
            if t == "inlineStr":
                is_ = c.find(S + "is")
                v = self._si(is_) if is_ is not None else ""
            elif t == "s":
                try:
                    v = self.sst[int((c.findtext(S + "v") or "").strip())] if self.sst else ""
                except (ValueError, IndexError):
                    v = ""
            else:
                v = c.findtext(S + "v") or ""
            out += v.split("\n")
        return out

    def check(self, mode, block, problems):
        want = None if mode == "none" else mode
        label = dict(_HF_PARTS)
        wrong = set()
        first_visible = None
        for name, state, part, typ in self.sheets:
            if typ not in ("worksheet", "chartsheet") or not part or not self.z.has(part):
                problems.append(f"sheet {name!r}: cannot be checked (a {typ or 'missing'} sheet)")
                continue
            root, hf = self.hf(part)
            if first_visible is None and state == "visible":
                first_visible = (name, root, hf, typ)
            if want:
                for n in self.needed(hf):
                    if not (hf is not None and _has_banner(_hf_lines(hf.findtext(S + n) or ""), want)):
                        problems.append(f"sheet {name!r}: no {_KINDS[want][0]} banner in the {label[n]} (every sheet "
                                        "needs it in its header and footer)")
            if hf is not None:                            # the wrong banner: in any of the six parts, shown or not
                for n, _ in _HF_PARTS:
                    wrong |= _wrong(_hf_lines(hf.findtext(S + n) or ""), mode)
        _wrong_problems(wrong, mode, "in a sheet header or footer", problems)
        if mode == "none":
            return
        if first_visible is None:
            if mode == "cui":
                problems.append("the designation block cannot be checked: no visible sheet")
            return
        name, root, hf, typ = first_visible
        have = set(self.cells(root, BLOCK_ROWS)) if typ == "worksheet" else set()
        if hf is not None:
            pre = "first" if _xon(hf.get("differentFirst")) else "odd"
            for n in (pre + "Header", pre + "Footer"):
                have.update(_hf_lines(hf.findtext(S + n) or ""))
        where = f"page one (rows 1-{BLOCK_ROWS} or the page-one header/footer of sheet {name!r})"
        if mode == "fci":
            _fci_block_problems(have, where, problems)
        else:
            _block_problems(block, have, where, problems)

    def text(self):
        out = list(self.sst or [])
        for _, _, part, typ in self.sheets:
            if part and self.z.has(part) and typ in ("worksheet", "chartsheet"):
                root, hf = self.hf(part)
                out += [x for x in self.cells(root) if x]
                if hf is not None:
                    out += _hf_lines(" ".join(c.text or "" for c in hf))
        return "\n".join(out)


# ---------- md ----------

def _md_block_ok(lines, block):
    """The block lines follow the first line in order; blank lines between them are allowed (Markdown needs them to
    keep the lines apart); a trailing backslash (a Markdown line break) is ignored."""
    got = []
    for x in lines[1:]:
        x = _norm(x.rstrip().rstrip("\\"))
        if not x:
            continue
        if len(got) == len(block):
            break
        got.append(x)
    return got == list(block)


class _Md:
    def __init__(self, data):
        try:
            self.text_ = data.decode("utf-8")
        except UnicodeDecodeError:
            raise _Bad("is not UTF-8 text") from None
        if self.text_.startswith("﻿"):
            self.text_ = self.text_[1:]
        self.lines = self.text_.splitlines()

    def check(self, mode, block, problems):
        lines = self.lines
        last = max((i for i, x in enumerate(lines) if x.strip()), default=-1)
        ends = ([lines[0]] if lines else []) + ([lines[last]] if last > 0 else [])
        _wrong_problems(_wrong(ends, mode), mode, "the first or last line", problems)
        if mode == "none":
            return
        word = _KINDS[mode][0]
        first_ok = bool(lines) and _is_banner(lines[0], mode)
        last_ok = last > 0 and _is_banner(lines[last], mode)
        if not first_ok:
            problems.append(f"the first line must be the {word} banner ({word})")
        if not last_ok:
            problems.append(f"the last line must be the {word} banner ({word})")
        if mode == "fci":
            head = [x for x in lines if x.strip()][:BLOCK_ROWS]
            _fci_block_problems(head, "page one (the first lines)", problems)
            return
        if first_ok and not _md_block_ok(lines, block[0]):
            problems.append("the designation block must follow the first banner line, one line each: "
                            + "; ".join(repr(x) for x in block[0]))
        elif not first_ok:
            problems.append("the designation block must follow the first banner line (there is no first banner)")

    def text(self):
        return self.text_


# ---------- pdf ----------

def _tool(name):
    """The poppler tool: /usr/bin first (root on the server never trusts PATH), else PATH (a workstation dev box)."""
    p = Path("/usr/bin") / name
    if p.is_file() and os.access(p, os.X_OK):
        return str(p)
    return shutil.which(name)


def _limits():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_PDF_TEXT, MAX_PDF_TEXT))
    except (ImportError, ValueError, OSError):
        pass


def _poppler(tool, args):
    """Run a poppler tool (no shell, timeout, output capped by RLIMIT_FSIZE into a temp file); its stdout as text."""
    exe = _tool(tool)
    if not exe:
        raise _Bad(f"cannot be checked: {tool} is not installed (poppler-utils)")
    with tempfile.TemporaryFile() as out:
        p = subprocess.run([exe] + list(args), stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL,
                           timeout=PDF_TIMEOUT, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
                           preexec_fn=_limits, close_fds=True)
        if p.returncode != 0:
            raise _Bad(f"cannot be read by {tool} (exit {p.returncode}; a damaged PDF, or too much text)")
        out.seek(0)
        return out.read(MAX_PDF_TEXT + 1).decode("utf-8", "replace")


def _page_lines(text):
    return [x for x in (_norm(y) for y in text.replace("\f", "\n").split("\n")) if x]


class _Pdf:
    def __init__(self, path):
        if _tool("pdftotext") is None or _tool("pdfinfo") is None:
            raise _Bad("cannot be checked: pdftotext/pdfinfo are not installed (poppler-utils)")
        try:
            info = _poppler("pdfinfo", [str(path)])
            m = re.search(r"^Pages:\s+(\d+)\s*$", info, re.M)
            if not m or int(m.group(1)) < 1:
                raise _Bad("has no pages (pdfinfo)")
            self.pages = int(m.group(1))
            self.first = _page_lines(_poppler("pdftotext", ["-q", "-enc", "UTF-8", "-f", "1", "-l", "1",
                                                            str(path), "-"]))
            self.last = self.first if self.pages == 1 else _page_lines(
                _poppler("pdftotext", ["-q", "-enc", "UTF-8", "-f", str(self.pages), "-l", str(self.pages),
                                       str(path), "-"]))
        except subprocess.TimeoutExpired:
            raise _Bad(f"cannot be read: pdftotext took longer than {PDF_TIMEOUT} s") from None
        except OSError as e:
            raise _Bad(f"cannot be read: the PDF tools failed ({e.strerror or e})") from None

    def check(self, mode, block, problems):
        pages = [("the first page", self.first)] + ([("the last page", self.last)] if self.pages > 1 else [])
        wrong = set()
        for _, ls in pages:
            wrong |= _wrong(ls[:2] + ls[-3:], mode)
        _wrong_problems(wrong, mode, "at the top or bottom of a page", problems)
        if mode == "none":
            return
        word = _KINDS[mode][0]
        for what, ls in pages:
            if not _has_banner(ls[:2], mode):
                problems.append(f"{what}: no {word} banner at the top")
            if not _has_banner(ls[-3:], mode):
                problems.append(f"{what}: no {word} banner at the bottom")
        if mode == "fci":
            _fci_block_problems(self.first, "page one", problems)
            return
        flat = " " + " ".join(self.first) + " "
        absent = [x for x in block[0] if f" {x} " not in flat]
        if absent:
            problems.append("the designation block is not on page one: missing " + "; ".join(repr(x) for x in absent))

    def text(self):
        return ""                                            # citations are checked in the source document


# ---------- check ----------

def _fmt(name, parts):
    ext = (parts.ext if parts else (os.path.splitext(name)[1][1:])).lower()
    return FORMATS.get(ext), ext


def _load(fmt, data, path):
    if fmt == "docx":
        return _Docx(data)
    if fmt == "xlsx":
        return _Xlsx(data)
    if fmt == "md":
        return _Md(data)
    return _Pdf(path)


def _read(path):
    try:
        st = os.stat(path)
        if st.st_size > MAX_FILE:
            raise _Bad(f"is too large ({st.st_size} bytes; at most {MAX_FILE >> 20} MiB)")
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE + 1)
    except OSError as e:
        raise _Bad(f"cannot be read ({e.strerror or e})") from None
    if len(data) > MAX_FILE:
        raise _Bad(f"is too large (at most {MAX_FILE >> 20} MiB)")
    return data


def _stat_ok(path):
    try:
        size = os.stat(path).st_size
    except OSError as e:
        raise _Bad(f"cannot be read ({e.strerror or e})") from None
    if size > MAX_FILE:
        raise _Bad(f"is too large ({size} bytes; at most {MAX_FILE >> 20} MiB)")
    return b""


_CITE = re.compile(r"(?<![\w-])((?:CUI_|FCI_)?)([^\W_][\w-]*?)_v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})"
                   r"(?![0-9]|\.[0-9])")


def _ver(v):
    if isinstance(v, (tuple, list)):
        return tuple(int(x) for x in v)
    return tuple(int(x) for x in str(v).lstrip("v").split("."))


def _citations(text, current, parts):
    cur = {}
    for k, v in (current or {}).items():
        try:
            cur[_series_key(k)] = _ver(v)
        except (TypeError, ValueError):
            continue
    own = _series_key(parts.series) if parts else None
    out = set()
    for m in _CITE.finditer(unicodedata.normalize("NFC", text)):
        key = _series_key(m.group(1) + m.group(2))
        if key == own or key not in cur:
            continue
        cited = (int(m.group(3)), int(m.group(4)))
        if cited < cur[key]:
            c = ".".join(str(x) for x in cur[key])
            out.add(f"{m.group(0)} is cited, but the current version in the Compliance area is v{c} "
                    "(a superseded citation)")
    return sorted(out)


def _check_data(name, data, path, cui, values, current=None):
    problems, warnings = [], []
    try:
        parts = parse_name(name)
    except NameRuleError as e:
        parts = None
        problems.append(str(e))
    if parts is not None:
        if cui and not parts.prefix:
            problems.append(f"name rule: {parts.series}: a controlled document in the CUI area needs the CUI_ or "
                            f"FCI_ prefix; the rule is {RULE}")
        if not cui and parts.prefix:
            problems.append(f"name rule: {name}: the {parts.prefix} prefix is for the CUI area; in the non-CUI area "
                            f"the name has no prefix; the rule is {RULE}")
    fmt, ext = _fmt(name, parts)
    if fmt is None:
        problems.append(f"{name}: the format .{ext} cannot be checked (docx, xlsx, md or pdf)")
        return Report(ok=False, problems=problems, name=parts, warnings=warnings)
    mode = _mode(cui, parts)
    block = (values.block() if values is not None else ([], [k for k, _, _ in LABELS])) if mode == "cui" \
        else ([], [])
    if mode == "cui" and block[1]:
        problems.append("the site keys " + ", ".join(block[1]) + " are not set, so the designation block cannot be "
                        "checked (set them on the site stick; they are never typed per file)")
    try:
        if data is None:
            data = _read(path) if fmt != "pdf" else _stat_ok(path)
        doc = _load(fmt, data, path)
        found = []
        doc.check(mode, block, found)
        problems += [f"{name}: {p}" for p in found]
        if current is not None:
            warnings += _citations(doc.text(), current, parts)
    except _Bad as e:
        problems.append(f"{name}: {e}")
    except Exception as e:                                 # noqa: BLE001 - never a traceback for a user's file
        problems.append(f"{name}: the file could not be read as {fmt} ({type(e).__name__})")
    return Report(ok=not problems, problems=problems, name=parts, warnings=warnings, format=fmt)


def check(path, cui, values, current=None) -> Report:
    """Check one file's name and marks for its target area (cui: the CUI area, else the non-CUI area; in the CUI area
    an FCI_ name takes the FCI banner and no designation block, any other name the CUI marks). current:
    {series (prefix+title): current version 'X.Y'} in the Compliance area, or None to skip the citation check."""
    path = Path(path)
    return _check_data(path.name, None, path, bool(cui), values, current)


# ---------- insert ----------

def _xml_text(b, name):
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        raise MarkingError(f"refused: {name} is not UTF-8 XML; mark this file in the editor") from None
    if "<!--" in t or "<![CDATA[" in t:
        raise MarkingError(f"refused: {name} holds XML comments or CDATA; mark this file in the editor")
    return t


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _root_prefix(text, local, ns, name):
    m = re.search(r"<(?:([A-Za-z_][\w.-]*):)?" + local + r"(?=[\s>/])([^>]*)>", text)
    if not m:
        raise MarkingError(f"refused: {name}: cannot find its <{local}> element; mark this file in the editor")
    decl = dict((p or "", u) for p, u in re.findall(r'xmlns(?::([\w.-]+))?\s*=\s*"([^"]*)"', m.group(2)))
    pfx = m.group(1) or ""
    if decl.get(pfx) != ns:
        raise MarkingError(f"refused: {name}: unexpected XML namespaces; mark this file in the editor")
    return pfx, m, decl


def _starts(text, pfx, local):
    q = (pfx + ":" if pfx else "") + local
    return list(re.finditer(r"<" + re.escape(q) + r"(?=[\s>/])[^>]*?(/?)>", text))


def _banner_p(w, word=BANNER):
    return f'<{w}:p><{w}:pPr><{w}:jc {w}:val="center"/></{w}:pPr><{w}:r><{w}:t>{word}</{w}:t></{w}:r></{w}:p>'


def _ins_docx(data, values, mode="cui"):
    word = _KINDS[mode][0]
    d = _Docx(data)
    z = d.z
    edits, changes, new_parts = {}, [], []
    doc_text = _xml_text(z.read(d.main), d.main)
    w, m_doc, decl = _root_prefix(doc_text, "document", W_NS, d.main)
    if not w:
        raise MarkingError(f"refused: {d.main} uses a default namespace; mark this file in the editor")
    rpfx = next((p for p, u in decl.items() if u == R_NS and p), None)
    sect_tags = _starts(doc_text, w, "sectPr")
    if len(sect_tags) != len(d.all_sects):
        raise MarkingError(f"refused: {d.main}: its section layout cannot be edited safely; mark it in the editor")
    sect_index = {id(s): i for i, s in enumerate(d.all_sects)}
    doc_ins = []                                           # (position, text) insertions into document.xml
    rels_part = posixpath.join(posixpath.dirname(d.main), "_rels", posixpath.basename(d.main) + ".rels")
    if not z.has(rels_part):
        raise MarkingError(f"refused: {d.main} has no relationships part; mark it in the editor")
    rel_ids = set(d.rels)
    names = set(z.lower)
    base_dir = posixpath.dirname(d.main)

    def new_part(kind):
        n = 1
        while posixpath.join(base_dir, f"{kind}{n}.xml").casefold() in names:
            n += 1
        pn = posixpath.join(base_dir, f"{kind}{n}.xml")
        names.add(pn.casefold())
        k = 1
        while f"rIdChp{k}" in rel_ids:
            k += 1
        rid = f"rIdChp{k}"
        rel_ids.add(rid)
        new_parts.append((kind, pn, rid))
        return pn, rid

    carry_new, done = {}, set()
    plan = d.plan()
    if not d.sects:                                        # no sectPr at all: one is added at the end of the body
        sect_refs = []
    for sect in plan:
        add_refs = []
        for kind, typ, part, s in sect:
            if part is None or part.startswith("?"):
                if (kind, typ) in carry_new:
                    continue
                pn, rid = new_part(kind)
                carry_new[(kind, typ)] = pn
                tag = "headerReference" if kind == "header" else "footerReference"
                add_refs.append((tag, typ, rid))
                changes.append(f"new {pn}: a {typ} {kind} with the {word} banner")
            elif part not in done and z.has(part):
                done.add(part)
                if not _has_banner(_part_lines(d.part(part), d.styles), mode):
                    edits[part] = kind
                    changes.append(f"{part}: add the {word} banner to the {typ} {kind}")
        if add_refs:
            if rpfx is None:
                rpfx = "r"
                while rpfx in decl:
                    rpfx += "x"
                doc_ins.append((m_doc.end() - 1 - (1 if doc_text[m_doc.end() - 2] == "/" else 0),
                                f' xmlns:{rpfx}="{R_NS}"'))
                decl[rpfx] = R_NS
            refs = "".join(f'<{w}:{tag} {w}:type="{typ}" {rpfx}:id="{rid}"/>' for tag, typ, rid in add_refs)
            s = sect[0][3]
            if s is None:
                sect_refs = refs
            else:
                mt = sect_tags[sect_index[id(s)]]
                if mt.group(1) == "/":                     # <w:sectPr/>
                    doc_ins.append((mt.start(), None, mt.end(), f"<{w}:sectPr>{refs}</{w}:sectPr>"))
                else:
                    doc_ins.append((mt.end(), refs))
    if not d.sects and carry_new:
        bc = doc_text.rfind(f"</{w}:body>")
        if bc == -1:
            raise MarkingError(f"refused: {d.main}: no body end; mark it in the editor")
        doc_ins.append((bc, f"<{w}:sectPr>{sect_refs}</{w}:sectPr>"))

    lines = values.block()[0] if mode == "cui" else []       # an FCI_ document takes no designation block
    have = set(d.body_page_one())
    for part in d.page_one_parts():
        if z.has(part):
            have.update(_part_lines(d.part(part), d.styles))
    if any(x not in {_norm(h) for h in have} for x in lines):
        bt = _starts(doc_text, w, "body")
        if len(bt) != 1 or bt[0].group(1) == "/":
            raise MarkingError(f"refused: {d.main}: no body to add the designation block to")
        blk = "".join(f'<{w}:p><{w}:r><{w}:t xml:space="preserve">{_esc(x)}</{w}:t></{w}:r></{w}:p>' for x in lines)
        doc_ins.append((bt[0].end(), blk))
        changes.append(f"{d.main}: add the designation block at the top of page one")
    if not changes:
        return data, []

    out = {}
    if doc_ins:
        t = doc_text
        for ins in sorted(doc_ins, key=lambda x: x[0], reverse=True):
            if len(ins) == 2:
                t = t[:ins[0]] + ins[1] + t[ins[0]:]
            else:
                t = t[:ins[0]] + ins[3] + t[ins[2]:]
        out[d.main] = t.encode("utf-8")
    for part, kind in edits.items():
        t = _xml_text(z.read(part), part)
        local = "hdr" if kind == "header" else "ftr"
        pfx, m, _ = _root_prefix(t, local, W_NS, part)
        if not pfx:
            raise MarkingError(f"refused: {part} uses a default namespace; mark this file in the editor")
        if m.group(0).endswith("/>"):
            t = t[:m.start()] + m.group(0)[:-2] + ">" + _banner_p(pfx, word) + f"</{pfx}:{local}>" + t[m.end():]
        elif kind == "header":
            t = t[:m.end()] + _banner_p(pfx, word) + t[m.end():]
        else:
            e = t.rfind(f"</{pfx}:{local}>")
            t = t[:e] + _banner_p(pfx, word) + t[e:]
        out[z.real(part)] = t.encode("utf-8")
    if new_parts:
        rt = _xml_text(z.read(rels_part), rels_part)
        e = rt.rfind("</Relationships>")
        ct_name = z.real("[Content_Types].xml")
        if e == -1 or ct_name is None:
            raise MarkingError("refused: the package relationships cannot be edited safely; mark it in the editor")
        ct = _xml_text(z.read(ct_name), ct_name)
        ce = ct.rfind("</Types>")
        if ce == -1:
            raise MarkingError("refused: the package content types cannot be edited safely; mark it in the editor")
        add_rel, add_ct = "", ""
        for kind, pn, rid in new_parts:
            tgt = posixpath.relpath(pn, base_dir)
            add_rel += f'<Relationship Id="{rid}" Type="{REL}{kind}" Target="{tgt}"/>'
            add_ct += (f'<Override PartName="/{pn}" ContentType="application/vnd.openxmlformats-officedocument.'
                       f'wordprocessingml.{kind}+xml"/>')
            local = "hdr" if kind == "header" else "ftr"
            out[pn] = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:{local} xmlns:w="{W_NS}">'
                       f"{_banner_p('w', word)}</w:{local}>").encode("utf-8")
        out[z.real(rels_part)] = (rt[:e] + add_rel + rt[e:]).encode("utf-8")
        out[ct_name] = (ct[:ce] + add_ct + ct[ce:]).encode("utf-8")
    return _rezip(z, out, [pn for _, pn, _ in new_parts]), changes


def _hf_raw_sections(s):
    """{'L'|'C'|'R': raw substring} (leading text before any section code is the centre)."""
    secs, cur, start = {}, "C", 0
    for kind, v, a, b in _hf_tokens(s):
        if kind == "sec":
            secs[cur] = secs.get(cur, "") + s[start:a]
            cur, start = v, b
    secs[cur] = secs.get(cur, "") + s[start:]
    return secs


def _hf_join(secs):
    return "".join(f"&{k}{secs[k]}" for k in "LCR" if secs.get(k))


def _hf_with_banner(s, word=BANNER):
    secs = _hf_raw_sections(s or "")
    c = secs.get("C", "")
    secs["C"] = word + ("\n" + c if c else "")
    return _hf_join(secs)


_HF_FOLLOW = ("rowBreaks", "colBreaks", "customProperties", "cellWatches", "ignoredErrors", "smartTags", "drawing",
              "legacyDrawing", "legacyDrawingHF", "drawingHF", "picture", "oleObjects", "controls",
              "webPublishItems", "tableParts", "extLst")


def _ins_xlsx(data, values, mode="cui"):
    word = _KINDS[mode][0]
    x = _Xlsx(data)
    z = x.z
    lines = values.block()[0] if mode == "cui" else []       # an FCI_ document takes no designation block
    out, changes = {}, []
    first_visible = next((s for s in x.sheets if s[1] == "visible"), None)
    for name, state, part, typ in x.sheets:
        if typ not in ("worksheet", "chartsheet") or not part or not z.has(part):
            raise MarkingError(f"refused: sheet {name!r} cannot be marked (a {typ or 'missing'} sheet)")
        root, hf = x.hf(part)
        kids = {} if hf is None else {c.tag[len(S):]: (c.text or "") for c in hf if c.tag.startswith(S)}
        attrs = {} if hf is None else dict(hf.attrib)
        if any(k.startswith("{") for k in attrs):
            raise MarkingError(f"refused: sheet {name!r}: its header/footer cannot be edited safely")
        label = dict(_HF_PARTS)
        sheet_changes = []
        for n in x.needed(hf):
            if not _has_banner(_hf_lines(kids.get(n, "")), mode):
                kids[n] = _hf_with_banner(kids.get(n, ""), word)
                sheet_changes.append(f"sheet {name!r}: add the {word} banner to the {label[n]}")
        if lines and first_visible is not None and name == first_visible[0]:
            have = set(x.cells(root, BLOCK_ROWS)) if typ == "worksheet" else set()
            pre = "first" if _xon(attrs.get("differentFirst")) else "odd"
            have.update(_hf_lines(kids.get(pre + "Header", "")))
            have.update(_hf_lines(kids.get(pre + "Footer", "")))
            if any(v not in {_norm(h) for h in have} for v in lines):
                if not _xon(attrs.get("differentFirst")):
                    attrs["differentFirst"] = "1"
                    kids["firstHeader"] = kids.get("oddHeader", "")
                    kids["firstFooter"] = kids.get("oddFooter", "")
                    for n in ("firstHeader", "firstFooter"):
                        if not _has_banner(_hf_lines(kids[n])):
                            kids[n] = _hf_with_banner(kids[n])
                secs = _hf_raw_sections(kids.get("firstFooter", ""))
                secs["L"] = "\n".join(v.replace("&", "&&") for v in lines)
                kids["firstFooter"] = _hf_join(secs)
                if not _has_banner(_hf_lines(kids["firstFooter"])):
                    kids["firstFooter"] = _hf_with_banner(kids["firstFooter"])
                sheet_changes.append(f"sheet {name!r}: add the designation block to the first-page footer")
        if not sheet_changes:
            continue
        for n, v in kids.items():
            if len(v) > 255:
                raise MarkingError(f"refused: sheet {name!r}: the {label.get(n, n)} would be longer than 255 "
                                   "characters (an Excel limit); type the designation block into rows 1-3 of the "
                                   "first sheet, or start from the marked template (chp-site doc new)")
        t = _xml_text(z.read(part), part)
        local = "worksheet" if typ == "worksheet" else "chartsheet"
        pfx, m, _ = _root_prefix(t, local, S[1:-1], part)
        q = (pfx + ":") if pfx else ""
        order = ["oddHeader", "oddFooter", "evenHeader", "evenFooter", "firstHeader", "firstFooter"]
        attr_s = "".join(f' {k}="{_esc(v)}"' for k, v in attrs.items())
        new_hf = f"<{q}headerFooter{attr_s}>" + "".join(
            f"<{q}{n}>{_esc(kids[n])}</{q}{n}>" for n in order if kids.get(n)) + f"</{q}headerFooter>"
        starts = _starts(t, pfx, "headerFooter")
        if hf is not None:
            if len(starts) != 1:
                raise MarkingError(f"refused: sheet {name!r}: its header/footer cannot be edited safely")
            st = starts[0]
            if st.group(1) == "/":
                end = st.end()
            else:
                close = f"</{q}headerFooter>"
                end = t.find(close, st.end())
                if end == -1:
                    raise MarkingError(f"refused: sheet {name!r}: its header/footer cannot be edited safely")
                end += len(close)
            t = t[:st.start()] + new_hf + t[end:]
        else:
            pos = None
            kids_top = [c.tag[len(S):] for c in root if c.tag.startswith(S)]
            nxt = next((k for k in kids_top if k in _HF_FOLLOW), None)
            if nxt is not None:
                idx = [e for e in root.iter(S + nxt)].index(next(c for c in root if c.tag == S + nxt))
                ms = _starts(t, pfx, nxt)
                if len(ms) != len(list(root.iter(S + nxt))):
                    raise MarkingError(f"refused: sheet {name!r}: its layout cannot be edited safely")
                pos = ms[idx].start()
            else:
                pos = t.rfind(f"</{q}{local}>")
                if pos == -1:
                    raise MarkingError(f"refused: sheet {name!r}: its layout cannot be edited safely")
            t = t[:pos] + new_hf + t[pos:]
        out[z.real(part)] = t.encode("utf-8")
        changes += sheet_changes
    if not changes:
        return data, []
    return _rezip(z, out, []), changes


def _ins_md(data, values, mode="cui"):
    word = _KINDS[mode][0]
    m = _Md(data)
    bom = data.startswith(b"\xef\xbb\xbf")
    nl = "\r\n" if "\r\n" in m.text_ else "\n"
    lines = list(m.lines)
    block = values.block()[0] if mode == "cui" else []       # an FCI_ document takes no designation block
    blk = [x for b in block for x in (b, "")]
    changes = []
    if not (lines and _is_banner(lines[0], mode)):
        lines = [word, ""] + blk + lines
        changes.append(f"add the {word} banner as the first line")
        if block:
            changes.append("add the designation block after the first banner line")
    elif block and not _md_block_ok(lines, block):
        rest = lines[1:]
        while rest and not rest[0].strip():
            rest = rest[1:]
        lines = [lines[0], ""] + blk + rest
        changes.append("add the designation block after the first banner line")
    last = max((i for i, x in enumerate(lines) if x.strip()), default=-1)
    if not (last > 0 and _is_banner(lines[last], mode)):
        lines = lines[:last + 1] + ["", word]
        changes.append(f"add the {word} banner as the last line")
    if not changes:
        return data, []
    return (b"\xef\xbb\xbf" if bom else b"") + (nl.join(lines) + nl).encode("utf-8"), changes


def _rezip(z, replaced, added):
    """The same package with some parts replaced and some added: same order, dates, compression and attributes, so
    the result depends only on the input and the values (deterministic)."""
    b = BytesIO()
    with zipfile.ZipFile(b, "w") as out:
        for i in z.infos:
            zi = zipfile.ZipInfo(i.filename, i.date_time)
            zi.compress_type, zi.external_attr, zi.create_system = i.compress_type, i.external_attr, i.create_system
            zi.comment = i.comment
            out.writestr(zi, replaced.get(i.filename, z.data[i.filename]))
        date = max((i.date_time for i in z.infos), default=(1980, 1, 1, 0, 0, 0))
        for pn in added:
            zi = zipfile.ZipInfo(pn, date)
            zi.compress_type, zi.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
            out.writestr(zi, replaced[pn])
    return b.getvalue()


def insert(path, values, dry_run=True) -> List[str]:
    """Insert the missing marks into a -DRAFT file: the CUI banner and the designation block for a CUI_ name, the FCI
    banner only for an FCI_ name. Returns what it changes (or, dry run, would change); [] when nothing is missing.
    Raises NameRuleError or MarkingError (plain message, nothing changed)."""
    path = Path(path)
    parts = parse_name(path.name)
    if not parts.draft:
        raise MarkingError(f"refused: {path.name} is not a -DRAFT file; marks are inserted only into a -DRAFT file, "
                           "before approval (an approved or published file is never changed)")
    if not parts.prefix:
        raise MarkingError(f"refused: {path.name} has a non-CUI name (no CUI_ or FCI_ prefix); CUI and FCI marks go "
                           "only on documents for the CUI area")
    mode = _mode(True, parts)
    fmt, ext = _fmt(path.name, parts)
    if fmt == "pdf":
        raise MarkingError(f"refused: {path.name}: a PDF is not marked in place; mark the source document and export "
                           "the PDF again")
    if fmt is None:
        raise MarkingError(f"refused: {path.name}: the format .{ext} cannot be marked (docx, xlsx or md)")
    lines, missing = values.block()
    if mode == "cui" and missing:
        raise MarkingError("refused: the site keys " + ", ".join(missing) + " are not set; set them on the site stick "
                           "(the marking values are never typed per file)")
    try:
        data = _read(path)
        new, changes = {"docx": _ins_docx, "xlsx": _ins_xlsx, "md": _ins_md}[fmt](data, values, mode)
    except _Bad as e:
        raise MarkingError(f"refused: {path.name} {e}") from None
    except MarkingError:
        raise
    except Exception as e:                                  # noqa: BLE001 - a user's file: plain refusal
        raise MarkingError(f"refused: {path.name}: the file could not be marked ({type(e).__name__}); mark it in "
                           "the editor") from None
    if not changes:
        rep = _check_data(path.name, data, path, True, values)
        if not rep.ok:                                      # e.g. the other banner: insert never removes a mark
            raise MarkingError(f"refused: {path.name}: nothing can be added, but the check fails ("
                               + "; ".join(rep.problems)[:800] + "); mark it in the editor")
        return []
    rep = _check_data(path.name, new, path, True, values)
    if not rep.ok:
        raise MarkingError(f"refused: {path.name}: after inserting the marks the check still fails ("
                           + "; ".join(rep.problems)[:800] + "); nothing was changed; mark it in the editor")
    if dry_run:
        return changes
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".chp-mark-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(new)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return changes
