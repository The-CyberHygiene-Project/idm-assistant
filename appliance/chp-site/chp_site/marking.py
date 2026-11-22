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
import html
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
REL_STRICT = "http://purl.oclc.org/ooxml/officeDocument/relationships/"
A_NS = "{http://schemas.openxmlformats.org/drawingml/2006/main}"     # DrawingML text (a:p, a:t)
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
    if len(n) > 200 or len(n.encode("utf-8", "surrogatepass")) > 255:
        bad("the name is too long (200 characters and 255 bytes at most; an accented letter is 2 bytes)")
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
    if prefix and _fold(title[:8]).startswith(("cui_", "fci_")):
        bad("the title starts with a second CUI_ or FCI_ prefix (one prefix only, for example FCI_Plan, not "
            "FCI_CUI_Plan)")
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


# The Latin-confusables fold (Task 12b fix round 4): letters (and letter-like signs) of other scripts that look like
# a Latin letter A-Z / a-z are read as that letter, before every WRONG-banner check (never the required banner, which
# stays an exact ASCII match). Source: the Unicode confusables data (UTS #39 confusables.txt, the MA table) as built
# into ICU 78.3 (Unicode 17.0): every non-ASCII code point whose skeleton (uspoof_getSkeleton) is one ASCII letter,
# without combining marks (_wfold drops those) and without the code points NFKC already folds to ASCII (checked with
# the Unicode data of Python 3.9 and 3.12). The skeleton has no I (I itself maps to l): an upper-case source (one with
# a lower-case mapping) whose skeleton is l is written I here. Grouped by the Latin letter.
_LATIN_CONFUSABLES = {
    "A": ("\u0391\u0410\u13aa\u15c5\ua4ee\U000102a0\U00016f40\U0001ccd6\U0001d6a8\U0001d6e2\U0001d71c\U0001d756"
          "\U0001d790"),
    "a": ("\u0251\u03b1\u0430\u237a\U0001d6c2\U0001d6fc\U0001d736\U0001d770\U0001d7aa"),
    "B": ("\u0392\u0412\u13f4\u15f7\u2c82\ua4d0\ua7b4\U00010282\U000102a1\U00010301\U0001ccd7\U0001d6a9\U0001d6e3"
          "\U0001d71d\U0001d757\U0001d791"),
    "b": ("\u0184\u042c\u13cf\u1472\u15af\U00016eb6"),
    "C": ("\u03f9\u0421\u13df\u2ca4\ua4da\U000102a2\U00010302\U00010415\U0001051c\U000118e9\U000118f2\U0001ccd8"
          "\U0001f74c"),
    "c": ("\u03f2\u0441\u1004\u105a\u1d04\u2ca5\uabaf\U0001043d"),
    "D": ("\u13a0\u15de\u15ea\ua4d3\U0001ccd9"),
    "d": ("\u0501\u13e7\u146f\ua4d2"),
    "E": ("\u0395\u0415\u13ac\u22ff\u2d39\ua4f0\U00010286\U000118a6\U000118ae\U0001ccda\U0001d6ac\U0001d6e6"
          "\U0001d720\U0001d75a\U0001d794"),
    "e": ("\u0435\u04bd\u212e\uab32"),
    "F": ("\u03dc\u15b4\ua4dd\ua798\U00010287\U000102a5\U00010525\U000118a2\U000118c2\U0001ccdb\U0001d213\U0001d7ca"),
    "f": ("\u0192\u0584\u1e9d\ua799\uab35"),
    "G": ("\u050c\u13c0\u13f3\ua4d6\U0001ccdc"),
    "g": ("\u018d\u0261\u0581\u1d83"),
    "H": ("\u0397\u041d\u13bb\u157c\u2c8e\ua4e7\U000102cf\U0001ccdd\U0001d6ae\U0001d6e8\U0001d722\U0001d75c"
          "\U0001d796"),
    "h": ("\u04bb\u0570\u13c2"),
    "I": ("\u0196\u0399\u0406\u04c0\u2c92\U00016eaa"),
    "i": ("\u0131\u0269\u026a\u02db\u037a\u03b9\u0456\u0582\u13a5\u1fbe\u2373\u2c93\ua647\uab75\U000118c3\U0001d6a4"
          "\U0001d6ca\U0001d704\U0001d73e\U0001d778\U0001d7b2"),
    "J": ("\u037f\u0408\u13ab\u148d\ua4d9\ua7b2\U0001ccdf"),
    "j": ("\u03f3\u0458"),
    "K": ("\u039a\u041a\u13e6\u16d5\u2c94\ua4d7\U00010518\U0001cce0\U0001d6b1\U0001d6eb\U0001d725\U0001d75f"
          "\U0001d799"),
    "L": ("\u13de\u14aa\u2cd0\ua4e1\U0001041b\U00010526\U000118a3\U000118b2\U00016f16\U0001cce1\U0001d22a"),
    "l": ("\u01c0\u04cf\u05c0\u05d5\u05df\u0627\u0661\u06f1\u07ca\u16c1\u2223\u23fd\u2d4f\ua4f2\ufe8d\ufe8e\uffe8"
          "\U0001028a\U00010309\U00010320\U00011dda\U00011de1\U00016f28\U0001ccde\U0001ccf1\U0001d6b0\U0001d6ea"
          "\U0001d724\U0001d75e\U0001d798\U0001e8c7\U0001ee00\U0001ee80"),
    "M": ("\u039c\u03fa\u041c\u13b7\u15f0\u16d6\u2c98\ua4df\U000102b0\U00010311\U0001cce2\U0001d6b3\U0001d6ed"
          "\U0001d727\U0001d761\U0001d79b"),
    "N": ("\u039d\u2c9a\ua4e0\U00010513\U0001cce3\U0001d6b4\U0001d6ee\U0001d728\U0001d762\U0001d79c"),
    "n": ("\u0578\u057c"),
    "O": ("\u039f\u041e\u0555\u07c0\u0b20\u0ce6\u12d0\u2c9e\u2d54\u3007\ua4f3\U00010292\U000102ab\U00010404"
          "\U000104c2\U00010516\U000118b5\U000118e0\U00011de0\U0001cce4\U0001ccf0\U0001d6b6\U0001d6f0\U0001d72a"
          "\U0001d764\U0001d79e"),
    "o": ("\u03bf\u03c3\u03ed\u043e\u0585\u05e1\u0647\u0665\u06be\u06c1\u06d5\u06f5\u0966\u09e6\u0a66\u0ae6\u0b66"
          "\u0be6\u0c66\u0d20\u0d66\u0e50\u0ed0\u101d\u1040\u10ff\u17e0\u1d0f\u1d11\u2c9f\uab3d\ufba6\ufba7\ufba8"
          "\ufba9\ufbaa\ufbab\ufbac\ufbad\ufee9\ufeea\ufeeb\ufeec\U0001042c\U000104ea\U000114d0\U000118c8\U000118d7"
          "\U0001d6d0\U0001d6d4\U0001d70a\U0001d70e\U0001d744\U0001d748\U0001d77e\U0001d782\U0001d7b8\U0001d7bc"
          "\U0001ee24\U0001ee64\U0001ee84"),
    "P": ("\u03a1\u0420\u13e2\u146d\u2ca2\u2cce\ua4d1\U00010295\U0001cce5\U0001d6b8\U0001d6f2\U0001d72c\U0001d766"
          "\U0001d7a0"),
    "p": ("\u00fe\u01bf\u03c1\u03f1\u03f8\u0440\u2374\u2ca3\u2ccf\U0001d6d2\U0001d6e0\U0001d70c\U0001d71a\U0001d746"
          "\U0001d754\U0001d780\U0001d78e\U0001d7ba\U0001d7c8"),
    "Q": ("\u2d55\U0001cce6"),
    "q": ("\u051b\u0563\u0566"),
    "R": ("\u01a6\u13a1\u13d2\u1587\ua4e3\U000104b4\U00016f35\U0001cce7\U0001d216"),
    "r": ("\u0433\u1d26\u2c85\uab47\uab48\uab81"),
    "S": ("\u0405\u054f\u13d5\u13da\ua4e2\U00010296\U00010420\U00016f3a\U0001cce8"),
    "s": ("\u01bd\u0455\u0d1f\ua731\uabaa\U00010448\U000118c1"),
    "T": ("\u03a4\u0422\u13a2\u22a4\u27d9\u2ca6\ua4d4\U00010297\U000102b1\U00010315\U000118bc\U00016f0a\U0001cce9"
          "\U0001d6bb\U0001d6f5\U0001d72f\U0001d769\U0001d7a3\U0001f768"),
    "U": ("\u054d\u1200\u144c\u222a\u22c3\ua4f4\U000104ce\U000118b8\U00016f42\U0001ccea"),
    "u": ("\u028b\u03c5\u057d\u1d1c\ua79f\uab4e\uab52\U000104f6\U000118d8\U0001d6d6\U0001d710\U0001d74a\U0001d784"
          "\U0001d7be"),
    "V": ("\u0474\u0667\u06f7\u13d9\u142f\u2d38\ua4e6\ua6df\U0001051d\U000118a0\U00016f08\U0001cceb\U0001d20d"),
    "v": ("\u03bd\u0475\u05d8\u1d20\u2228\u22c1\uaba9\U00011706\U000118c0\U0001d6ce\U0001d708\U0001d742\U0001d77c"
          "\U0001d7b6"),
    "W": ("\u051c\u13b3\u13d4\ua4ea\U000118e6\U000118ef\U0001ccec"),
    "w": ("\u026f\u0448\u0461\u051d\u0561\u1d21\u2cbd\uab83\U0001170a\U0001170e\U0001170f"),
    "X": ("\u03a7\u0425\u166d\u16b7\u2573\u2cac\u2d5d\ua4eb\ua7b3\U00010290\U000102b4\U00010317\U00010322\U00010527"
          "\U000118ec\U0001cced\U0001d6be\U0001d6f8\U0001d732\U0001d76c\U0001d7a6"),
    "x": ("\u00d7\u0445\u1541\u157d\u166e\u292b\u292c\u2a2f"),
    "Y": ("\u03a5\u03d2\u0423\u04ae\u13a9\u13bd\u2ca8\ua4ec\U000102b2\U000118a4\U00016f43\U0001ccee\U0001d6bc"
          "\U0001d6f6\U0001d730\U0001d76a\U0001d7a4"),
    "y": ("\u0263\u028f\u03b3\u0443\u04af\u10e7\u1d8c\u1eff\u213d\u2ca9\uab5a\U000118dc\U0001d6c4\U0001d6fe"
          "\U0001d738\U0001d772\U0001d7ac"),
    "Z": ("\u0396\u13c3\ua4dc\U000102f5\U000118a9\U000118e5\U0001ccef\U0001d6ad\U0001d6e7\U0001d721\U0001d75b"
          "\U0001d795"),
    "z": ("\u1d22\uab93\U000118c4"),
}
# CHP additions, kept from the hand-made table of earlier rounds (fail closed): not in the confusables data, or read
# there as another letter (Cyrillic U as Y, Carrier GHO as A); these win
_CHP_LOOKALIKES = {"\u0423": "U", "\u0545": "U", "\u15c5": "F", "\u0191": "F"}
_LATIN_FOLD = {ord(c): t for t, cs in _LATIN_CONFUSABLES.items() for c in cs}
_LATIN_FOLD.update({ord(c): t for c, t in _CHP_LOOKALIKES.items()})
# the fold for both checks: the letters, and the lookalike slashes (fraction slash, division slash, big solidus)
_LOOKALIKE = {**_LATIN_FOLD, **{ord(c): "/" for c in "\u2044\u2215\u29f8"}}


def _fold(s):
    """For the prefix test only: compatibility forms (fullwidth etc.), cross-script lookalikes and case folded."""
    return unicodedata.normalize("NFKC", s.translate(_LOOKALIKE)).translate(_LOOKALIKE).casefold()


_WMAP = str.maketrans({"l": "i", "1": "i"})


_CAPS_L1 = re.compile(r"(?<![^\W\d_])(CU|FC)[l1](?![^\W\d_])")


def _wfold(s, li=True, cf=True):
    """For the WRONG-banner search only (never the prefix test, never the required banner): compatibility forms, NBSP,
    format characters (zero-width, soft hyphen: Unicode Cf) and combining marks (accents, underlines, enclosing
    circles: NFKD, every category M dropped, NFKC; Task 12b) dropped, cross-script lookalikes (the Latin-confusables
    fold, _LOOKALIKE, before and after the normalisation: fix round 4), case. li=True: l / 1
    read as i everywhere (the wide forms); li=False: only in a capitals context (CUl, CU1, FCl, FC1: the Markdown body,
    so "Cul-de-sac" stays a word). cf=False keeps the case (the citation tail check). Runs of white space become one
    space."""
    s = "".join(c for c in unicodedata.normalize("NFKD", s.translate(_LOOKALIKE))
                if unicodedata.category(c)[0] != "M" and unicodedata.category(c) != "Cf")
    s = unicodedata.normalize("NFKC", s).replace("\u00a0", " ").translate(_LOOKALIKE)
    if not li:
        s = _CAPS_L1.sub(lambda m: m.group(1) + "I", s)
    if cf:
        s = s.casefold()
    return " ".join((s.translate(_WMAP) if li else s).split())


def _phrase(text):
    """The spelled-out phrase, casefolded, with l, i and 1 interchangeable (either fold)."""
    return r"[\W_]{0,3}".join("".join("[li1]" if c in "li" else re.escape(c) for c in w.casefold())
                               for w in text.split())


# what may follow the word in a banner line: //, - – — : | ( [ / and the middle dots · • ∙ ⋅ (review I2)
_SEP = r"(?://|[-:|(\[\u2010-\u2015/\u00b7\u2022\u2219\u22c5])"
SHORT_TAIL = 3                                  # Markdown body: a banner's tail after a separator has at most 3 words
# kind -> (the banner text, the exact pattern a required banner must match, (the word, the spelled-out phrase))
_KINDS = {"cui": (BANNER, _BANNER_RE, ("cui", _phrase("Controlled Unclassified Information"))),
          "fci": (FCI_BANNER, _FCI_RE, ("fci", _phrase("Federal Contract Information")))}
# the word spelled out letter by letter at the start of a line (C-U-I, C.U.I., C/U/I, C U I), read as the word
_SPELLED = {k: re.compile("^" + r"[\W_]{1,3}".join(v[2][0]) + r"(?![^\W_])\.?") for k, v in _KINDS.items()}
# ... and anywhere as a whole word (the text after a cited name: fix round 4)
_SPELLED_ANY = {k: re.compile(r"(?<![^\W_])" + r"[\W_]{1,3}".join(v[2][0]) + r"(?![^\W_])") for k, v in _KINDS.items()}
_SLASHES = re.compile(r"/(?: ?/)+")             # "/ /" is "//"
_CUI_BLOCK_LABEL = re.compile(r"cui\s*category\s*:")
# a document name after its prefix: <title>_vX.Y (ASCII digits; shared with the citation check, _CITE). In a banner
# position, the word, _ and this is a citation of a controlled document, not a banner (review fix round 2)
_CITE_TAIL = r"([^\W_][\w-]*?)_v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(?![0-9]|\.[0-9])"
# the name token of a citation in a banner position: the word, _, the title, the version, -DRAFT and the extension,
# as a whole word; the title is bounded (a name has 200 characters at most) so a search along a line stays linear
_NAME_TOKEN = {k: re.compile(r"(?<![^\W_])" + v[2][0] + "_" + _CITE_TAIL.replace(r"[\w-]*?", r"[\w-]{0,199}?")
                             + r"(?:-draft)?(?:\.[a-z0-9]{1,10})?(?![^\W_])", re.I)
               for k, v in _KINDS.items()}
_CAPS_TOKEN = re.compile(r"[\W_]*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)(?![^\W_])")
_MD_LEAD = re.compile(r"(?:#{1,6}\s+|#{1,6}$|>|[-*+]\s+|\d{1,9}[.)]\s+|\[[ xX]\])\s*")
_MD_TAG = re.compile(r"<[^<>]{0,200}>")
# tags that render as a line break or a new block: each piece around them is judged as a line (Task 12b)
_MD_BREAK = re.compile(r"<\s{0,20}/?\s{0,20}(?:br|p|div|hr|li|ul|ol|dl|dt|dd|tr|td|th|thead|tbody|tfoot|table|"
                       r"caption|h[1-6]|blockquote|pre|section|article|aside|header|footer|nav|main|details|summary|"
                       r"figure|figcaption|center|address)(?![\w-])[^<>]{0,200}>", re.I)
_MD_TASK = re.compile(r"^(\s*(?:[-*+]|\d{1,9}[.)])\s+)\[[ xX]\]\s*")
_MD_REFDEF = re.compile(r"^\s{0,3}\[([^\[\]]{1,1000})\]:\s*\S.*$")
_MD_FOOTREF = re.compile(r"\[\^[^\[\]\s]{1,200}\]")
_MD_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
_MD_STRIP = " \t()[]{}<>\"'.,;:!?\\"
MD_MAX_LINE = 8192                # a longer Markdown line is refused, not scanned (Task 12b: no unbounded work)


def _md_plain(cell, keep_us=False):
    """A Markdown line (or table cell) without its block and inline markup: heading #s (and closing #s), quote >s,
    list and task-list markers, the * _ ` ~ wrappers, and surrounding brackets, parentheses and punctuation. Linear:
    no pattern here can backtrack over the line."""
    s, pos = cell.strip(), 0
    while True:
        m = _MD_LEAD.match(s, pos)
        if not m or not m.group(0):
            break
        pos = m.end()
    s = re.sub(r"[*`~]" if keep_us else r"[*_`~]", "", s[pos:]).rstrip()
    k = len(s)
    while k and s[k - 1] == "#":
        k -= 1
    if k < len(s) and (k == 0 or s[k - 1].isspace()):     # an ATX heading's closing #s
        s = s[:k]
    return s.strip(_MD_STRIP)


def _md_comments(s):
    """HTML comments removed, in one pass; the text of a comment that never closes stays (judged: fail closed)."""
    out, i = [], 0
    while True:
        j = s.find("<!--", i)
        if j < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        k = s.find("-->", j + 4)
        if k < 0:
            out.append(" " + s[j + 4:])
            break
        out.append(" ")
        i = k + 3
    return "".join(out).replace("-->", " ")


def _md_links(s):
    """[text](dest), ![alt](dest), [text][ref] and [text] read as the text, in one linear pass (no backtracking): the
    brackets (and an image's !) are dropped, and a (dest) right after them, balanced parentheses included, or a [ref]
    right after them is removed. An unmatched bracket is dropped too (fail closed: the text around it is judged)."""
    paren, stack = {}, []
    for i, c in enumerate(s):
        if c == "(":
            stack.append(i)
        elif c == ")" and stack:
            paren[stack.pop()] = i
    square, last = {}, None
    for i, c in enumerate(s):
        if c == "[":
            last = i
        elif c == "]" and last is not None:
            square[last] = i
            last = None
    out, opens, i, n = [], 0, 0, len(s)
    while i < n:
        c = s[i]
        if c == "[":
            if out and out[-1] == "!":
                out.pop()
            opens += 1
        elif c == "]" and opens:
            opens -= 1
            if i + 1 < n and s[i + 1] == "(" and i + 1 in paren:
                i = paren[i + 1]
            elif i + 1 < n and s[i + 1] == "[" and i + 1 in square:
                i = square[i + 1]
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _md_attrs(s):
    """A trailing attribute block ({#id}, {.class}, {: ...}) removed (at most three)."""
    for _ in range(3):
        t = s.rstrip()
        j = t.rfind("{")
        if not t.endswith("}") or j < 0 or "}" in t[j:-1]:
            break
        s = t[:j]
    return s


def _md_cells(line):
    """Every reading of one Markdown line the wrong-banner search judges (Task 12 fix round 3, controller design;
    Task 12b): HTML entities decoded (repeatedly, bounded), NBSP and comments removed, the line split at <br> and
    block tags (each piece rendered as its own line), inline HTML tags removed (and, as a second reading, replaced by
    their text, so <CUI> counts), footnote references removed, link, image and reference syntax reduced to the link
    text, backslash escapes and trailing attribute blocks removed, a table row split into its cells, then each cell
    without its markup (_md_plain). Every step is linear in the line; a line longer than MD_MAX_LINE is refused."""
    if len(line) > MD_MAX_LINE:
        raise _Bad(f"has a line longer than {MD_MAX_LINE} characters ({len(line)}); a Markdown line that long cannot "
                   "be checked: break it into shorter lines")
    s = line
    for _ in range(5):
        u = html.unescape(s)
        if u == s:
            break
        s = u
    s = _md_comments(s.replace("\u00a0", " "))
    out = []
    for piece in _MD_BREAK.split(s):
        for v in (_MD_TAG.sub(" ", piece), _MD_TAG.sub(lambda m: " " + m.group(0)[1:-1].strip(" \t/") + " ", piece)):
            v = _MD_TASK.sub(r"\1", v)                              # a task-list box
            v = _MD_FOOTREF.sub("", v)                              # a footnote reference [^1]
            v = _MD_REFDEF.sub(r"\1", v)                            # a reference definition: its label
            v = _md_attrs(_MD_ESCAPE.sub(r"\1", _md_links(v) if "[" in v else v))
            cells = v.split("|") if "|" in v else [v]
            out += [_md_plain(c) for c in cells]
            # an intraword _ renders as itself (CUI_SP-PROPIN): a second reading keeps it, so the banner-position rules
            # (and the citation carve-out, _cite_rest) see what docx sees (review I2, fix round 3)
            out += [_md_plain(c, keep_us=True) for c in cells if "_" in c]
    return [c for c in out if c]


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


def _trim(s):
    """Everything that is not a letter or digit removed from both ends (quotes, brackets, stars, ellipses, #, ...)."""
    i, j = 0, len(s)
    while i < j and not s[i].isalnum():
        i += 1
    while j > i and not s[j - 1].isalnum():
        j -= 1
    return s[i:j]


def _cite_rest(line, kind):
    """When the line (folded without the l/1 reading, which would turn digits into letters, and keeping case) starts
    with a citation of a controlled document, the word, _ and a document name (CUI_SSP_v1.2[-DRAFT][.ext]): the text
    after the name token; else None. A title that starts with SP- (a CUI category marking) is no citation."""
    t = _trim(_wfold(line, li=False, cf=False))
    m = _NAME_TOKEN[kind].match(t)
    if not m or m.group(1).casefold().startswith("sp-"):
        return None
    return t[m.end():]


def _tail_banner(rest, kind):
    """What follows a cited name (already Latin-folded, case kept: _cite_rest) is a banner when it holds // (after
    the slash fold), the word or the phrase as a whole word, or starts with a capitals token of 3 letters or more
    (SP-PROPIN, NOFORN) (review fix round 3). Fix round 4: it is read like a wide line start (l and 1 as i, the word
    spelled out letter by letter as the word), and a further citation in it (CUI_SSP_v1.2, CUI_POAM_v1.0) is a
    citation, not the word: the text is cut at each one and every piece is judged the same way."""
    word, phrase = _KINDS[kind][2]
    pieces, pos = [], 0
    for m in _NAME_TOKEN[kind].finditer(rest):
        if not m.group(1).casefold().startswith("sp-"):    # an SP- title is no citation: it stays in the text
            pieces.append(rest[pos:m.start()])
            pos = m.end()
    pieces.append(rest[pos:])
    for piece in pieces:
        r = _SPELLED_ANY[kind].sub(word, _SLASHES.sub("//", _wfold(piece)))
        if "//" in r or re.search(rf"(?<![^\W_])(?:{word}|{phrase})(?![^\W_])", r):
            return True
        if re.search(r"(?<![^\W_])sp\s*-\s*[a-z]", r):     # a CUI category marking in any case, split or not
            return True                                    # (Task 13a, 12b minor: sp-propin, Sp - Propin)
        m = _CAPS_TOKEN.match(piece)
        if m and sum(c.isalpha() for c in m.group(1)) >= 3:
            return True
    return False


def _looks_like(line, kind, wide=True):
    """The folded search for a banner that must NOT be there (see the module notes). One normalisation for every
    format first (Task 12b): _wfold, "/ /" read as "//", everything but letters and digits trimmed from both ends
    (quotes, brackets, ellipses, stars), and the word spelled out letter by letter (C-U-I, C.U.I.) read as the word;
    the phrase allows up to 3 non-letters between its words (Controlled-Unclassified-Information). A banner line is:
      - the word alone (also spaced, dotted or otherwise split: "C U I", "C.U.I."), or the word with //markings;
      - the word or the spelled-out phrase followed by a separator (- – — : | ( [) and a tail;
      - the spelled-out phrase alone, or (wide) followed by anything;
      - (wide only, controller rulings 2026-11-20) the word followed by white space or any character that is not a
        letter or digit, and anything: "CUI SP-PROPIN", "CUI/SP-PROPIN", "CUI_SP-PROPIN" ("CUI's ..." too).
    wide (docx/xlsx/pdf banner positions, the first and last Markdown lines): any tail counts, and l/1 read as i
    everywhere. Not wide (the Markdown body, where lines are prose): a separator tail counts only when it starts with
    the spelled-out phrase, holds //, or has at most SHORT_TAIL words; l/1 read as i only in CUl/FCl capitals."""
    word, phrase = _KINDS[kind][2]
    s = _trim(_SLASHES.sub("//", _wfold(line, li=wide)))
    s = _SPELLED[kind].sub(word, s, count=1)
    if re.sub(r"[\W_]", "", s) == word:                      # the word alone, spaced, dotted or quoted
        return True
    m = re.fullmatch(rf"({word}|{phrase})\s*(.*)", s)
    if not m:
        return False
    head, rest = m.group(1), m.group(2)
    if not rest or rest.startswith("//"):
        return True
    if head != word and wide:
        return True                                        # the phrase followed by anything, in a banner position
    if wide and not s[len(word)].isalnum():
        # the word, then white space or any non-alphanumeric and anything (rulings), unless it is a citation (the
        # word, _ and a document name) with a tail that is no banner
        tail = _cite_rest(line, kind) if s[len(word)] == "_" else None
        return tail is None or _tail_banner(tail, kind)
    sep = re.match(rf"{_SEP}\s*(.*)", rest)
    if not sep:
        return False
    tail = sep.group(1)
    if wide or "//" in tail or re.match(phrase, tail):
        return True
    return len(re.findall(r"[^\W_]+", tail)) <= SHORT_TAIL


def _wrong(lines, mode, wide=True):
    """The banner kinds among `lines` that do not belong to a document of this mode ('cui', 'fci' or 'none')."""
    return {k for k in _KINDS if k != mode and any(_looks_like(x, k, wide) for x in lines)}


def _md_wrong(lines, mode):
    """Markdown: every line outside code (fenced and indented code blocks), in every reading of _md_cells. The first
    and the last non-blank lines are banner positions (the wide forms, fail closed), judged even when they are code;
    the body is judged as prose."""
    idx = [i for i, x in enumerate(lines) if x.strip()]
    ends = {idx[0], idx[-1]} if idx else set()
    judged = dict(_md_unfenced_idx(lines))
    for i in ends:
        judged.setdefault(i, lines[i])
    found = set()
    for i in sorted(judged):
        found |= _wrong(_md_cells(judged[i]), mode, wide=i in ends)
    return found


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


def _fci_block_problems(lines, where, problems):
    """An FCI_ document carries no CUI designation block: a `CUI Category:` line (_wfold, any spacing) is a
    problem."""
    if any(_CUI_BLOCK_LABEL.match(_wfold(x)) for x in lines):
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
            # the short type ("header", "styles", ...) only for the OOXML relationship namespaces: a Type of another
            # namespace that merely ends in /header is not a header (final review B M3); it stays whole
            typ = next((typ[len(p):] for p in (REL, REL_STRICT) if typ.startswith(p) and "/" not in typ[len(p):]),
                       typ)
            if (r.get("TargetMode") or "").lower() == "external":
                out[rid] = (typ, None)
                continue
            t = tgt[1:] if tgt.startswith("/") else posixpath.join(d, tgt)
            t = posixpath.normpath(t)
            out[rid] = (typ, None if t.startswith("..") or t.startswith("/") else t)
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


_WRONG_SKIP = (W + "del", W + "moveFrom")       # deleted and moved-away text never shows
_PARAS = (W + "p", A_NS + "p")


def _wrong_lines(root):
    """Every line a header/footer part could show, for the WRONG-banner search only (final review B I1): the text of
    each paragraph (w:p, and DrawingML a:p) anywhere in the part -- text boxes, shapes, drawings, objects, hidden
    runs included -- each nested paragraph a line of its own, every mc:AlternateContent read once per branch (Choice
    and Fallback), and every VML text path (v:textpath string, Word's Design > Watermark). Only deleted and moved-away
    text is left out. The required banner is never looked for here (it stays strict: _part_lines)."""
    acs = [e for e in root.iter(MC + "AlternateContent")]
    width = max([len([k for k in a if k.tag in (MC + "Choice", MC + "Fallback")]) for a in acs] or [1])

    def line(p, branch):
        buf = []

        def walk(e):
            for c in e:
                t = c.tag
                if t in _WRONG_SKIP or t in _PARAS:
                    continue                              # a nested paragraph is a line of its own
                if t == MC + "AlternateContent":
                    ks = [k for k in c if k.tag in (MC + "Choice", MC + "Fallback")]
                    if ks:
                        walk(ks[min(branch, len(ks) - 1)])
                    continue
                if t in (W + "t", A_NS + "t"):
                    buf.append(c.text or "")
                elif t == W + "tab":
                    buf.append(" ")
                elif t in (W + "br", W + "cr", A_NS + "br"):
                    buf.append("\n")
                walk(c)
        walk(p)
        return [_norm(x) for x in "".join(buf).split("\n")]

    deleted = set()
    for d in root.iter():
        if d.tag in _WRONG_SKIP:
            deleted.update(id(x) for x in d.iter())
    out = []
    for e in root.iter():
        if id(e) in deleted:
            continue
        if e.tag in _PARAS:
            for b in range(width):
                out += [x for x in line(e, b) if x]
        elif isinstance(e.tag, str) and e.tag.rsplit("}", 1)[-1] == "textpath" and e.get("string"):
            out += [x for x in (_norm(y) for y in e.get("string").split("\n")) if x]
    return out


def _body_paras(e):
    """The body-level paragraphs: children of w:body, also through w:sdt/w:sdtContent and w:customXml wrappers."""
    for c in e:
        if c.tag == W + "p":
            yield c
        elif c.tag == W + "sdt":
            sc = c.find(W + "sdtContent")
            if sc is not None:
                yield from _body_paras(sc)
        elif c.tag == W + "customXml":
            yield from _body_paras(c)


BAD_SECT = ("a section break is in a place that cannot be checked (inside alternate content, a tracked change, a "
            "text box or a table, or on a deleted paragraph mark), so which header and footer its pages show is not "
            "certain; remove or accept it in the editor")


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
        # final review B I2: only the places Word reads a section's properties from count -- the body's last child,
        # and the paragraph properties of a body-level paragraph whose mark is not deleted. Any other sectPr
        # (mc:Fallback, w:pPrChange, a text box, a table cell, a deleted paragraph mark) is a problem, never a source
        # of header inheritance
        ok = set()
        for p in _body_paras(self.body):
            ppr = p.find(W + "pPr")
            sp = ppr.find(W + "sectPr") if ppr is not None else None
            if sp is None:
                continue
            rpr = ppr.find(W + "rPr")
            if rpr is None or (rpr.find(W + "del") is None and rpr.find(W + "moveFrom") is None):
                ok.add(id(sp))
        kids = list(self.body)
        if kids and kids[-1].tag == W + "sectPr":
            ok.add(id(kids[-1]))
        self.sects = [s for s in self.all_sects if id(s) in ok]
        self.bad_sects = [s for s in self.all_sects if id(s) not in ok and id(s) not in nested]
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
                        rtyp, tgt = self.rels.get(rid, (None, None))
                        if tgt and rtyp != kind:              # final review B M3: not a header/footer relationship
                            tgt = "!" + tgt
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
        return [p for k, t, p, _ in first if t == want and p and not p.startswith(("?", "!"))
                and self.hf_root_ok(p, k)]

    def hf_root_ok(self, part, kind):
        """The part is a header (w:hdr) or footer (w:ftr) as its reference says (final review B M3)."""
        return self.z.has(part) and self.part(part).tag == W + ("hdr" if kind == "header" else "ftr")

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
        if self.bad_sects:
            problems.append(BAD_SECT)
        for i, sect in enumerate(plan, 1):
            for kind, typ, part, _ in sect:
                where = (f"section {i}: " if multi else "") + f"the {typ} {kind}"
                if part is not None and part.startswith("!"):
                    if (kind, typ, part) not in seen:
                        problems.append(f"{where}: its reference points at {part[1:]}, which is not a {kind} "
                                        "relationship; fix the file in the editor")
                    seen.add((kind, typ, part))
                    continue
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
                if not self.hf_root_ok(part, kind):
                    problems.append(f"{where} part {part} is not a {kind} part (its root element is not "
                                    f"w:{'hdr' if kind == 'header' else 'ftr'}); fix the file in the editor")
                    continue
                root = self.part(part)
                lines = _part_lines(root, self.styles)
                wrong |= _wrong(lines + _wrong_lines(root), mode)     # a wrong banner anywhere it can show
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


_FENCE = re.compile(r"\s{0,3}(`{3,}|~{3,})")
# a line that opens a container whose indented continuation renders as text: a list item, a footnote definition, a
# definition (": ..." or pandoc's "~ ..."), an admonition head (!!! / ???), a tab head (=== "Tab") (review I1 and fix
# round 2: fail closed)
_LIST_ITEM = re.compile(r" {0,3}(?:(?:[-*+]|\d{1,9}[.)]|[:~])(?:[ \t]|$)|\[\^[^\]]+\]:|!!!|\?\?\?|===[+!]{0,2}[ \t])")


def _indent(x):
    """The column of a line's first non-blank character (a tab moves to the next multiple of 4, as CommonMark)."""
    col = 0
    for c in x:
        if c == " ":
            col += 1
        elif c == "\t":
            col += 4 - col % 4
        else:
            break
    return col


def _md_unfenced_idx(lines):
    """(index, line) for the lines outside code blocks: every one is searched for a wrong banner (Task 12 fix round 1:
    insert must not be able to push a wrong banner inward, and a hand-written one inside must be seen).
    Code blocks: fenced (``` or ~~~; a fence that never closes hides nothing), and indented (Task 12b: indented 4
    columns or more, after a blank line, the start of the file or another code line, and not after a list item, a
    footnote definition, a definition line, an admonition or a tab head: _LIST_ITEM).
    Indented text that renders as text stays judged (fail closed): a paragraph continuation (no blank line before),
    and anything after a list item until a blank line and a line at column 0 that is not a list item end the list
    (indented text there is the item's paragraph; lazy continuation lines keep the list open)."""
    out, fence, blank, code, in_list = [], None, True, False, False
    for i, x in enumerate(lines):
        m = _FENCE.match(x)
        if fence is not None:
            if m and m.group(1).startswith(fence) and not x.strip().strip(fence[0]):
                fence = None
            continue
        if m:
            fence, blank, code = m.group(1)[0] * 3, False, False
            continue
        if not x.strip():
            blank = True
            out.append((i, x))
            continue
        ind = _indent(x)
        if ind >= 4 and not in_list and (blank or code):
            code, blank = True, False
            continue
        if _LIST_ITEM.match(x):
            in_list = True
        elif ind == 0 and blank:
            in_list = False
        code, blank = False, False
        out.append((i, x))
    return out if fence is None else list(enumerate(lines))


def _md_unfenced(lines):
    return [x for _, x in _md_unfenced_idx(lines)]


_MD_EOL = re.compile(r"\r\n|\r|\n")


class _Md:
    def __init__(self, data):
        try:
            self.text_ = data.decode("utf-8")
        except UnicodeDecodeError:
            raise _Bad("is not UTF-8 text") from None
        if self.text_.startswith("﻿"):
            self.text_ = self.text_[1:]
        # lines end at LF, CR or CRLF only (final review B M1): str.splitlines also ends one at VT, FF, the file and
        # group separators, NEL and U+2028/9, which CommonMark keeps inside a line, so a required "banner" after one
        # of those was a line here and need not be one on the rendered page
        self.lines = _MD_EOL.split(self.text_)
        if self.lines and self.lines[-1] == "":
            self.lines.pop()

    def wrong(self, mode):
        """The wrong banner kinds, in both readings: lines ended at LF/CR only, and also at every other separator
        (a renderer may break the line there: U+2028 is a mandatory break in UAX #14), so a wrong banner is found
        whichever way the line is shown (fail closed); the required banner is read from LF/CR lines only."""
        return _md_wrong(self.lines, mode) | _md_wrong(self.text_.splitlines(), mode)

    def check(self, mode, block, problems):
        lines = self.lines
        last = max((i for i, x in enumerate(lines) if x.strip()), default=-1)
        _wrong_problems(self.wrong(mode), mode, "a line of the document", problems)
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
            # a judged line over MD_MAX_LINE was refused above; a longer code line is read up to the cap (the label
            # starts a cell)
            _fci_block_problems([c for x in head for c in _md_cells(x[:MD_MAX_LINE])], "page one (the first lines)",
                                problems)
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


_CITE = re.compile(r"(?<![\w-])((?:CUI_|FCI_)?)" + _CITE_TAIL)


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
    if d.bad_sects:
        raise MarkingError(f"refused: {d.main}: {BAD_SECT}")
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
    for sect in plan:
        for kind, typ, part, _ in sect:
            if part and not part.startswith("?") and (part.startswith("!") or (z.has(part)
                                                                                and not d.hf_root_ok(part, kind))):
                raise MarkingError(f"refused: the {typ} {kind} reference points at {part.lstrip('!')}, which is not "
                                   f"a {kind}; fix the file in the editor")
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


def _hf_plain(raw):
    """A header/footer section's text without its codes, for a message."""
    return " ".join(_hf_lines("&L" + raw)) or raw


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
                left = "\n".join(v.replace("&", "&&") for v in lines)
                if secs.get("L", "").strip() and secs["L"] != left:
                    # final review B M5: never replaced silently (the dry run says so too: it is the same refusal)
                    raise MarkingError(f"refused: sheet {name!r}: the designation block goes in the left section of "
                                       "the first-page footer, which already holds text "
                                       f"({_hf_plain(secs['L'])[:80]!r}); insert never replaces text: move that text "
                                       "to the centre or right section in Excel, or type the designation block into "
                                       "rows 1-3 of the first sheet, then run it again")
                secs["L"] = left
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
    found = m.wrong(mode)
    if found:                                                # never wrap the right banner around a wrong one
        raise MarkingError("refused: the file carries " + " and ".join(f"{_ART[k]} banner" for k in sorted(found))
                           + "; insert never removes a mark: fix it in the editor")
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
