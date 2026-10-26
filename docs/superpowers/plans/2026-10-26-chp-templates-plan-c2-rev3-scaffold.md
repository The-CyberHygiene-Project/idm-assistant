# chp-templates Plan C2 (batch 1): the Rev 3 scaffold — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the self-contained Rev 3 library to `chp-templates`. It holds NIST's Rev 3 catalog, a Rev 2 → Rev 3 crosswalk, the 80 DoD organization-defined parameter (ODP) values as defaults, a Rev 3 SSP laid out by the 03.xx families, and a Rev 3 POA&M. Every control block is `pending`. It is released as signed `templates-1.3.0`.

**Architecture:** `rev3/` mirrors `rev2/`. The NIST and DoD sources are pinned by sha256. Importers and generators in `tools/` produce the data files once, and tests then pin the committed files. The renderer gains three additive behaviours, all driven by the library's own files, and Rev 2's output stays byte-identical.

**Tech Stack:** Python 3.9 standard library (`render/`, `tools/`). `pdftotext` (poppler) runs only in the developer-side ODP checker. Tests use pytest in `.venv`.

**Spec:** `docs/superpowers/specs/2026-10-24-chp-templates-design.md` (idm-assistant). Owner decisions of 2026-10-26 amend it (Task 7 writes them in):
- **Scaffold first:** diwai has had no Rev 3 walk, so every Rev 3 block is `pending` in this release.
- **ODP keys** are `odp.<memo part id with dots as underscores>`, e.g. `odp.03_01_01_f_02`, in a new `[odp]` section, never mixed into `decision.*`.
- **The DoD memo's IDs are authoritative.** The memo has 80 ODPs over 50 requirements. NIST's OSCAL file splits some of them differently (88), so it is not used.
- **The Rev 3 SSP is keyed to the 03.xx families,** because Rev 3 has no separate SSP layout.

**Repo:** all work is in `~/chp-templates`, on a new branch `c2-rev3-scaffold`. Only Task 7 also touches `~/idm-assistant` (the spec amendment and memory). Test command: `cd ~/chp-templates && .venv/bin/python -m pytest -q` (baseline: 287 passed, 3 skipped).

## Global Constraints

- `render/chpfill.py` stays Python 3.9 standard library only, and `tests/test_py39_and_contract.py` must keep passing.
- **Placeholders are only ever added.** No existing placeholder is renamed or removed.
- **Rev 2 output must not change.** `tests/test_golden.py` must still pass unchanged, except for the deliberate Rev 2 POA&M T-06 update in Task 5. That task regenerates the Rev 2 golden snapshot and says why.
- **Nothing real:** no organization, person, host, address or diwai fact enters the library. `tests/test_nothing_real.py` must pass. Its domain allow-list gains only `dodcio.defense.gov`, for the memo citation.
- **Never copy diwai content.** diwai supplied only "no Rev 3 walk yet". No block may claim diwai proof.
- **Sources (pinned):**
  - NIST change analysis `https://csrc.nist.gov/files/pubs/sp/800/171/r3/final/docs/sp800-171r2-to-r3-analysis.xlsx`, sha256 `ad0908f52945e316dec05a4032cbcaa75958eab2534d2627b3a89f696fb30b84`.
  - DoD memo "Department of Defense Organization-Defined Parameters for NIST SP 800-171 Revision 3", signed 2025-04-10, `https://dodcio.defense.gov/Portals/0/Documents/CMMC/OrgDefinedParmsNISTSP800-171.pdf`, sha256 `fd83ecf4e0998f0b29d5e6f222e7364ce67eb6fdedb5ac4f34ec4310ba495916`. The site refuses scripted downloads (HTTP 403); the owner's copy is at `~/rag-library/documents-sysadmin/2026-10/DOD 800-171 ODP guidance.pdf`.
- **Known source facts (verified 2026-10-26):**
  - The workbook's sheet `xl/worksheets/sheet2.xml` ("Change Analysis 800-171 R2-R3") has 130 data rows: 97 active and 33 withdrawn. Columns are A family, C R2 id, D R2 text, G R3 id, H name, I R3 text, J/K/L no-significant/significant/minor change, M new ODP, N new requirement, O withdrawn, P summary.
  - Family is blank on 6 new rows. Some ids carry a trailing tab. One text has the typo `03.02 01`.
  - **Erratum:** row 97 is labelled Rev 2 `3.11.4`, but Rev 2 has no 3.11.4. That row is the withdrawn Rev 3 slot `03.12.04`. Rev 2 3.12.4's own row (row 124) maps it to `03.15.02`. The importer skips row 97.
- **Rev 3 families** (from NIST's OSCAL group titles): 01 Access Control AC, 02 Awareness and Training AT, 03 Audit and Accountability AU, 04 Configuration Management CM, 05 Identification and Authentication IA, 06 Incident Response IR, 07 Maintenance MA, 08 Media Protection MP, 09 Personnel Security PS, 10 Physical Protection PE, 11 Risk Assessment RA, 12 Security Assessment and Monitoring CA, 13 System and Communications Protection SC, 14 System and Information Integrity SI, 15 Planning PL, 16 System and Services Acquisition SA, 17 Supply Chain Risk Management SR.
- **Writing style:** plain English with short sentences. Never mention AI tools in library text.
- **Commits** end with the session attribution lines. The owner merges the PR.

## Review Focus

1. **A wrong DoD value is silently shipped as a default.** A site would sign an SSP stating a value DoD never set. The checker (Task 3) must tie every value to its memo table row; spot-check the printout.
2. **The renderer change leaks into Rev 2.** A Rev 2 render must be byte-identical to before (golden test). The title, blockquote and pending behaviours must trigger only on Rev 3's catalog columns and status.
3. **A guidance-only ODP shows a made-up value.** The 4 guidance ODPs get no default. They stay visible as `{{odp.…}}`, appear in the fill-in report, and their block quotes DoD's guidance.
4. **The crosswalk drops or invents a Rev 2 ID.** It must cover exactly the 110 Rev 2 IDs, map 3.12.4 → 03.15.02, and never list 3.11.4.
5. **A `pending` block reads like a claim.** Its status line and text must say "not yet proven" and put the site in charge. It must have no evidence and no appliance wording.

---

### Task 1: Renderer — Rev 3 catalog headings, `pending` status, `odp.*` defaults

**Files:**
- Modify: `render/chpfill.py` (`load_values` defaults loop; `_status_line`; `assemble` heading)
- Test: `tests/test_rev3_render.py` (new)

**Interfaces:**
- Produces:
  - `load_values()` now also takes `odp.*` keys from a defaults file;
  - `_status_line(text)` returns a pending line for `status=pending`;
  - `assemble(lib)` headings: when the catalog has a non-empty `title` column, it writes `#### <id> <title>` followed by the requirement as a blockquote.
- Rev 3 `catalog.csv` columns (Task 2 produces them): `id,family,family_code,title,requirement`, where `requirement` holds newline-separated lines.

- [ ] **Step 1: Create the branch and write the failing tests**

```bash
cd ~/chp-templates && git checkout -b c2-rev3-scaffold
```

`tests/test_rev3_render.py`:

```python
from pathlib import Path

from render.chpfill import DEFAULT, _status_line, assemble, load_values

TOP = Path(__file__).resolve().parents[1]
MAP = TOP / "site-conf-mapping.csv"


def lib(tmp_path, catalog, block):
    t = tmp_path / "lib" / "templates"
    (t / "ssp" / "controls").mkdir(parents=True)
    (t / "ssp" / "arch").mkdir()
    (t / "poam").mkdir()
    (t / "ssp" / "frame.md").write_text("{{> controls}}\n")
    (t / "ssp" / "arch" / "chp-appliance.md").write_text("arch\n")
    (t / "poam" / "frame.md").write_text("poam\n")
    (tmp_path / "lib" / "catalog.csv").write_text(catalog)
    for cid, text in block.items():
        (t / "ssp" / "controls" / f"{cid}.md").write_text(text)
    return tmp_path / "lib"


def test_rev3_heading_uses_title_and_quotes_the_requirement(tmp_path):
    cat = ('id,family,family_code,title,requirement\n'
           '03.01.01,Access Control,AC,Account Management,"a. Define the types.\nb. Create accounts."\n')
    blk = "<!-- chp:control id=03.01.01 status=pending evidence= -->\n**Implementation:** Pending.\n"
    ssp = assemble(lib(tmp_path, cat, {"03.01.01": blk}))["ssp.md"]
    assert "#### 03.01.01 Account Management\n\n> a. Define the types.\\\n> b. Create accounts.\n\n" in ssp


def test_rev2_heading_is_unchanged(tmp_path):
    cat = "id,family,family_code,basic_derived,requirement\n3.1.1,Access Control,AC,Basic,Limit access.\n"
    blk = "<!-- chp:control id=3.1.1 status=site evidence= -->\n**Implementation:** None.\n"
    ssp = assemble(lib(tmp_path, cat, {"3.1.1": blk}))["ssp.md"]
    assert "#### 3.1.1 Limit access.\n\n**Status:** site." in ssp and "> " not in ssp


def test_pending_status_line_says_not_yet_proven():
    line = _status_line("<!-- chp:control id=03.01.01 status=pending evidence= -->\nx")
    assert line == ("**Status:** pending (not yet proven on the Rev 3 reference implementation). "
                    "**Evidence:** none yet.\n\n")


def test_odp_defaults_load_and_are_marked_as_defaults(tmp_path):
    d = tmp_path / "defaults.ini"
    d.write_text("[odp]\n03_01_01_f_02 = at most 90 days\n[other]\nx = 1\n")
    v, _, prov = load_values(None, None, d, MAP)
    assert v["odp.03_01_01_f_02"] == "at most 90 days" and prov["odp.03_01_01_f_02"] == DEFAULT
    assert "other.x" not in v


def test_profile_overrides_an_odp_default(tmp_path):
    d = tmp_path / "defaults.ini"
    d.write_text("[odp]\n03_01_01_f_02 = at most 90 days\n")
    p = tmp_path / "p.ini"
    p.write_text("[odp]\n03_01_01_f_02 = 30 days\n")
    v, _, prov = load_values(p, None, d, MAP)
    assert v["odp.03_01_01_f_02"] == "30 days" and prov["odp.03_01_01_f_02"] == "profile"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_rev3_render.py`
Expected: 4 FAIL: the title heading, the pending line, and the two odp tests. `test_rev2_heading_is_unchanged` PASSES.

- [ ] **Step 3: Implement**

In `load_values`, change the defaults condition:

```python
            if key.startswith(("decision.", "odp.")) and key not in values:
```

In `_status_line`, after `if not m: return ""`, add:

```python
    if m.group(2) == "pending":
        return ("**Status:** pending (not yet proven on the Rev 3 reference implementation). "
                "**Evidence:** none yet.\n\n")
```

In `assemble`, replace the `blocks.append(f"#### {r['id']} {r['requirement']}\n\n…")` line with:

```python
        if r.get("title"):                 # Rev 3 catalog: named requirement, multi-part text quoted under it
            quote = " \\\n".join(f"> {ln}" for ln in r["requirement"].split("\n") if ln.strip())
            head = f"#### {r['id']} {r['title']}\n\n{quote}\n\n"
        else:                              # Rev 2 catalog: the one-sentence requirement is the heading
            head = f"#### {r['id']} {r['requirement']}\n\n"
        blocks.append(f"{head}{_status_line(text)}{META.sub('', text).strip()}\n")
```

The join must produce `> a. …\` + newline + `> b. …`. The test pins the exact string; if your join differs, fix the code, not the test.

- [ ] **Step 4: Run the new tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass (287 + 5). `tests/test_golden.py` passes unchanged, which proves Rev 2 is byte-identical.

- [ ] **Step 5: Commit**

```bash
git add render/chpfill.py tests/test_rev3_render.py
git commit -m "Renderer: Rev 3 catalog headings (title + quoted requirement), pending status line, odp.* defaults; Rev 2 output unchanged"
```

---

### Task 2: Rev 3 catalog and Rev 2 → Rev 3 crosswalk importer

**Files:**
- Create: `tools/import_catalog_r3.py`, `rev3/catalog.csv`, `rev3/crosswalk.csv`
- Test: `tests/test_catalog_r3.py` (new)

**Interfaces:**
- Produces:
  - `rev3/catalog.csv` with columns `id,family,family_code,title,requirement` (97 rows, sorted by id);
  - `rev3/crosswalk.csv` with columns `rev2_id,rev3_ids,change,note` (110 rows in Rev 2 order). `rev3_ids` is space-separated and may be empty. `change` is one of `no significant change`, `minor change`, `significant change`, `withdrawn`.
  - Functions `tools.import_catalog_r3.read_rows(data: bytes) -> list[dict]`, `convert(rows) -> (catalog, crosswalk)` and `FAMILIES: dict[str, tuple[str, str]]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_catalog_r3.py`:

```python
import csv
from pathlib import Path

import pytest
from tools.import_catalog_r3 import FAMILIES, convert, load

TOP = Path(__file__).resolve().parents[1]
CAT = list(csv.DictReader(open(TOP / "rev3/catalog.csv", encoding="utf-8")))
XW = list(csv.DictReader(open(TOP / "rev3/crosswalk.csv", encoding="utf-8")))
R2 = [r["id"] for r in csv.DictReader(open(TOP / "rev2/catalog.csv", encoding="utf-8"))]


def test_catalog_has_the_97_requirements_in_order():
    ids = [r["id"] for r in CAT]
    assert len(ids) == 97 and len(set(ids)) == 97 and ids == sorted(ids)
    assert list(csv.DictReader(open(TOP / "rev3/catalog.csv")).fieldnames) == ["id", "family", "family_code", "title",
                                                                               "requirement"]


def test_families_come_from_the_id_and_all_17_appear():
    assert len(FAMILIES) == 17
    for r in CAT:
        assert (r["family"], r["family_code"]) == FAMILIES[r["id"][3:5]]
        assert r["title"] and r["title"] != "Withdrawn" and r["requirement"].strip()
        assert "\t" not in r["requirement"] and "\t" not in r["id"]
    assert {r["family_code"] for r in CAT} == {c for _, c in FAMILIES.values()}


def test_crosswalk_covers_exactly_the_rev2_ids():
    assert [r["rev2_id"] for r in XW] == R2


def test_crosswalk_targets_exist_and_changes_are_known():
    ids = {r["id"] for r in CAT}
    for r in XW:
        assert set(r["rev3_ids"].split()) <= ids, r
        assert r["change"] in ("no significant change", "minor change", "significant change", "withdrawn"), r


def test_known_mappings_including_the_nist_erratum():
    x = {r["rev2_id"]: r for r in XW}
    assert x["3.12.4"]["rev3_ids"] == "03.15.02"                       # 3.11.4 row in the workbook is an erratum
    assert x["3.4.7"]["rev3_ids"] == "03.04.06 03.04.08" and x["3.4.7"]["change"] == "withdrawn"
    assert x["3.2.3"]["rev3_ids"] == "03.02.01"                        # NIST text has the typo "03.02 01"
    assert x["3.5.6"]["rev3_ids"] == "" and x["3.5.6"]["note"] == "Consistency with SP 800-53."
    assert x["3.1.1"] == {"rev2_id": "3.1.1", "rev3_ids": "03.01.01", "change": "significant change",
                          "note": "New security requirement title Aligned with SP 800-53, Rev 5"}


def test_convert_skips_the_erratum_row_and_fixes_spacing():
    head = {"C": "SP 800-171 R2 Identifier", "G": "SP 800-171 R3 Identifier"}
    rows = [head,
            {"C": "3.2.3", "G": "03.02.03", "H": "Withdrawn", "I": "Incorporated into 03.02 01.", "O": "X"},
            {"C": "3.11.4", "G": "03.12.04", "H": "Withdrawn", "I": "Incorporated into 03.15.02.", "O": "X"},
            {"C": "", "A": "", "G": "03.15.01\t", "H": "Policy and Procedures", "I": "a.\tDevelop policies.\n\n",
             "N": "X"}]
    cat, xw = convert(rows)
    assert cat == [{"id": "03.15.01", "family": "Planning", "family_code": "PL", "title": "Policy and Procedures",
                    "requirement": "a. Develop policies."}]
    assert xw == [{"rev2_id": "3.2.3", "rev3_ids": "03.02.01", "change": "withdrawn",
                   "note": "Incorporated into 03.02.01."}]


def test_load_refuses_an_unpinned_file(tmp_path):
    p = tmp_path / "x.xlsx"
    p.write_bytes(b"not the NIST file")
    with pytest.raises(SystemExit, match="refusing"):
        load(str(p))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_catalog_r3.py`
Expected: an ERROR at import (`tools.import_catalog_r3` missing and `rev3/catalog.csv` missing).

- [ ] **Step 3: Implement `tools/import_catalog_r3.py`**

```python
# CyberHygiene Project — chp-templates (shared SSP and POA&M templates).
# Licensed under the Apache License 2.0. Placeholder templates only: no site's values belong in this repository.
"""import_catalog_r3.py SOURCE: build rev3/catalog.csv and rev3/crosswalk.csv from NIST's SP 800-171 Rev 2 to Rev 3
change analysis workbook (one pinned file gives both). SOURCE is the NIST URL or a local copy; its sha256 must match."""
import csv
import hashlib
import io
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

URL = "https://csrc.nist.gov/files/pubs/sp/800/171/r3/final/docs/sp800-171r2-to-r3-analysis.xlsx"
SHA256 = "ad0908f52945e316dec05a4032cbcaa75958eab2534d2627b3a89f696fb30b84"
SHEET = "xl/worksheets/sheet2.xml"          # "Change Analysis 800-171 R2-R3" (pinned file, so the position is fixed)
FAMILIES = {"01": ("Access Control", "AC"), "02": ("Awareness and Training", "AT"),
            "03": ("Audit and Accountability", "AU"), "04": ("Configuration Management", "CM"),
            "05": ("Identification and Authentication", "IA"), "06": ("Incident Response", "IR"),
            "07": ("Maintenance", "MA"), "08": ("Media Protection", "MP"), "09": ("Personnel Security", "PS"),
            "10": ("Physical Protection", "PE"), "11": ("Risk Assessment", "RA"),
            "12": ("Security Assessment and Monitoring", "CA"), "13": ("System and Communications Protection", "SC"),
            "14": ("System and Information Integrity", "SI"), "15": ("Planning", "PL"),
            "16": ("System and Services Acquisition", "SA"), "17": ("Supply Chain Risk Management", "SR")}
# NIST erratum: the withdrawn 03.12.04 row is labelled with Rev 2 ID 3.11.4, which does not exist in Rev 2.
# Rev 2 3.12.4 has its own row (mapped to 03.15.02), so this row is skipped.
ERRATA = {("3.11.4", "03.12.04")}
R3ID = re.compile(r"03\.(\d\d)[ .](\d\d)")
M = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
TOP = Path(__file__).resolve().parents[1]


def load(source):
    if source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=60) as r:
            data = r.read()
    else:
        data = Path(source).read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != SHA256:
        sys.exit(f"refusing: sha256 {got} is not the pinned NIST file {SHA256}")
    return data


def read_rows(data):
    """Every sheet row as {column letter: text}."""
    z = zipfile.ZipFile(io.BytesIO(data))
    shared = ["".join(t.text or "" for t in si.iter(M + "t"))
              for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall(M + "si")]
    rows = []
    for r in ET.fromstring(z.read(SHEET)).iter(M + "row"):
        d = {}
        for c in r.findall(M + "c"):
            v = c.find(M + "v")
            col = re.sub(r"\d", "", c.get("r"))
            d[col] = "" if v is None else (shared[int(v.text)] if c.get("t") == "s" else v.text)
        rows.append(d)
    return rows


def _lines(text):
    return "\n".join(ln.replace("\t", " ").strip() for ln in text.replace("\r", "").split("\n") if ln.strip())


def _change(r):
    if r.get("O", "").strip() == "X":
        return "withdrawn"
    for col, name in (("J", "no significant change"), ("K", "significant change"), ("L", "minor change")):
        if r.get(col, "").strip() == "X":
            return name
    raise ValueError(f"row for {r.get('C')} / {r.get('G')} has no change type")


def _key(rev2_id):
    return tuple(int(p) for p in rev2_id.split("."))


def convert(rows):
    catalog, crosswalk = [], []
    for r in rows[1:]:
        r2, r3 = r.get("C", "").strip(), r.get("G", "").strip()
        if (r2, r3) in ERRATA:
            continue
        withdrawn = r.get("O", "").strip() == "X"
        if not withdrawn and r3:
            fam, code = FAMILIES[r3[3:5]]
            catalog.append({"id": r3, "family": fam, "family_code": code, "title": r.get("H", "").strip(),
                            "requirement": _lines(r.get("I", ""))})
        if r2:
            if withdrawn:
                note = re.sub(r"^Withdrawn\s+", "", " ".join(_lines(r.get("I", "")).split("\n")))
                note = R3ID.sub(lambda m: f"03.{m.group(1)}.{m.group(2)}", note)
                targets = sorted(set(re.findall(r"03\.\d\d\.\d\d", note)))
            else:
                note, targets = r.get("P", "").strip(), [r3]
            crosswalk.append({"rev2_id": r2, "rev3_ids": " ".join(targets), "change": _change(r), "note": note})
    catalog.sort(key=lambda x: x["id"])
    crosswalk.sort(key=lambda x: _key(x["rev2_id"]))
    return catalog, crosswalk


def write(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    cat, xw = convert(read_rows(load(sys.argv[1] if len(sys.argv) > 1 else URL)))
    (TOP / "rev3").mkdir(exist_ok=True)
    write(TOP / "rev3/catalog.csv", ["id", "family", "family_code", "title", "requirement"], cat)
    write(TOP / "rev3/crosswalk.csv", ["rev2_id", "rev3_ids", "change", "note"], xw)
    print(f"wrote rev3/catalog.csv ({len(cat)} requirements) and rev3/crosswalk.csv ({len(xw)} Rev 2 IDs)")
```

- [ ] **Step 4: Generate the data files**

Run: `cd ~/chp-templates && .venv/bin/python -m tools.import_catalog_r3 "$SCRATCH/nist-r3/analysis.xlsx"`. SCRATCH is this session's scratchpad (`/private/tmp/claude-501/-Users-dshannon/70ba5b3a-b884-4620-8909-fa61db9c207a/scratchpad`); if that file is gone, run with no argument to fetch the URL.
Expected: `wrote rev3/catalog.csv (97 requirements) and rev3/crosswalk.csv (110 Rev 2 IDs)`

If a withdrawn row's note yields a target that isn't in the catalog, or a row has no change type, stop. Look at that row, decide how to handle it, and record the ruling in the ledger.

- [ ] **Step 5: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add tools/import_catalog_r3.py rev3/catalog.csv rev3/crosswalk.csv tests/test_catalog_r3.py
git commit -m "Rev 3 catalog (97 requirements, 17 families) and Rev 2 -> Rev 3 crosswalk (110 IDs) from NIST's pinned change analysis; NIST's 3.11.4 row erratum skipped"
```

---

### Task 3: DoD ODP values, `rev3/defaults.ini`, and the `odp.*` vocabulary

**Files:**
- Create: `rev3/odp-values.csv`, `tools/check_odp_values.py`, `tools/odp_tables.py`, `rev3/defaults.ini`
- Modify: `vocabulary.md` (append a generated block between markers)
- Test: `tests/test_odp_r3.py` (new)

**Interfaces:**
- Produces:
  - `rev3/odp-values.csv` with columns `odp_id,requirement_id,assignment,value,kind`: 80 rows, `kind` is `value` or `guidance` (4 are guidance), and `requirement_id == odp_id[:8]`;
  - `tools.odp_tables.key(odp_id) -> "odp.03_01_01_f_02"`, `defaults_text(rows) -> str` and `vocab_block(rows) -> str`;
  - `rev3/defaults.ini` `[odp]`, with 76 keys (the value rows only);
  - vocabulary rows `odp.<id>`: kind `value`, visibility `public`, meaning `DoD ODP <odp_id> (Rev 3 <requirement_id>): <assignment>`.

- [ ] **Step 1: Write the failing tests**

`tests/test_odp_r3.py`:

```python
import csv
from pathlib import Path

from render.chpfill import load_vocabulary
from tools.odp_tables import defaults_text, key, vocab_block

TOP = Path(__file__).resolve().parents[1]
ROWS = list(csv.DictReader(open(TOP / "rev3/odp-values.csv", encoding="utf-8")))
CAT = {r["id"] for r in csv.DictReader(open(TOP / "rev3/catalog.csv", encoding="utf-8"))}


def test_eighty_odps_over_fifty_requirements_four_guidance():
    ids = [r["odp_id"] for r in ROWS]
    assert len(ids) == 80 and len(set(ids)) == 80
    assert len({r["requirement_id"] for r in ROWS}) == 50
    assert sum(r["kind"] == "guidance" for r in ROWS) == 4 and {r["kind"] for r in ROWS} == {"value", "guidance"}
    for r in ROWS:
        assert r["requirement_id"] == r["odp_id"][:8] and r["requirement_id"] in CAT
        assert r["assignment"].startswith(("[Assignment:", "[Selection")) and r["assignment"].endswith("]")
        assert r["value"].strip() and "significant1" not in r["value"]


def test_key_form():
    assert key("03.01.01.f.02") == "odp.03_01_01_f_02" and key("03.04.06.b") == "odp.03_04_06_b"


def test_defaults_file_is_generated_from_the_values():
    assert (TOP / "rev3/defaults.ini").read_text() == defaults_text(ROWS)
    text = defaults_text(ROWS)
    assert "\n[odp]\n" in text and "03_01_01_f_02 = at most 90 days\n" in text
    assert sum(1 for ln in text.split("\n") if " = " in ln and not ln.startswith("#")) == 76


def test_vocabulary_has_every_odp_once_as_public():
    voc = (TOP / "vocabulary.md").read_text()
    assert vocab_block(ROWS) in voc
    v = load_vocabulary(TOP / "vocabulary.md")
    for r in ROWS:
        assert v[key(r["odp_id"])]["visibility"] == "public" and v[key(r["odp_id"])]["kind"] == "value"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_odp_r3.py`
Expected: an ERROR at import (`tools.odp_tables` missing).

- [ ] **Step 3: Write the checker `tools/check_odp_values.py`**

```python
# CyberHygiene Project — chp-templates (shared SSP and POA&M templates).
# Licensed under the Apache License 2.0. Placeholder templates only: no site's values belong in this repository.
"""check_odp_values.py MEMO.pdf [--show]: check rev3/odp-values.csv against the DoD ODP memo (developer tool; needs
pdftotext). The memo's sha256 must match the pinned copy. Every memo ODP ID must be in the CSV exactly once; each row's
assignment and value words must appear, in order, in that ID's table row; the guidance count must match the memo."""
import csv
import hashlib
import re
import subprocess
import sys
from pathlib import Path

SHA256 = "fd83ecf4e0998f0b29d5e6f222e7364ce67eb6fdedb5ac4f34ec4310ba495916"
TOP = Path(__file__).resolve().parents[1]
ROW_ID = re.compile(r"^\s*(03\.\d\d\.\d\d(?:\.[a-z0-9]+)*)\s")


def words(text):
    return re.sub(r"significant1", "significant", text).replace("[", " [ ").replace("]", " ] ").split()


def in_order(needle, hay):
    it = iter(hay)
    return all(w in it for w in needle)


def windows(lines):
    """{odp_id: the table lines from just after the previous row to just before the next one}."""
    marks = [(i, m.group(1)) for i, ln in enumerate(lines) if (m := ROW_ID.match(ln)) and "(" not in ln[:20]]
    out = {}
    for n, (i, oid) in enumerate(marks):
        start = marks[n - 1][0] + 1 if n else max(0, i - 15)
        end = marks[n + 1][0] if n + 1 < len(marks) else i + 15
        out[oid] = lines[start:end]
    return out


def check(pdf, show=False):
    data = Path(pdf).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        return ["memo: sha256 is not the pinned copy"]
    text = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True, check=True).stdout
    lines = text.split("\n")
    memo_ids = set(re.findall(r"\((03\.\d\d\.\d\d[^)\s]*)\)", text))
    rows = list(csv.DictReader(open(TOP / "rev3/odp-values.csv", encoding="utf-8")))
    ids = [r["odp_id"] for r in rows]
    bad = [f"duplicate {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    bad += [f"missing from CSV: {i}" for i in sorted(memo_ids - set(ids))]
    bad += [f"not in memo: {i}" for i in sorted(set(ids) - memo_ids)]
    if sum(r["kind"] == "guidance" for r in rows) != text.count("Guidance:"):
        bad.append("guidance count differs from the memo")
    win = windows(lines)
    for r in rows:
        w = win.get(r["odp_id"])
        if w is None:
            bad.append(f"{r['odp_id']}: no table row found")
            continue
        hay = words(" ".join(w))
        for field in ("assignment", "value"):
            if not in_order(words(r[field]), hay):
                bad.append(f"{r['odp_id']}: {field} words not found in order in its table row")
        if show:
            print(f"== {r['odp_id']} [{r['kind']}]\n  CSV:  {r['value']}\n  MEMO: {' '.join(' '.join(w).split())}")
    return bad


if __name__ == "__main__":
    problems = check(sys.argv[1], "--show" in sys.argv)
    print("\n".join(problems) if problems else f"ODP OK: rev3/odp-values.csv matches the DoD memo")
    sys.exit(1 if problems else 0)
```

Note: `windows()` uses the walrus operator. The tools are developer-side, but keep 3.9-compatible syntax anyway (the walrus is 3.8+, which is fine).

- [ ] **Step 4: Transcribe `rev3/odp-values.csv` from the memo**

Extract the memo text into the scratchpad with `pdftotext -layout "<memo>" "$SCRATCH/nist-r3/dod-odp.txt"`. Draft the CSV with a throwaway script in the scratchpad (never committed). It reads each "ODP Values" table and joins each cell's wrapped lines. Then correct every row by hand against the memo.

Rules:
- `odp_id` is the memo's ID exactly, e.g. `03.01.01.f.02`.
- `assignment` is the memo's "ODP Assignment Text" in square brackets, joined onto one line.
- `value` is the memo's "ODP Value" joined onto one line. Drop the footnote marker in `significant1`, writing `significant`.
- For the 4 guidance rows, use `kind=guidance` and `value` = the guidance text, starting at "Guidance:".
- File order is memo order (= id order). Write with `csv` (quote as needed), with `\n` line endings.

Then run: `.venv/bin/python -m tools.check_odp_values "$HOME/rag-library/documents-sysadmin/2026-10/DOD 800-171 ODP guidance.pdf" --show > "$SCRATCH/odp-show.txt"; echo $?`
Expected: exit 0, and the last line is `ODP OK: rev3/odp-values.csv matches the DoD memo`.

Then read all of `odp-show.txt` and compare each CSV value with its MEMO line. The checker proves that the words exist in order; you must also confirm that **nothing was dropped**: no row is missing the end of its value, and none took words from the next row. Fix the CSV and re-run until both checks hold.

If the checker reports footnote markers other than `significant1`, extend `words()` for the specific marker and record a ruling.

- [ ] **Step 5: Implement `tools/odp_tables.py` and generate the defaults and vocabulary**

```python
# CyberHygiene Project — chp-templates (shared SSP and POA&M templates).
# Licensed under the Apache License 2.0. Placeholder templates only: no site's values belong in this repository.
"""odp_tables.py: generate rev3/defaults.ini and vocabulary.md's ODP block from rev3/odp-values.csv."""
import csv
import re
from pathlib import Path

TOP = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- odp:begin (generated by tools/odp_tables.py; do not edit) -->", "<!-- odp:end -->"


def key(odp_id):
    return "odp." + odp_id.replace(".", "_")


def defaults_text(rows):
    out = ["# Default organization-defined parameter (ODP) values for the Rev 3 library: the DoD values from",
           "# \"Department of Defense Organization-Defined Parameters for NIST SP 800-171 Revision 3\" (memo signed",
           "# April 10, 2025, Attachment A). A site confirms or changes each one in its profile.ini [odp] section; until",
           "# then the document marks it \"(default, not yet confirmed)\". The four ODPs that DoD defines as guidance",
           "# have no default here: the site sets them, and the fill-in report lists them.", "", "[odp]"]
    for r in rows:
        if r["kind"] == "value":
            out += [f"# {r['odp_id']} {r['assignment']}", f"{key(r['odp_id'])[4:]} = {r['value']}"]
    return "\n".join(out) + "\n"


def vocab_block(rows):
    lines = [BEGIN, "", "Rev 3 organization-defined parameters. The key is the DoD memo's part ID with the dots written",
             "as underscores. The DoD value is the Rev 3 library's default (`rev3/defaults.ini`).", "",
             "| placeholder | kind | visibility | meaning |", "|---|---|---|---|"]
    lines += [f"| `{key(r['odp_id'])}` | value | public | DoD ODP {r['odp_id']} (Rev 3 {r['requirement_id']}): "
              f"{r['assignment']} |" for r in rows]
    return "\n".join(lines + ["", END]) + "\n"


def rows():
    return list(csv.DictReader(open(TOP / "rev3/odp-values.csv", encoding="utf-8")))


if __name__ == "__main__":
    rs = rows()
    (TOP / "rev3/defaults.ini").write_text(defaults_text(rs), encoding="utf-8")
    voc = (TOP / "vocabulary.md").read_text(encoding="utf-8")
    block = vocab_block(rs)
    voc = (re.sub(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n", lambda _: block, voc, flags=re.S)
           if BEGIN in voc else voc.rstrip("\n") + "\n\n" + block)
    (TOP / "vocabulary.md").write_text(voc, encoding="utf-8")
    print(f"wrote rev3/defaults.ini ({sum(r['kind'] == 'value' for r in rs)} defaults) and vocabulary.md ODP block")
```

Before generating, check that `load_vocabulary` reads a second table: its `VOCAB_ROW` regex matches any `| `x` | kind | vis | meaning |` line, and it skips the header row by name. A meaning containing `|` would break the row. Assignment texts have none; if the checker found one, stop and record a ruling.

Run: `.venv/bin/python -m tools.odp_tables`
Expected: `wrote rev3/defaults.ini (76 defaults) and vocabulary.md ODP block`

- [ ] **Step 6: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass, including `test_vocabulary.py` (every vocabulary row is well-formed) and `test_nothing_real.py`.

- [ ] **Step 7: Commit**

```bash
git add rev3/odp-values.csv rev3/defaults.ini tools/check_odp_values.py tools/odp_tables.py vocabulary.md tests/test_odp_r3.py
git commit -m "Rev 3 ODPs: the 80 DoD values (memo signed 04/10/2025) checked against the pinned memo; 76 defaults in rev3/defaults.ini [odp]; odp.* keys added to vocabulary.md (owner decision 2026-10-26)"
```

---

### Task 4: The 97 `pending` Rev 3 control blocks

**Files:**
- Create: `tools/gen_rev3_blocks.py`, `rev3/templates/ssp/controls/<id>.md` (97 files)
- Test: `tests/test_controls_r3.py` (new)

**Interfaces:**
- Consumes: `rev3/catalog.csv` and `rev3/crosswalk.csv` (Task 2), `rev3/odp-values.csv` and `tools.odp_tables.key` (Task 3).
- Produces: `tools.gen_rev3_blocks.block_text(cid, rev2_basis, odps) -> str`, `rev2_basis(crosswalk) -> {rev3_id: (primary list, also list)}` and `main(force=False)`. `main` writes only missing files; blocks are hand-edited in later batches.

The block format is:

```
<!-- chp:control id=03.01.01 status=pending evidence= -->
**Implementation:** Pending. This requirement is not yet proven on the Rev 3 reference implementation, so this library does not yet describe the appliance's implementation.

**Rev 2 basis:** 3.1.1. For the appliance's implementation today, see the Rev 2 plan's narrative for 3.1.1.

**Organization-defined parameters** (the DoD values are the defaults until the site confirms them):

- `03.01.01.f.02` [Assignment: organization-defined time period]: {{odp.03_01_01_f_02}}

**Site responsibility:** Describe how the site meets this requirement until this library's Rev 3 text is written.
```

- The parameters paragraph and its list appear only when the requirement has ODPs.
- A guidance ODP line ends with ` *DoD gives guidance, not a value: <guidance text without the leading "Guidance: ">*`.
- The Rev 2 basis line has three forms:
  - one Rev 2 basis ID: `**Rev 2 basis:** 3.1.1. For the appliance's implementation today, see the Rev 2 plan's narrative for 3.1.1.`
  - several primary IDs and/or withdrawn ones it absorbs: `**Rev 2 basis:** 3.1.12; it also covers withdrawn 3.1.13, 3.1.14, 3.1.15. For the appliance's implementation today, see the Rev 2 plan's narratives for those requirements.`
  - none: `**Rev 2 basis:** none; this requirement is new in Rev 3.`
- "Primary" Rev 2 IDs are crosswalk rows whose `change` is not `withdrawn` and whose `rev3_ids` is this ID. "Also" IDs are withdrawn rows that list this ID. Both lists are in Rev 2 order.

- [ ] **Step 1: Write the failing tests**

`tests/test_controls_r3.py`:

```python
import csv
import re
from pathlib import Path

import pytest
from render.chpfill import TOKEN, load_vocabulary, vocab_entry
from tools.gen_rev3_blocks import block_text, main, rev2_basis
from tools.odp_tables import key

TOP = Path(__file__).resolve().parents[1]
CTRL = TOP / "rev3/templates/ssp/controls"
HEAD = re.compile(r"^<!-- chp:control id=(\S+) status=(appliance|site|partial|pending) evidence=(\S*) -->\n")
IDS = [r["id"] for r in csv.DictReader(open(TOP / "rev3/catalog.csv", encoding="utf-8"))]
XW = list(csv.DictReader(open(TOP / "rev3/crosswalk.csv", encoding="utf-8")))
ODP = list(csv.DictReader(open(TOP / "rev3/odp-values.csv", encoding="utf-8")))


def test_one_block_per_rev3_requirement():
    assert sorted(p.stem for p in CTRL.glob("*.md")) == sorted(IDS)


@pytest.mark.parametrize("cid", IDS)
def test_block_header_odps_and_vocabulary(cid):
    text = (CTRL / f"{cid}.md").read_text()
    m = HEAD.match(text)
    assert m and m.group(1) == cid
    if m.group(2) in ("appliance", "partial"):
        assert m.group(3), "appliance/partial must cite evidence"
    if m.group(2) == "pending":
        assert m.group(3) == "" and "not yet proven" in text and "**Site responsibility:** " in text
    used = {t.group(1) for t in TOKEN.finditer(text) if t.group(1).startswith("odp.")}
    assert used == {key(r["odp_id"]) for r in ODP if r["requirement_id"] == cid}
    v = load_vocabulary(TOP / "vocabulary.md")
    assert all(vocab_entry(t.group(1), v) for t in TOKEN.finditer(text))


def test_guidance_odps_quote_dod_guidance():
    for r in (r for r in ODP if r["kind"] == "guidance"):
        text = (CTRL / f"{r['requirement_id']}.md").read_text()
        line = next(ln for ln in text.split("\n") if f"{{{{{key(r['odp_id'])}}}}}" in ln)
        assert "*DoD gives guidance, not a value: " in line


def test_rev2_basis_lines_follow_the_crosswalk():
    basis = rev2_basis(XW)
    assert basis["03.01.12"] == (["3.1.12"], ["3.1.13", "3.1.14", "3.1.15"])
    assert basis["03.15.02"][0] == ["3.12.4"]
    assert "3.11.4" not in str(basis)
    assert basis.get("03.04.10", ([], [])) == ([], [])                  # new in Rev 3
    assert "**Rev 2 basis:** none; this requirement is new in Rev 3." in (CTRL / "03.04.10.md").read_text()
    assert "**Rev 2 basis:** 3.1.1. " in (CTRL / "03.01.01.md").read_text()


def test_block_text_exact_form():
    t = block_text("03.09.09", ([], []), [])
    assert t == ("<!-- chp:control id=03.09.09 status=pending evidence= -->\n"
                 "**Implementation:** Pending. This requirement is not yet proven on the Rev 3 reference implementation, "
                 "so this library does not yet describe the appliance's implementation.\n\n"
                 "**Rev 2 basis:** none; this requirement is new in Rev 3.\n\n"
                 "**Site responsibility:** Describe how the site meets this requirement until this library's Rev 3 text "
                 "is written.\n")


def test_generator_never_overwrites_a_block(tmp_path, monkeypatch):
    import tools.gen_rev3_blocks as g
    monkeypatch.setattr(g, "CTRL", tmp_path)
    (tmp_path / "03.01.01.md").write_text("hand edited\n")
    main()
    assert (tmp_path / "03.01.01.md").read_text() == "hand edited\n"
    assert len(list(tmp_path.glob("*.md"))) == 97
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_controls_r3.py`
Expected: an ERROR at import (`tools.gen_rev3_blocks` missing).

- [ ] **Step 3: Implement `tools/gen_rev3_blocks.py`**

```python
# CyberHygiene Project — chp-templates (shared SSP and POA&M templates).
# Licensed under the Apache License 2.0. Placeholder templates only: no site's values belong in this repository.
"""gen_rev3_blocks.py: write a 'pending' Rev 3 control block for every catalog requirement that has none. Existing
blocks are never touched: later batches edit them by hand as the Rev 3 reference implementation proves each control."""
import csv
from pathlib import Path

from tools.odp_tables import key

TOP = Path(__file__).resolve().parents[1]
CTRL = TOP / "rev3/templates/ssp/controls"


def _csv(name):
    return list(csv.DictReader(open(TOP / "rev3" / name, encoding="utf-8")))


def rev2_basis(crosswalk):
    out = {}
    for r in crosswalk:
        for t in r["rev3_ids"].split():
            prim, also = out.setdefault(t, ([], []))
            (also if r["change"] == "withdrawn" else prim).append(r["rev2_id"])
    return out


def _basis_line(primary, also):
    if not primary and not also:
        return "**Rev 2 basis:** none; this requirement is new in Rev 3."
    if len(primary) == 1 and not also:
        return (f"**Rev 2 basis:** {primary[0]}. For the appliance's implementation today, see the Rev 2 plan's "
                f"narrative for {primary[0]}.")
    head = ", ".join(primary) if primary else "none directly"
    tail = f"; it also covers withdrawn {', '.join(also)}" if also else ""
    return (f"**Rev 2 basis:** {head}{tail}. For the appliance's implementation today, see the Rev 2 plan's narratives "
            "for those requirements.")


def block_text(cid, basis, odps):
    parts = [f"<!-- chp:control id={cid} status=pending evidence= -->\n"
             "**Implementation:** Pending. This requirement is not yet proven on the Rev 3 reference implementation, "
             "so this library does not yet describe the appliance's implementation.",
             _basis_line(*basis)]
    if odps:
        lines = ["**Organization-defined parameters** (the DoD values are the defaults until the site confirms them):", ""]
        for r in odps:
            ln = f"- `{r['odp_id']}` {r['assignment']}: {{{{{key(r['odp_id'])}}}}}"
            if r["kind"] == "guidance":
                ln += f" *DoD gives guidance, not a value: {r['value'].replace('Guidance:', '', 1).strip()}*"
            lines.append(ln)
        parts.append("\n".join(lines))
    parts.append("**Site responsibility:** Describe how the site meets this requirement until this library's Rev 3 "
                 "text is written.")
    return "\n\n".join(parts) + "\n"


def main(force=False):
    CTRL.mkdir(parents=True, exist_ok=True)
    basis, odps, wrote = rev2_basis(_csv("crosswalk.csv")), _csv("odp-values.csv"), 0
    for r in _csv("catalog.csv"):
        p = CTRL / f"{r['id']}.md"
        if p.exists() and not force:
            continue
        p.write_text(block_text(r["id"], basis.get(r["id"], ([], [])),
                                [o for o in odps if o["requirement_id"] == r["id"]]), encoding="utf-8")
        wrote += 1
    return wrote


if __name__ == "__main__":
    print(f"wrote {main()} pending Rev 3 control blocks")
```

Do not expose `force` on the command line. It exists only so that tests can regenerate into a temporary folder.

- [ ] **Step 4: Generate the blocks**

Run: `.venv/bin/python -m tools.gen_rev3_blocks`
Expected: `wrote 97 pending Rev 3 control blocks`

Read three generated blocks:
- `03.01.01` (6 ODPs);
- `03.04.06` (a guidance ODP);
- `03.15.02` (basis 3.12.4).

Each must read as plain English.

- [ ] **Step 5: Run the tests and the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add tools/gen_rev3_blocks.py rev3/templates/ssp/controls tests/test_controls_r3.py
git commit -m "Rev 3: 97 pending control blocks (no Rev 3 walk on the reference implementation yet), each with its Rev 2 basis and its DoD ODPs"
```

---

### Task 5: Rev 3 SSP frame, architecture text and POA&M; update Rev 2 POA&M T-06

**Files:**
- Create: `rev3/templates/ssp/frame.md`, `rev3/templates/ssp/arch/chp-appliance.md`, `rev3/templates/poam/frame.md`, `tests/fixtures/example-profile-r3.ini`, `tests/golden-r3/{ssp.md,poam.md,fill-report.md}`
- Modify: `rev2/templates/poam/frame.md` (T-06 row), `tests/golden/poam.md` (regenerated)
- Test: `tests/test_frame_r3.py` (new); extend `tests/test_golden.py`

**Interfaces:**
- Consumes: Task 1's renderer, Tasks 2–4's files, and the crosswalk for the seeded POA&M IDs.
- Produces: a complete `rev3/` that `chpfill.py fill --lib rev3` renders.

- [ ] **Step 1: Write the failing tests**

`tests/test_frame_r3.py`:

```python
import csv
import re
from pathlib import Path

from render.chpfill import TOKEN, load_vocabulary, vocab_entry

TOP = Path(__file__).resolve().parents[1]
FRAME = (TOP / "rev3/templates/ssp/frame.md").read_text()
POAM = (TOP / "rev3/templates/poam/frame.md").read_text()
XW = {r["rev2_id"]: r["rev3_ids"].split() for r in csv.DictReader(open(TOP / "rev3/crosswalk.csv"))}
ORDER = ["## DOCUMENT CONTROL", "## EXECUTIVE SUMMARY", "## 2. SYSTEM IDENTIFICATION", "## 3. SYSTEM DESCRIPTION",
         "## 4. SECURITY CONTROL IMPLEMENTATION", "## 5. CONTINGENCY PLANNING (CP)", "## 6. SECURITY POLICIES AND PROCEDURES",
         "## 10. PLAN OF ACTION AND MILESTONES (POA&M)", "## 11. IMPLEMENTATION METRICS", "## 12. CONCLUSION",
         "## AUTHORIZATION", "## APPENDICES"]


def test_same_fixed_layouts_as_rev2():
    pos = [FRAME.index(h + "\n") for h in ORDER]
    assert pos == sorted(pos)
    assert "| Version | Date | Author | Description |\n|:---|:---|:---|:---|\n" in FRAME
    assert "{{assessment.sprs_score}}" in FRAME and "| **Strict 800-171A objectives met** |" in FRAME
    assert "**{{assessment.objectives_met}}/97**" in FRAME
    for inc in ("{{> arch}}", "{{> controls}}", "{{> family_status}}"):
        assert FRAME.count(inc) == 1
    assert FRAME.rstrip().endswith("*Add further lettered appendices below; nothing reads their order.*")


def test_frame_is_rev3_and_explains_pending_and_odps():
    assert "## NIST SP 800-171 Rev 3 Compliance" in FRAME and "/110" not in FRAME
    assert "- **pending:**" in FRAME and "April 10, 2025" in FRAME
    assert len(re.findall(r"Rev 2", FRAME)) == len(re.findall(r"Rev 2 basis|CMMC Level 2 assessments use Rev 2", FRAME))


def test_every_placeholder_is_in_the_vocabulary():
    v = load_vocabulary(TOP / "vocabulary.md")
    for text in (FRAME, POAM, (TOP / "rev3/templates/ssp/arch/chp-appliance.md").read_text()):
        assert all(vocab_entry(m.group(1), v) for m in TOKEN.finditer(text))


def test_poam_seeds_use_the_crosswalk():
    rows = [ln for ln in POAM.split("\n") if ln.startswith("| T-")]
    assert [r.split(" | ")[0] for r in rows] == ["| T-01", "| T-02", "| T-03", "| T-04", "| T-05", "| T-07"]
    seeds = {"T-01": ["3.10.4"], "T-02": ["3.13.11", "3.5.10"], "T-03": ["3.8.6"],
             "T-04": ["3.1.10", "3.1.11", "3.13.9"], "T-05": ["3.5.6", "3.5.8"], "T-07": ["3.4.3"]}
    for r in rows:
        cells = [c.strip() for c in r.strip("|").split("|")]
        assert cells[1] == "Rev 3"
        want = sorted({t for r2 in seeds[cells[0]] for t in XW[r2]})
        assert cells[2] == ", ".join(want), cells[0]
    assert "T-06" in POAM and "0.2.0-update3" in POAM


def test_rev2_t06_says_closed_by_update3():
    t06 = next(ln for ln in (TOP / "rev2/templates/poam/frame.md").read_text().split("\n") if ln.startswith("| T-06"))
    assert "0.2.0-update3" in t06 and "still denied" in t06
```

In `tests/test_golden.py`, generalise `render(tmp_path)` to `render(tmp_path, lib="rev2", profile="example-profile.ini")`. Add:

```python
def test_rev3_golden_render_matches_the_snapshot(tmp_path):
    out = render(tmp_path, "rev3", "example-profile-r3.ini")
    for name in ("ssp.md", "poam.md", "fill-report.md"):
        assert (out / name).read_text() == (TOP / "tests/golden-r3" / name).read_text(), f"{name} differs"
    report = (out / "fill-report.md").read_text()
    assert report.count("`odp.") == 75 + 4         # 75 defaults listed (03.01.01.f.02 confirmed), 4 guidance unfilled
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_frame_r3.py tests/test_golden.py`
Expected: FAIL / ERROR: the rev3 frame and the POA&M are missing, and the T-06 text is old.

- [ ] **Step 3: Write the Rev 3 frame**

Copy `rev2/templates/ssp/frame.md` to `rev3/templates/ssp/frame.md`, then make exactly these edits:
1. Line 3: `## NIST SP 800-171 Rev 3 Compliance`.
2. The SPRS row's definition becomes: `The DoD Assessment Methodology score, on the basis the site's contracts require. Assessed {{assessment.sprs_date}}. **Basis:** {{assessment.sprs_basis}}`.
3. The objectives row: `SP 800-171A` becomes `SP 800-171A Rev 3`, and `/110` becomes `/97`.
4. In 1.3:
   - replace the Rev 2 bullet with `- NIST SP 800-171 Rev 3: Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations`;
   - add after it `- DoD Organization-Defined Parameters for NIST SP 800-171 Revision 3 (memo signed April 10, 2025)`;
   - after the bullet list, add the paragraph `At the time of this template, CMMC Level 2 assessments use Rev 2. Check which revision each contract requires; this plan prepares the system for Rev 3.`
5. Supporting standards: `NIST SP 800-53 Rev 5 and NIST SP 800-171A Rev 3.`
6. Section 4's status list gains the item `- **pending:** the library's Rev 3 text is not yet written, because the control is not yet proven on the Rev 3 reference implementation; until then the site describes its own implementation.` Add after the list: `Each requirement lists its organization-defined parameters. The DoD values are the defaults, marked *(default, not yet confirmed)* until the site confirms or changes them in profile.ini's [odp] section. Each requirement also names its Rev 2 basis.`
7. Appendix B: the Rev 2 bullet becomes Rev 3. `SP 800-171A` becomes `NIST SP 800-171A Rev 3, Assessing Security Requirements for Controlled Unclassified Information`. Add `- DoD Organization-Defined Parameters for NIST SP 800-171 Revision 3 (memo signed April 10, 2025)`.
8. Appendix E: keep the heading. Replace the table with: `Rev 3's organization-defined parameters are stated with each requirement in Section 4. The site's other decisions:`, followed by the table rows for `review_cycle_months`, `backup_frequency` and `restore_test_frequency` only. Rev 3 ODPs replace the other rows; they are not mixed into `decision.*`. Use the Rev 2 table's two-column layout with the labels `Review cycle (months)`, `Backup frequency` and `Restore test frequency`.

Then run `grep -n "Rev 2" rev3/templates/ssp/frame.md`. Each hit must be either the CMMC sentence or a "Rev 2 basis" mention, as the test pins.

- [ ] **Step 4: Architecture text and POA&M**

- `rev3/templates/ssp/arch/chp-appliance.md`: copy the Rev 2 file unchanged. The architecture is the same, and grep showed it has no revision-specific text.
- `rev3/templates/poam/frame.md`: copy the Rev 2 POA&M, then:
  - change `## NIST SP 800-171 Rev 2` to `Rev 3`;
  - in each seeded row, set the Revision cell to `Rev 3`. Set the Requirement cell to the sorted, comma-separated Rev 3 IDs that the crosswalk gives for the row's Rev 2 IDs; the test computes the expected value (read them from `rev3/crosswalk.csv`);
  - delete row T-06, and after the table add: `T-06 (the fapolicyd SELinux denials) is not seeded: appliance update 0.2.0-update3 silences them, and the access is still denied.`
- `rev2/templates/poam/frame.md` T-06: replace its Weakness cell with: `SELinux denials were logged when fapolicyd looked up local accounts at the identity client's socket. Appliance update 0.2.0-update3 silences them; the access is still denied, and no access is lost. *Seeded by the template: confirm, adapt or close.*` Replace its Milestones cell with: `Apply update 0.2.0-update3 and close this item with that reason.`

- [ ] **Step 5: Golden fixtures**

- `tests/fixtures/example-profile-r3.ini`: copy `example-profile.ini`, and add one ODP confirmation to show the override: `[odp]` with `03_01_01_f_02 = at most 90 days`.
- Regenerate the snapshots:

```bash
.venv/bin/python render/chpfill.py fill --lib rev3 --profile tests/fixtures/example-profile-r3.ini --out "$SCRATCH/g3" --templates-version 1.0.0 && mkdir -p tests/golden-r3 && cp "$SCRATCH/g3/"*.md tests/golden-r3/
.venv/bin/python render/chpfill.py fill --lib rev2 --profile tests/fixtures/example-profile.ini --out "$SCRATCH/g2" --templates-version 1.0.0 && cp "$SCRATCH/g2/poam.md" tests/golden/poam.md
git diff --stat tests/golden
```

Expected: only `tests/golden/poam.md` changes, and only on the T-06 row.

Read the Rev 3 `ssp.md` around 03.01.01, 03.04.06 and the 4.15–4.17 family headings, and check the Control Family Status table has 17 rows plus TOTAL 97. In `fill-report.md`, check the four guidance ODPs are listed as unfilled and `odp.03_01_01_f_02` is NOT listed as a default.

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add rev3/templates tests/test_frame_r3.py tests/test_golden.py tests/fixtures/example-profile-r3.ini tests/golden-r3 tests/golden/poam.md rev2/templates/poam/frame.md
git commit -m "Rev 3 SSP frame (03.xx families, ODPs, pending) and POA&M (seeds crosswalked, T-06 closed by 0.2.0-update3); Rev 2 POA&M T-06 updated; Rev 3 golden render"
```

---

### Task 6: Manifests, release plumbing, README and release notes

**Files:**
- Create: `rev3/MANIFEST.json`, `RELEASE-NOTES-1.3.0.md`
- Modify: `tools/release.sh` (verify both libraries), `tests/test_manifest.py`, `tests/test_nothing_real.py` (allow `dodcio.defense.gov`), `README.md`, `rev2/MANIFEST.json` (rebuilt for the T-06 change, content version 1.2.1)
- Test: `tests/test_manifest.py`, `tests/test_release_static.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_manifest.py`:

```python
def test_rev3_manifest_matches_its_library():
    lib = TOP / "rev3"
    m = json.loads((lib / "MANIFEST.json").read_text())
    assert m["library"] == "rev3" and m["content_version"] == "0.1.0" and verify(lib) == []
    ctrl = [f for f in m["files"] if f["path"].startswith("templates/ssp/controls/")]
    assert len(ctrl) == 97 and {f["status"] for f in ctrl} == {"pending"}


def test_rev2_content_version_moved_for_t06():
    assert json.loads((LIB / "MANIFEST.json").read_text())["content_version"] == "1.2.1"
```

In `tests/test_release_static.py`, add an assertion that `tools/release.sh` contains `for lib in ("rev2", "rev3")`. Run `grep -n "def test" tests/test_release_static.py` first, and follow its existing style.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_manifest.py tests/test_release_static.py`
Expected: FAIL. rev3 has no MANIFEST, rev2 is still 1.2.0 (stale after T-06), and release.sh verifies rev2 only.

- [ ] **Step 3: Implement**

```bash
.venv/bin/python -m tools.build_manifest rev2 1.2.1
.venv/bin/python -m tools.build_manifest rev3 0.1.0
sed -i '' 's/for lib in ("rev2",)/for lib in ("rev2", "rev3")/' tools/release.sh
```

If `-m tools.build_manifest` fails because of how its `__main__` reads its paths, run `.venv/bin/python tools/build_manifest.py rev3 0.1.0` from the repo root instead.

In `tests/test_nothing_real.py`, add `"dodcio.defense.gov"` to `ALLOWED_DOMAINS`.

`README.md`:
- In the layout table, change the `rev3/` row to `the self-contained **Rev 3** library: NIST's Rev 3 catalog, the Rev 2 → Rev 3 crosswalk, the DoD ODP values as defaults; every control block is *pending* until the Rev 3 reference implementation proves it`.
- Under "Filling the templates", add one line: `Use --lib rev3 for the Rev 3 plan. Its organization-defined parameters go in profile.ini's [odp] section, keyed by the DoD memo's part ID with dots as underscores (e.g. 03_01_01_f_02).`

`RELEASE-NOTES-1.3.0.md`:

```markdown
# chp-templates 1.3.0: release notes

**Released:** October 2026 · **Additive; replaces 1.2.0 as current.**

## The Rev 3 library (first batch)

- **NIST SP 800-171 Rev 3 catalog:** 97 requirements in 17 families, from NIST's Rev 2 to Rev 3 change analysis
  (pinned by sha256).
- **Rev 2 → Rev 3 crosswalk** (`rev3/crosswalk.csv`): every Rev 2 ID, its Rev 3 ID(s), and the type of change. NIST's
  workbook labels one withdrawn row "3.11.4", an ID that Rev 2 does not have; that row is skipped, and 3.12.4 maps to
  03.15.02.
- **DoD organization-defined parameters:** the 80 values from DoD's memo signed April 10, 2025. 76 are the library's
  defaults, marked *(default, not yet confirmed)* until a site confirms them. The other 4 are guidance, so the site
  sets them.
- **Every Rev 3 control block is *pending*.** The Rev 3 reference implementation has not yet been assessed, so the
  library does not yet describe the appliance's Rev 3 implementation. Each block names its Rev 2 basis and its
  parameters, and puts the site in charge until the text is written. Narratives come in later releases.
- **A Rev 3 SSP and POA&M,** laid out by the 03.xx families, with the same fixed layouts as Rev 2.

## New placeholders (Automated_Compliance)

- `odp.<part id>`, e.g. `odp.03_01_01_f_02`, in a new `[odp]` section: one per DoD ODP, all public. They are
  separate from the `decision.*` names. Nothing was renamed or removed.

## Rev 2 change

- **POA&M T-06** now says that appliance update 0.2.0-update3 silences the fapolicyd SELinux denials (the access is
  still denied), so a site on that update closes it. Rev 2 content version 1.2.1.

## Verifying this release

1. Check `SHA256SUMS.asc` against the project release key, `2DE0D71BF37D8F5E4201A590521276F43C908F8E`.
2. Run `shasum -a 256 -c SHA256SUMS`.
```

- [ ] **Step 4: Run the full suite and the scan**

Run: `.venv/bin/python -m pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add rev2/MANIFEST.json rev3/MANIFEST.json tools/release.sh tests/test_manifest.py tests/test_release_static.py tests/test_nothing_real.py README.md RELEASE-NOTES-1.3.0.md
git commit -m "Manifests (rev2 1.2.1, rev3 0.1.0), release script verifies both libraries, README and release notes for 1.3.0"
```

---

### Task 7: Spec amendment, final review, PR, release

**Files:**
- Modify: `~/idm-assistant/docs/superpowers/specs/2026-10-24-chp-templates-design.md` (one new subsection), and memory

- [ ] **Step 1: Amend the spec** (in idm-assistant, on a branch `c2-spec-amendment`)

Add after §1's decisions table:

```markdown
### Decisions of 2026-10-26 (owner, Plan C2)

| Topic | Decision |
|---|---|
| First Rev 3 release | **Scaffold first.** The Rev 3 reference implementation has had no Rev 3 walk, so every Rev 3 block is `pending`. Narratives come in later batches. |
| ODP names | **`odp.<memo part id, dots as underscores>`** (e.g. `odp.03_01_01_f_02`) in a new `[odp]` section, never mixed into `decision.*`. The DoD memo's IDs are authoritative (80 ODPs; NIST's OSCAL splits some differently). |
| Rev 3 SSP layout | **Keyed to the 03.xx families,** with the same fixed layouts as Rev 2, because Rev 3 defines no separate SSP structure. |
```

Commit with the attribution lines.

- [ ] **Step 2: Final review.** Run the executing-plans final review: a fresh reviewer on the most capable model, given this plan, the spec, the ledger rulings and the Review Focus. Then do one fix pass for Critical and Important findings.

- [ ] **Step 3: Pre-publication scan.** Scan `git diff main..c2-rev3-scaffold` in chp-templates for:
  - secrets or keys;
  - real names (`shannon`, `diwai`, `cyberinabox`, `contract-coach`);
  - IP addresses, and email addresses other than `example.test`;
  - any diwai fact.

  `test_nothing_real.py` already covers most of this; read its result and grep the diff.

- [ ] **Step 4: Push and open PRs** (owner merges)

```bash
cd ~/chp-templates && git push -u origin c2-rev3-scaffold && gh pr create --base main --head c2-rev3-scaffold --title "Plan C2 batch 1: the Rev 3 scaffold (1.3.0)" --body "<summary + test count + attribution>"
cd ~/idm-assistant && git push -u origin c2-spec-amendment && gh pr create --base main --head c2-spec-amendment --title "Spec: Plan C2 owner decisions (2026-10-26)" --body "<summary + attribution>"
```

- [ ] **Step 5: After the owner merges:** tag and release.
  - Run `git checkout main && git pull && git tag templates-1.3.0 && git push origin templates-1.3.0`.
  - Ask the owner for "go", explain the key touch, then run `V=1.3.0 bash tools/release.sh`.
  - Expected: `RELEASED: /Volumes/For Jeff/chp-templates/1.3.0`.

- [ ] **Step 6: Tell diwai** (SendMessage to the diwai session). Send IDs and key names only: 1.3.0 adds the `odp.*` keys (owner-approved naming, additive), a Rev 3 library with every block pending, and Rev 2 content version 1.2.1 (T-06).

- [ ] **Step 7: Memory.** Update `project_chp_template_library.md` and the MEMORY.md line with the 1.3.0 release, the PR numbers and the next batch: narratives after diwai's Rev 3 walk.

## Out of scope (later)

- **Rev 3 narratives,** batch by batch, after the Rev 3 reference implementation proves each control.
- **Installer support for Rev 3:** `chp-site docs` choosing `rev3` from `profile.ini`, and a chp-templates 1.3.0 RPM. That is an installer release (a C3 follow-up).
- **Policies and the IR plan** (the spec's second cut).
