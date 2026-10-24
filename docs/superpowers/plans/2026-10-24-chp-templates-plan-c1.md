# chp-templates Plan C1: repo, renderer, vocabulary and the complete Rev 2 library — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new repository, `chp-templates`, holding:
- a tested fill-in renderer;
- the shared vocabulary and the `site.conf` mapping;
- a complete **Rev 2** SSP and POA&M library for the CHP appliance.

It is released as signed `templates-1.0.0`.

**Architecture:**
- **One stdlib Python module, `render/chpfill.py`, with two subcommands.**
  - `assemble` builds a library's full SSP and POA&M templates from the frame, the architecture file and the
    per-requirement blocks, in catalog order.
  - `fill` replaces placeholders from `profile.ini`, then `site.conf` through the mapping, then `defaults.ini`. It also
    writes a fill-in report.
- **Content is plain Markdown files** with a small HTML-comment metadata header that tests read.
- **Everything is placeholder-only.** Site values never enter the repo.

**Tech Stack:** Python 3.9 standard library (`configparser`, `csv`, `json`, `re`, `hashlib`, `argparse`), pytest on the
Mac, pandoc 3.x (Word smoke test only), git, gpg with the project YubiKey.

**Spec:** `docs/superpowers/specs/2026-10-24-chp-templates-design.md` (APPROVED 2026-10-24). Read it with this plan.

## Facts established while planning (2026-10-24)

- **NIST's Rev 2 CSV** is at
  `https://csrc.nist.gov/files/pubs/sp/800/171/r2/upd1/final/docs/sp800-171r2-security-reqs.csv`.
  - sha256 `0f4d59413bbcc9998da80495ce46ebfe0475e392803c4d2ed38d9941d83f138d`; 110 data rows.
  - Header: `Family,Basic/Derived Security Requirement,Identifier,Sort-As, Security Requirement,Discussion`. **Note the
    leading space in `" Security Requirement"`.**
  - The file starts with a UTF-8 BOM.
  - `Sort-As` (`03.01.01`) is a sort key only, **not** a Rev 3 identifier.
- **The appliance's gate-3 scan** (`idm-assistant/lab/iso5/scan-results/*.xml.xz`, rc2) references 800-171 in 273
  rules. Rules that were evaluated give pass evidence for **17** Rev 2 requirements directly. The rest need the proof
  records.
- **Evidence sources** for narratives, all in `idm-assistant`:
  - `lab/iso5/PROOF-RECORD.md` (gates 1–3, ISO 0.2.0-rc2);
  - `lab/aide/PROOF-RECORD.md`;
  - `lab/iso5/DEVIATIONS.md`;
  - `lab/iso-requirements.md` (48 rows);
  - `appliance/release/RELEASE-RECORD-ISO-0.2.0.md`.
- **`site.conf`'s 14 keys** are DOMAIN, SUBNET, GATEWAY, DNS_FORWARDERS, NTP_UPSTREAM, TIMEZONE, ISSO_NAME,
  UNEXPIRE_DELEGATES, COLLECTOR_IP, ACCESSIBILITY, ALERT_HOOK, ADMIN_SSH_PUBKEY, COLLECTOR_SSH_PUBKEY,
  BASELINE_DELEGATES (`appliance/chp-site/chp_site/sitefile.py`).
- **The model texts:**
  - the public RS#2 SSP v2.18 (redacted), which is the structure;
  - the project's own SSP v2.9 and POA&M v2.11, in the local archive
    `~/Documents/Claude/Projects/Cyberhygiene Project Final Report/archive/git_mirrors/cyberhygiene-documentation/CyberSecurity/Current/`.
- **The private interface note** is `~/idm-lab-secrets/templates-private/INTERFACE-NOTE.md`. It holds the exact
  machine-read layouts and Automated_Compliance's in-use key list. **Never copy it into a repo.**
- **Tooling and names:** pandoc is installed (`/opt/homebrew/bin/pandoc`, 3.12.1). The GitHub name
  `The-CyberHygiene-Project/chp-templates` is free.

## Decisions to confirm with the owner (stated, not hidden)

1. **Machine-read layouts become public.** The frame template necessarily shows the two machine-read tables' column
   headers, because a site's SSP is built from it. They are generic headers (`| Family | Total | Met | Not Met |
   Unverified |`), and every SSP that uses them shows them. **Ask at Task 7** whether publishing them is acceptable.
   If not, stop: the spec's public/private split would need revisiting.
2. **Header and licence.** The new repo uses Apache-2.0, like `idm-assistant`, and a short file header (below), not the
   installer's Rocky Linux header, because nothing in this repo is based on Rocky Linux.
3. **The narratives are claims, so the owner approves them.** Task 13 is a stop for the owner to review all 110 status
   lines before the release.

## Global Constraints

- **Location:** the repo is created at `~/chp-templates` (local git; remote created in Task 15, with the owner's go-ahead).
  The plan and its ledger stay in `idm-assistant`.
- **File header** on code files (Python as `#` comments):
  ```
  # CyberHygiene Project — chp-templates (shared SSP and POA&M templates).
  # Licensed under the Apache License 2.0. Placeholder templates only: no site's values belong in this repository.
  ```
- **Python 3.9, standard library only.** It runs on the appliance (EL9), the Mac and the RS#2 host. Tests run with
  `python3 -m pytest -q` from `~/chp-templates` (create `.venv` with pytest only).
- **Placeholder names** match `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`, written as `{{section.key}}`. INI option names are
  case-insensitive (`configparser` lowercases them), so all vocabulary names are lowercase.
- **Fill is single pass.** A value that itself contains `{{` is inserted literally and never expanded again.
- **Nothing real:** no real organization, person, host, domain, IP, email, UEI or CAGE in any file. Fixtures use
  `example.test`, `192.0.2.0/24` and "Example Manufacturing LLC".
- **Secrets:** never in `profile.ini`. Never print the private interface note's content into the repo.
- **Commits** end with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01JjtDCYK3hhwsbH1nLYRG36
  ```
- **Ledger:** `idm-assistant/.superpowers/sdd/2026-10-24-chp-templates-plan-c1/progress.md` (git-ignored there).

## Review Focus

1. **A `profile.ini` saved by Windows Notepad or TextEdit** (UTF-8 BOM, CRLF line endings, a trailing space after a
   value). Expect identical output to a clean file. → Task 4 test `test_profile_with_bom_crlf_and_trailing_space`.
2. **A value containing `{{` or `}}`**, for example a business name copied from a template. Expect it inserted
   literally, never expanded and never reported as unfilled. → Task 3 test
   `test_value_with_braces_is_inserted_literally`.
3. **Nested, unclosed or mismatched `{{#if}}` blocks.** Expect a stop naming the file and line, with no output. →
   Task 3 test `test_unclosed_if_is_an_error_with_line`.
4. **A list value whose items contain commas**, such as "Smith, J." as a reviewer. Lists are one item per line in INI,
   never comma-split. → Task 3 test `test_list_items_keep_their_commas`.
5. **Re-running `assemble` after a narrative edit.** Expect the full template and `MANIFEST.json` checksums to change
   together, and the integrity test to catch a stale manifest. → Task 11 test `test_manifest_detects_a_stale_file`.

---

### Task 1: Repository skeleton

**Files:** Create `~/chp-templates/{README.md,LICENSE,.gitignore,pyproject.toml,render/__init__.py,tests/__init__.py}`.

- [ ] **Step 1:**
  - `mkdir ~/chp-templates && cd ~/chp-templates && git init -b main`
  - copy `~/idm-assistant/LICENSE` (Apache-2.0)
  - `.gitignore`: `.venv/`, `__pycache__/`, `out/`, `*.docx`
  - `pyproject.toml`: a `[tool.pytest.ini_options]` section with `testpaths = ["tests"]`
- [ ] **Step 2: README.md.** It covers: what the library is (spec §1); placeholder-only; the Rev 2 and Rev 3 folders;
  how to fill (`python3 render/chpfill.py fill …`); the release and verification procedure. It also says **"No site's
  values belong here"**.
- [ ] **Step 3:** `python3 -m venv .venv && .venv/bin/pip install -q pytest`, then `.venv/bin/python -m pytest -q`.
  Expected: "no tests ran", exit 5.
- [ ] **Step 4: Commit** `Skeleton: licence, README, test setup`.

### Task 2: Rev 2 catalog from NIST's CSV

**Files:** Create `tools/import_catalog_r2.py`, `rev2/catalog.csv`, `tests/test_catalog_r2.py`.

**Interfaces:** Produces `rev2/catalog.csv` with header `id,family,family_code,basic_derived,requirement`, 110 rows in
publication order. `family_code` is the two-letter code: AC, AT, AU, CM, IA, IR, MA, MP, PS, PE, RA, CA, SC, SI.

- [ ] **Step 1: Failing test:**

```python
import csv
from pathlib import Path

CAT = Path(__file__).resolve().parents[1] / "rev2" / "catalog.csv"
CODES = {"Access Control": "AC", "Awareness and Training": "AT", "Audit and Accountability": "AU",
         "Configuration Management": "CM", "Identification and Authentication": "IA", "Incident Response": "IR",
         "Maintenance": "MA", "Media Protection": "MP", "Personnel Security": "PS", "Physical Protection": "PE",
         "Risk Assessment": "RA", "Security Assessment": "CA", "System and Communications Protection": "SC",
         "System and Information Integrity": "SI"}


def rows():
    return list(csv.DictReader(open(CAT, encoding="utf-8")))


def test_110_requirements_14_families_in_publication_order():
    r = rows()
    assert len(r) == 110 and len({x["family_code"] for x in r}) == 14
    assert r[0]["id"] == "3.1.1" and r[-1]["id"] == "3.14.7"
    assert all(CODES[x["family"]] == x["family_code"] for x in r)


def test_ids_unique_and_text_clean():
    r = rows()
    assert len({x["id"] for x in r}) == 110
    assert all(x["requirement"] == x["requirement"].strip() and x["requirement"] for x in r)
```

- [ ] **Step 2:** Run it. Expected: FAIL (the file is missing).
- [ ] **Step 3: `tools/import_catalog_r2.py URL-or-file`.** It reads with `encoding="utf-8-sig"` and
  **verifies the sha256 above** (refusing on mismatch). It maps `" Security Requirement"` (with its leading space) to
  `requirement` and `Basic/Derived Security Requirement` to `basic_derived`. It keeps publication order, writes the
  five columns, and adds `family_code` from the `CODES` map above.
- [ ] **Step 4:** Run the importer on the URL, then the test. Expected: PASS.
- [ ] **Step 5: Commit** `Rev 2 catalog imported from NIST's CSV (sha256-pinned)`.

### Task 3: Renderer core — values, lists, conditionals, errors

**Files:** Create `render/chpfill.py`, `tests/test_fill.py`.

**Interfaces:** Produces `fill_text(text: str, values: dict[str, str|list[str]], facts: dict[str, bool], src: str) ->
(str, list[tuple[str, int]])`. The return is the output plus the unfilled `(key, line)` pairs. On a syntax error it
raises `FillError("<src>:<line>: <message>")`.

- [ ] **Step 1: Failing tests** (`tests/test_fill.py`):

```python
import pytest
from render.chpfill import FillError, fill_text


def test_value_list_and_unfilled():
    out, unfilled = fill_text("A {{org.name}}\n{{org.reviewers | list}}\nB {{org.missing}}\n",
                              {"org.name": "Example Manufacturing LLC", "org.reviewers": ["Smith, J.", "Lee, K."]}, {}, "t.md")
    assert out == "A Example Manufacturing LLC\n- Smith, J.\n- Lee, K.\nB {{org.missing}}\n"
    assert unfilled == [("org.missing", 3)]


def test_list_items_keep_their_commas():
    out, _ = fill_text("{{a.b | list}}", {"a.b": ["Smith, J."]}, {}, "t.md")
    assert out == "- Smith, J."


def test_value_with_braces_is_inserted_literally():
    out, unfilled = fill_text("{{a.b}}", {"a.b": "{{x.y}} Co"}, {}, "t.md")
    assert out == "{{x.y}} Co" and unfilled == []


def test_if_true_false_and_not_applicable():
    t = "{{#if facts.has_wireless}}\nWireless text.\n{{/if}}\n"
    assert fill_text(t, {}, {"facts.has_wireless": True}, "t.md")[0] == "Wireless text.\n"
    out, _ = fill_text(t, {}, {"facts.has_wireless": False}, "t.md")
    assert out == "*Not applicable: facts.has_wireless = no.*\n"


def test_unknown_fact_leaves_block_and_reports():
    t = "{{#if facts.x}}\nT\n{{/if}}\n"
    out, unfilled = fill_text(t, {}, {}, "t.md")
    assert "{{#if facts.x}}" in out and ("facts.x", 1) in unfilled


@pytest.mark.parametrize("t,line", [("{{#if facts.a}}\nx\n", 1), ("x\n{{/if}}\n", 2),
                                    ("{{#if facts.a}}\n{{#if facts.b}}\n{{/if}}\n", 2), ("{{a.b | lisst}}", 1)])
def test_unclosed_if_is_an_error_with_line(t, line):
    with pytest.raises(FillError, match=rf"^t\.md:{line}: "):
        fill_text(t, {}, {"facts.a": True, "facts.b": True}, "t.md")
```

- [ ] **Step 2:** Run it. Expected: FAIL (import error).
- [ ] **Step 3: Implement `fill_text`.**
  - Scan lines once.
  - A line that is exactly `{{#if facts.NAME}}` or `{{/if}}` (after `strip()`) opens or closes a block.
  - Nesting is an error (`nested {{#if}} is not allowed`), as is an unmatched close or an unclosed open. Report the
    open's line.
  - For each other line, replace with `re.sub(r"\{\{([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)(?:\s*\|\s*(\w+))?\}\}", …)`,
    using a function that looks the key up and **returns the value text without rescanning it**.
  - A filter other than `list` is a `FillError` (`unknown filter lisst`).
  - `list` renders each item as `- item` on its own line. A missing key returns the original token and is recorded.
  - A block whose fact is False renders exactly `*Not applicable: facts.NAME = no.*` in place of the block.
  - A block whose fact is missing is left verbatim (open line, body, close) and is recorded as unfilled.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5: Commit** `chpfill: single-pass values, lists, fact blocks, line-numbered errors`.

### Task 4: Value sources — profile.ini, site.conf mapping, defaults, no secrets

**Files:** Modify `render/chpfill.py`. Create `site-conf-mapping.csv`, `tests/test_sources.py`.

**Interfaces:** Produces `load_values(profile: Path|None, site_conf: Path|None, defaults: Path|None, mapping: Path) ->
(values: dict, facts: dict, provenance: dict[str, str])`. Provenance is one of `profile`, `site.conf`, or
`default (not yet confirmed)`.

- [ ] **Step 1: `site-conf-mapping.csv`.** Header `site_conf_key,placeholder,visibility`. Rows:
  `DOMAIN,site.domain,public`; `SUBNET,site.lan_subnet,private`; `GATEWAY,site.lan_gateway,private`;
  `TIMEZONE,site.timezone,public`; `ISSO_NAME,roles.security_officer,private`;
  `BASELINE_DELEGATES,roles.baseline_delegates,private`.
  The other eight `site.conf` keys are machine settings and do **not** map, which the README says.
- [ ] **Step 2: Failing tests** (`tests/test_sources.py`). They cover:
  - a `profile.ini` `[organization] name=…` becomes `organization.name`;
  - a multi-line INI value becomes a list (one item per non-empty line);
  - `[facts] has_wireless = no` becomes `facts.has_wireless = False`; the accepted forms are
    yes/no/true/false/1/0, case-insensitive, and anything else is a `FillError`;
  - `site.conf` `DOMAIN=example.test` fills `site.domain` **only when the profile lacks it** (profile wins);
  - `defaults.ini` `[decision] lockout_threshold = 5` fills with provenance `default (not yet confirmed)`;
  - `test_profile_with_bom_crlf_and_trailing_space`: identical values from a clean file and from a BOM+CRLF+trailing-space
    file;
  - `test_secrets_refused`: any value matching
    `(?i)(password|passphrase|secret|token|BEGIN .*PRIVATE)|^[A-Za-z0-9+/=]{32,}$` raises `FillError` naming the
    key (not the value).
- [ ] **Step 3:** Run the tests. Expected: FAIL.
- [ ] **Step 4: Implement.**
  - Use `configparser.ConfigParser(interpolation=None, strict=True)` with `read_string` on text decoded
    `utf-8-sig`, after `\r\n` → `\n`. Strip values.
  - Section `[contract.1]` with option `label` becomes `contract.1.label`.
  - `site.conf` is read with the same KEY=VALUE rules as `idm-assistant`'s `read_kv`: comments on their own line, no
    quotes. Reimplement in ~10 lines; do not import from `idm-assistant`.
- [ ] **Step 5:** Run the tests. Expected: PASS.
- [ ] **Step 6: Commit** `chpfill: values from profile.ini, mapped site.conf keys and defaults; secrets refused`.

### Task 5: Vocabulary, visibility tags and --public mode

**Files:** Create `vocabulary.md`, `tests/test_vocabulary.py`. Modify `render/chpfill.py`.

**Interfaces:** `vocabulary.md` holds one table: `| placeholder | kind | visibility | meaning |`, where kind is `value`,
`list` or `fact` and visibility is `public`, `private` or `never-to-ai`. Produces `load_vocabulary(path) -> dict[str,
dict]`.

- [ ] **Step 1: Write `vocabulary.md`.** Include every placeholder the Rev 2 templates use. The template tasks append
  rows as they need them, and each must add its row first.
  - Start with the generic names from spec §3: `organization.name`, `organization.legal_name`, `organization.dba`,
    `organization.location` (public form only), `roles.system_owner`, `roles.security_officer`,
    `roles.administrator`, `roles.approver_of_changes`, `roles.baseline_delegates`, `scope.cui_types` (list),
    `scope.boundary_note`, `site.domain`, `site.lan_subnet`, `site.lan_gateway`, `site.timezone`,
    `system.description`, the `decision.*` names from the RS#2-proven controls list (generic names only), and `facts.*`
    as needed by blocks.
  - **Then reconcile against the private interface note's in-use list.** Every in-use Automated_Compliance key that a
    Rev 2 template needs must use **the same name and meaning**. Do this by reading the note; do not copy the note into
    the repo.
- [ ] **Step 2: Failing tests:**
  - every row is well-formed (name pattern, kind, visibility);
  - no duplicates;
  - `--public` refuses a private value: `fill(..., public=True)` with `roles.security_officer` set raises
    `FillError("roles.security_officer is private: not placed in a public copy")` and writes nothing;
  - a `profile.ini` key that isn't in the vocabulary is a `FillError` naming the key.
- [ ] **Step 3:** Run the tests. Expected: FAIL.
- [ ] **Step 4:** Implement `load_vocabulary` and the checks in `fill`. Run the tests. Expected: PASS.
- [ ] **Step 5: Commit** `Vocabulary with visibility tags; --public refuses private values; unknown profile keys refused`.

### Task 6: The CLI — `assemble` and `fill`, with the report and no partial output

**Files:** Modify `render/chpfill.py`. Create `tests/test_cli.py`.

**Interfaces:**
- `python3 render/chpfill.py assemble --lib rev2 --out out/rev2` writes `ssp.md` and `poam.md` (the full templates).
- `python3 render/chpfill.py fill --lib rev2 --profile P [--site-conf S] [--public] --out DIR` writes `ssp.md`,
  `poam.md` and `fill-report.md`.

**Include directives** are resolved by `assemble` only, never by `fill`:
- `{{> arch}}` inserts `templates/ssp/arch/chp-appliance.md`;
- `{{> controls}}` inserts every `templates/ssp/controls/<id>.md`, in catalog order, each under `### <id>
  <requirement text>`;
- `{{> family_status}}` inserts the generated Control Family Status table.

- [ ] **Step 1: Failing tests.**
  - `assemble` on a fixture library (two families, three requirements) produces the blocks in catalog order and a
    family table with the right Total counts.
  - `fill` writes all three files.
  - On a `FillError`, the out dir is **not created** or is left exactly as before: write to `DIR.partial`, then rename.
  - `fill-report.md` lists each unfilled key with file and line, and each default-filled key with
    `default (not yet confirmed)`.
  - The exit status is 0 on success and 2 on `FillError`, with the message on stderr.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - **Family table (spec §4.2):** rows in catalog order of first appearance, `| XX — Family Name | <total> |
    {{status.xx.met}} | {{status.xx.not_met}} | {{status.xx.unverified}} |`, then the TOTAL row.
  - **The exact header, alignment row and TOTAL format** come from the private interface note. Copy the layout, which
    is generic headers, into code. This is subject to the Task 7 owner confirmation.
  - Add `status.xx.*` rows to `vocabulary.md` (kind `value`, visibility `private`).
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5: Commit** `CLI: assemble (catalog-driven) and fill (atomic output + fill-in report)`.

### Task 7: SSP frame (Rev 2) — **owner confirmation first**

**Files:** Create `rev2/templates/ssp/frame.md`, `tests/test_frame_r2.py`.

- [ ] **Step 0: STOP and ask the owner** (Decision 1): "The SSP frame will show the revision-history and Control Family
  Status table headers, which are generic column names. OK to publish?" Ledger the answer. On "no", stop the plan.
- [ ] **Step 1: Failing tests.**
  - The section headings appear in this order: Document Control, Executive Summary, `## 2. SYSTEM IDENTIFICATION`,
    `## 3. SYSTEM DESCRIPTION`, `## 4. SECURITY CONTROL IMPLEMENTATION`, `## 5. CONTINGENCY PLANNING`,
    `## 6. SECURITY POLICIES AND PROCEDURES`, `## 10. PLAN OF ACTION AND MILESTONES (POA&M)`,
    `## 11. IMPLEMENTATION METRICS`, `## 12. CONCLUSION`, Authorization, Appendices.
  - There is no `## 7.`, `## 8.` or `## 9.`.
  - The revision-history table has exactly the 4-column header.
  - **Two separate score cards:** SPRS, with `{{assessment.sprs_score}}`, method, revision, date and a basis line
    `{{assessment.sprs_basis}}`; and the strict objective count, `{{assessment.objectives_met}}`, with its definition.
    Neither contains a digit score.
  - `{{> arch}}`, `{{> controls}}` and `{{> family_status}}` each appear once.
  - The Appendices section ends with *"Add further lettered appendices below; nothing reads their order."*
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3: Write `frame.md`.**
  - Model the structure and prose on the public RS#2 SSP v2.18 (redacted), plus the project's SSP v2.9. **Rewrite**;
    never paste a sentence containing a site fact.
  - Every organization, person, host, address and date is a placeholder.
  - The revision history has one placeholder row, `| {{document.version}} | {{document.date}} | {{document.author}} |
    **Initial issue.** Generated from chp-templates {{templates.version}}. |`.
  - Add the needed rows to `vocabulary.md`.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5: Commit** `Rev 2 SSP frame (RS#2 structure; placeholders only; two separate score cards)`.

### Task 8: Architecture file — CHP appliance (RS#3)

**Files:** Create `rev2/templates/ssp/arch/chp-appliance.md`, `tests/test_arch.py`.

- [ ] **Step 1: Failing test.**
  - The file mentions only placeholders for names and addresses.
  - It describes the components: the Kanidm identity server, step-ca, BIND DNS, clients with `kanidm-unixd`, USBGuard,
    fapolicyd, LUKS with TPM unlock, FIPS mode, AIDE, and the CHP monitor.
  - It describes the boundary as `{{systems.in_boundary | list}}` and the site stick's role.
  - Each component sentence ends with an evidence pointer `(evidence: idm-assistant <path>)` naming a real file listed
    under "Facts".
- [ ] **Step 2:** Run the test. Expected: FAIL.
- [ ] **Step 3:** Write the file from `RELEASE-RECORD-ISO-0.2.0.md`, `lab/iso5/PROOF-RECORD.md` and the 0.2.0 spec.
  State only what the gates proved.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5: Commit** `Architecture text for the CHP appliance (RS#3), evidence-pointed`.

### Task 9: Evidence index (a tool, not shipped content)

**Files:** Create `tools/evidence_index.py`, `tests/test_evidence_index.py`.

**Interfaces:** `python3 tools/evidence_index.py --scan <rc2 xml…> --catalog rev2/catalog.csv` writes
`out/evidence-r2.md`, listing for each requirement the passing SSG rules from the scan that cite it. Narrative authors
use it; it is not part of a release.

- [ ] **Step 1: Failing test.** On a fixture XCCDF with two rules referencing `3.1.1`, one passing and one failing,
  the index shows the pass under 3.1.1 and the fail flagged.
- [ ] **Step 2:** Run the test. Expected: FAIL.
- [ ] **Step 3: Implement** with `xml.etree`. References are where `href` contains `800-171`. Split comma lists. The
  output lists the rule id and title.
- [ ] **Step 4:** Run the test (PASS), then run the tool on the three rc2 results. Expected: 17 requirements with
  scan evidence.
- [ ] **Step 5: Commit** `Evidence index: scan rules per Rev 2 requirement (authoring aid)`.

### Task 10: Control narratives — 110 blocks, in four batches

**Files:** Create `rev2/templates/ssp/controls/<id>.md` × 110. Create `tests/test_controls_r2.py`.

**Block format** (exactly):
```
<!-- chp:control id=3.1.1 status=appliance evidence=lab/iso5/PROOF-RECORD.md;scan:<rule-id> -->
**Implementation:** <how the CHP appliance meets it, with placeholders for site facts>

**Site responsibility:** <what the business must still do, or "None beyond operating the appliance as documented.">
```
`status` is one of `appliance`, `site` or `partial`. Rev 2 has no `pending`.

- [ ] **Step 1: Failing test.**
  - Every catalog id has exactly one block, and every block id is in the catalog.
  - The header parses.
  - **Every status `appliance` or `partial` names at least one evidence item**, and each `idm-assistant` path in it
    exists when `IDM_ASSISTANT` (env) points at the checkout. Skip that existence check when the env is unset.
  - Status `site` blocks give a non-empty site responsibility.
  - No block contains a digit-only score.
- [ ] **Step 2:** Run the test. Expected: FAIL, with 110 missing.
- [ ] **Steps 3–6: Write the blocks in four batches**, with the full suite run after each:
  - (a) AC, AT, AU (22 + 3 + 9);
  - (b) CM, IA, IR, MA (9 + 11 + 3 + 6);
  - (c) MP, PS, PE, RA, CA (9 + 2 + 6 + 3 + 4);
  - (d) SC, SI (16 + 7).

  For each requirement:
  - read the catalog text, the evidence index (Task 9) and the proof records;
  - model the wording on the project's SSP v2.9 and the RS#2 v2.18 control prose;
  - **claim `appliance` only with a gate-proven evidence pointer**; otherwise use `partial` or `site`.

  Ledger every requirement where the status is a judgement call.
- [ ] **Step 7:** Run the suite. Expected: PASS, 110/110.
- [ ] **Step 8: Commit** (one per batch) `Rev 2 narratives: <families>`.

### Task 11: POA&M template, MANIFEST.json and integrity tests

**Files:** Create `rev2/templates/poam/frame.md`, `rev2/defaults.ini`, `rev2/MANIFEST.json`, `tools/build_manifest.py`,
`tests/test_manifest.py`.

- [ ] **Step 1: POA&M frame.** It has an item table `| ID | Revision | Requirement | Weakness | Milestones | Scheduled
  completion | Owner | Status |`.
  - Seed items, each tagged *"seeded by the template: confirm, adapt or close"*: **3.10.4** (a physical access record
    is the site's; the appliance keeps no door log); the **fapolicyd AVCs** (requirements row 49), mapped to
    **3.14.x**, and **3.4.x** as the owner confirms at Task 13; and the **one-time AIDE alert** when the stick is pulled
    early (the 0.2.0 known limit).
  - Every item's Revision is `Rev 2`.
- [ ] **Step 2: `rev2/defaults.ini`.** It holds `[decision]` defaults only, using values documented as proven in the
  appliance's own records (for example the lockout and session values from `lab/iso-requirements.md`). Each line has a
  comment citing its source row.
- [ ] **Step 3: Failing tests.**
  - `MANIFEST.json` lists every template file with a sha256 that matches.
  - `test_manifest_detects_a_stale_file`: edit a block → the test fails until `tools/build_manifest.py` is re-run.
  - The manifest carries `library: rev2`, `content_version` and `catalog_sha256`.
- [ ] **Step 4:** Run the tests. Expected: FAIL. Implement `build_manifest.py`, run it, then run the tests. Expected:
  PASS.
- [ ] **Step 5: Commit** `Rev 2 POA&M (seeded), defaults, manifest with integrity test`.

### Task 12: Nothing-real scan, golden render, Word smoke test, Automated_Compliance contract

**Files:** Create `tests/test_nothing_real.py`, `tests/fixtures/example-profile.ini`, `tests/test_golden.py`,
`tests/test_ac_contract.py`.

- [ ] **Step 1: `test_nothing_real`.** Scan every tracked file except `tests/fixtures/`. It fails on:
  - an IPv4 address outside `192.0.2.0/24`, `127.0.0.1` and `0.0.0.0`;
  - an email that isn't `@example.test`;
  - a domain ending in a real TLD that isn't `example.test`, `nist.gov`, `csrc.nist.gov` or `doi.org`;
  - UEI-shaped values (`\b[A-Z0-9]{12}\b` next to "UEI");
  - CAGE-shaped values (`\b[0-9A-Z]{5}\b` next to "CAGE");
  - `PRIVATE KEY`;
  - the strings `cyberinabox`, `diwai`, `contract-coach`, `Shannon`.
- [ ] **Step 2: Golden render.** `example-profile.ini` is a complete fictional profile (Example Manufacturing LLC,
  `example.test`, `192.0.2.0/24`, made-up roles, facts both true and false). `fill --lib rev2` produces an
  **empty fill-in report**. A snapshot of `ssp.md` is checked in under `tests/golden/`, and a change shows as a diff.
- [ ] **Step 3: Word smoke test.** `pandoc out/ssp.md -o out/ssp.docx` exits 0 and the file is over 20 kB. Skip when
  pandoc is absent.
- [ ] **Step 4: `test_ac_contract`.** It reads the in-use key list from the path in env `CHP_AC_KEYS` (a private file
  the owner keeps; **skip** when unset). Every key a Rev 2 template uses that is on that list must exist in
  `vocabulary.md`. Write the private file from the interface note to `~/idm-lab-secrets/templates-private/ac-keys.txt`
  (outside the repo), then run with the env set. Expected: PASS.
- [ ] **Step 5:** Run the suite (PASS), then commit `Nothing-real scan, golden Rev 2 render, Word smoke test, AC contract`.

### Task 13: Owner review of the narratives — **STOP**

- [ ] **Step 1:** Generate `out/review-r2.md`: one line per requirement with id, status, first sentence and evidence.
  Show it to the owner, along with the list of judgement calls from the Task 10 ledger.
- [ ] **Step 2:** Apply the owner's changes (status or wording), re-run `build_manifest.py` and the suite, and commit
  `Rev 2 narratives: owner review (<date>)`.

### Task 14: Release templates-1.0.0 (owner's YubiKey)

**Files:** Create `tools/release.sh`, `tests/test_release_static.py`, `RELEASE-NOTES-1.0.0.md`.

- [ ] **Step 1: Failing static test**, modelled on `idm-assistant`'s `test_release_iso_static.py`:
  - `V` is required;
  - an existing target is refused (`For Jeff/chp-templates/$V/`);
  - the script builds `chp-templates-$V.tar.gz` from `git archive` of the tag;
  - it writes `SHA256SUMS` and `SHA256SUMS.asc` (key `2DE0D71BF37D8F5E4201A590521276F43C908F8E`);
  - it runs `gpg --verify` and `shasum -c`;
  - it builds in `.partial` and renames last.
- [ ] **Step 2:** Implement, then run the test. Expected: PASS.
- [ ] **Step 3:** `git tag -s`? **No:** use an annotated tag `templates-1.0.0` (no git signing key setup). The tarball's
  signature is the trust anchor.
- [ ] **Step 4: Owner signing.** Cue the owner: *"reply go, finger on the key; touch when it flashes — a PIN window
  only if not cached; click inside it first"*. Then run `V=1.0.0 bash tools/release.sh`. Expected: `Good signature`,
  and every `shasum -c` line OK.
- [ ] **Step 5: Commit** `Release templates-1.0.0`.

### Task 15: Publish the repository (owner's go-ahead) and finish

- [ ] **Step 1: Pre-publication scan.** Run `test_nothing_real`, plus a `git log -p` grep for the private note's
  distinctive strings and any key material.
- [ ] **Step 2: Ask the owner:** "Create public `The-CyberHygiene-Project/chp-templates` and push `main` + tag?" On
  yes: `gh repo create The-CyberHygiene-Project/chp-templates --public --source ~/chp-templates --push`, then
  `git push origin templates-1.0.0`.
- [ ] **Step 3:** Final whole-branch review (fresh reviewer, most capable model), with this plan's Review Focus. Fix
  Important findings RED→GREEN.
- [ ] **Step 4:** Update `idm-assistant`'s backlog memory. Tell the diwai session (after its tests) that release 1.0.0
  exists, with its version and sha256, so Automated_Compliance can pin it.
