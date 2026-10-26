# Design: chp-templates, a shared SSP and POA&M template library (Rev 2 and Rev 3)

**Status:** APPROVED by the owner (2026-10-24) · **Owner:** the CyberHygiene Project ISSO
**Consumers:** the CHP installer's site stick (this repo), and Automated_Compliance, which generates SSPs and POA&Ms
from templates and then uses them as the editable "canvas".

## 1. Purpose

One library of **placeholder templates** for the System Security Plan (SSP) and Plan of Action and Milestones (POA&M).
Both consumers use the same library, so the installer and Automated_Compliance never drift apart.

A site fills the templates with its own values, which come from the site stick and a profile file. The result is a
business's own SSP and POA&M, which it then maintains.

### Decisions settled during design (owner, 2026-10-24)

| Topic | Decision |
|---|---|
| Where it lives | **A separate public repository, `chp-templates`**, published as signed, versioned releases (approach A) |
| Rev 2 and Rev 3 | **Two self-contained libraries in one repo** (`rev2/`, `rev3/`). They share only the renderer and the vocabulary. |
| Starting text | **The project's own documents**, using the section structure of the RS#2 reference SSP (its public redacted record). Wording is rewritten to placeholders; no reference-system facts are copied. NIST's Rev 2 and Rev 3 templates and catalogs are completeness checks. |
| Architectures (first cut) | **The CHP appliance (RS#3) only.** Other architectures are later, as separate files. |
| Format | **Markdown is the master.** A Word copy is rendered from it for assessors and signatures. |
| First cut | **SSP and POA&M.** Policies and the IR plan come in a second cut. |
| Fill-in syntax | **`{{section.key}}`**, following Automated_Compliance's existing `profile.ini` naming |
| Values | The site stick **keeps `site.conf`** for machine settings, unchanged, and **adds `profile.ini`** for document values. A published mapping links the overlaps. |
| Public or private | The repo holds **placeholders only**. Every site's values are private and never enter the library. |

### Decisions of 2026-10-26 (owner, Plan C2)

| Topic | Decision |
|---|---|
| First Rev 3 release | **Scaffold first.** The Rev 3 reference implementation has had no Rev 3 walk, so every Rev 3 block is `pending`. Narratives come in later batches. |
| ODP names | **`odp.<memo part id, dots as underscores>`** (e.g. `odp.03_01_01_f_02`) in a new `[odp]` section, never mixed into `decision.*`. The DoD memo's IDs are authoritative (80 ODPs; NIST's OSCAL splits some differently). |
| Rev 3 SSP layout | **Keyed to the 03.xx families,** with the same fixed layouts as Rev 2, because Rev 3 defines no separate SSP structure. |

## 2. Repository layout

```
chp-templates/
  rev2/                         self-contained Rev 2 library (CMMC Level 2 basis today)
    MANIFEST.json               every template: id, path, content version, status, placeholders used, sha256
    catalog.csv                 the 110 requirements, from NIST's Rev 2 requirements CSV
    defaults.ini                default decision.* values (a site confirms or changes each)
    templates/ssp/frame.md      the SSP frame (§4.1)
    templates/ssp/controls/<id>.md   one narrative block per requirement, e.g. 3.1.1.md
    templates/ssp/arch/chp-appliance.md  system description, boundary and architecture text for RS#3
    templates/poam/frame.md     the POA&M (§4.4)
  rev3/                         self-contained Rev 3 library, same layout
    catalog.csv                 the Rev 3 requirements, from NIST's Rev 3 dataset
    crosswalk.csv               Rev 2 ID → Rev 3 ID(s), from NIST's change analysis
    defaults.ini                decision.* defaults from the DoD Rev 3 organization-defined parameter values (memo, 2025-04-10)
    templates/…
  vocabulary.md                 every placeholder: meaning, list or single, visibility (public / private / never-to-AI)
  site-conf-mapping.csv         site.conf KEY ↔ profile.ini section.key
  render/chpfill.py             the one renderer (Python 3.9, standard library only)
  tests/
```

Each library's `MANIFEST.json` carries its **own content version**, separate from the repo's release version.

## 3. Filling a template

### 3.1 Syntax

| Form | Meaning |
|---|---|
| `{{section.key}}` | a single value |
| `{{section.key \| list}}` | a list value, rendered as bullets |
| `{{#if facts.name}} … {{/if}}` | a block included only when the stated fact is true |

There is nothing else: no loops, no expressions and no computed values, so a template can never invent a value.

**Excluded blocks.** A block switched off by a fact renders as *"Not applicable: \<fact and its value\>"*. An assessor
always sees the stated reason.

### 3.2 Value sources, in order

1. The site's **`profile.ini`**: document values such as organization, roles, scope, decisions and facts.
2. The site's **`site.conf`**, through `site-conf-mapping.csv`. For example, `DOMAIN` fills `{{site.domain}}`.
3. The library's **`defaults.ini`**, for `decision.*` keys only. A default is rendered with the marker *"(default, not
   yet confirmed)"* until the site's `profile.ini` confirms it. The confirmation records who confirmed it and when.

### 3.3 The renderer (`chpfill.py`)

- **Unfilled placeholders stay in the output as written** (`{{key}}`). They are listed in a **fill-in report** with
  their file and section. They are never guessed and never blanked.
- **`--public` mode** refuses to place any value whose key is tagged private or never-to-AI. It names the key, writes no
  output and exits with a non-zero status. This protects copies made for publication.
- **Errors stop the run before any output is written.** The error names the file and line. Errors are: an unknown
  placeholder, a malformed block, an unknown revision, or a `profile.ini` key not in `vocabulary.md`.
- **Output:** the Markdown master, plus the fill-in report. A Word copy is made from the Markdown with `pandoc` on the
  admin workstation; the appliance needs no Word tooling.
- **`profile.ini` must never hold secrets.** A value shaped like a password, key or token is refused.

## 4. Template content

### 4.1 SSP frame

The SSP is built from these sections, in this order:

- Document Control
- Executive Summary
- 2 System Identification
- 3 System Description
- 4 Security Control Implementation
- 5 Contingency Planning
- 6 Security Policies and Procedures
- 10 POA&M
- 11 Implementation Metrics
- 12 Conclusion
- Authorization
- Appendices

**Sections 7–9 stay deliberately absent**, as in the reference structure. **The Appendices are an open list:** a site can
add lettered sub-sections without editing the frame.

Sections 2 and 3 take their architecture-specific text from `arch/<architecture>.md`.

### 4.2 Machine-read elements: fixed layouts

These elements are read by tools, so their exact layouts are fixed and pinned by tests:

- the revision-history table in Document Control (four columns, MM/DD/YYYY dates, newest first);
- the Control Family Status table, **generated from the library's catalog** (one row per family plus a TOTAL row);
- two score cards.

The exact layouts are recorded in the owner-held interface note and pinned by tests (§6).

**Two separate score cards, never merged:**

- **SPRS**, under the DoD Assessment Methodology: method, revision, date, a blank value, and a **basis** line (who
  assessed, when, and under which evidence rule).
- **The strict 800-171A objective count:** its definition, revision, date and a blank value.

The templates never carry a score.

### 4.3 Control narratives

There is **one block per requirement, keyed by its catalog ID.** Each block states how the CHP appliance meets the
requirement, citing **proven evidence**: the proof records, release gates and scan results in this repo. Where the
appliance does nothing, the block says the **site** must supply the control. Coverage is never claimed without
evidence.

Each block carries one status:

| Status | Meaning |
|---|---|
| `appliance` | implemented and proven by the CHP appliance |
| `site` | the site's responsibility |
| `partial` | partly implemented by the appliance |
| `pending` | Rev 3 only: not yet proven on the Rev 3 reference implementation |

**Rev 3 text follows the reference implementation.** A Rev 3 block moves from `pending` to written only after the Rev 3
reference implementation (RS#2) has proven that control.

### 4.4 POA&M

Each item carries:

- the revision and requirement ID;
- the weakness;
- milestones;
- the scheduled completion date;
- the owner;
- the status.

**The template is pre-seeded with the appliance's known gaps** from this repo's records, for example the 3.10.4 physical
access record and the fapolicyd finding (row 49). Each seeded item is marked *"seeded by the template: confirm, adapt or
close"*.

## 5. Use by the consumers

### 5.1 Releases

`chp-templates` is published as `templates-X.Y.Z`: a tarball plus `SHA256SUMS` and `SHA256SUMS.asc`, signed by the
project key. It goes to the For Jeff share beside the installer releases. Each library's `MANIFEST.json` version moves
independently.

### 5.2 Installer (additive; nothing changes for 0.1.0 or 0.2.0 sites)

- **A new package, `chp-templates`**, in the signed repo, installs the pinned release to `/usr/share/chp-templates/`.
- **An optional `profile.ini` on the site stick.** `chp-site validate` checks it: known keys only, syntax, and the
  no-secrets rule. `site.conf` is unchanged.
- **A new command, `chp-site docs`**, run as root on the server. It renders the SSP and POA&M for the revision named in
  `profile.ini` (default `rev2`) into `/var/lib/chp/docs/<UTC timestamp>/`, with the fill-in report. A new render never
  overwrites an earlier one.
- **`SITE-STICK.md`** gains a "Your SSP and POA&M" section.

### 5.3 Automated_Compliance

- It pins a release by version and sha256, verifies the signature, and runs the same `chpfill.py` with its own
  `profile.ini`.
- **Shared contract:** `vocabulary.md`, the visibility tags and `site-conf-mapping.csv` live in `chp-templates` only.
- **Placeholders are only ever added.** A new placeholder is added to `vocabulary.md` in a release before any template
  uses it. A placeholder is never renamed or removed; at most it is marked deprecated, with its replacement named.

### 5.4 Compatibility

Placeholders and the machine-read layouts (§4.2) are a **stable interface**. Any change to them is a **major version**,
and the release notes call it out as affecting Automated_Compliance.

## 6. Testing and proof

**Renderer tests:**
- every syntax form;
- unfilled placeholders kept and reported;
- `--public` refusal;
- "Not applicable" citing its fact;
- every error stopping with file and line, and writing nothing;
- the no-secrets rule on `profile.ini`.

**Library tests:**
- every placeholder used is defined in `vocabulary.md`, with a visibility tag;
- every Rev 2 catalog requirement has a narrative block;
- every Rev 3 block is written or `pending`;
- the crosswalk covers every Rev 2 ID;
- `MANIFEST.json` checksums match.

**Fixed layouts:** the §4.2 elements match the owner-held interface note exactly.

**Nothing real:** a scan fails the build on real organization names, domains, IP addresses, email addresses,
UEI- or CAGE-shaped values, or key material. Fixtures use made-up values only.

**Golden render:** a fictional profile ("Example Manufacturing LLC", a made-up domain) renders a complete Rev 2 SSP and
POA&M with an empty fill-in report. A `pandoc` Word render is a smoke test.

**Automated_Compliance contract:** every key that Automated_Compliance already uses in its `profile.ini` exists in
`vocabulary.md` with the same meaning. The list of those keys is supplied by the owner and kept out of this public repo.

**Lab proof (Plan C3):** on the 0.2.0 golden hosts:

1. Install the `chp-templates` package.
2. Render with a lab `profile.ini`.
3. Check the documents and the fill-in report.
4. Confirm that AIDE reports only the expected new files.

## 7. Plans

| Plan | Scope | Release |
|---|---|---|
| **C1** | The repo, `chpfill.py`, `vocabulary.md`, `site-conf-mapping.csv`, and the **complete Rev 2 library** | signed `templates-1.0.0` |
| **C2** | The **Rev 3 library**: catalog, crosswalk, DoD defaults, and narratives as the reference implementation proves each control | a minor release per batch |
| **C3** | Installer integration: the `chp-templates` package, `chp-site docs`, `profile.ini` on the stick, kit guide | an installer release |

## 8. Out of scope

- Policies, procedures and the IR plan (the second cut).
- Architectures other than the CHP appliance, such as the RS#2 Mac host with a VM, or the RS#1 FreeIPA server.
- Output formats other than Markdown and Word.
- Hosting or publishing any site's filled-in documents.
